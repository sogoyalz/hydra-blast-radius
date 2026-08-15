const HYDRA_HTTP_ADDR = process.env.HYDRA_HTTP_ADDR ?? "http://127.0.0.1:8443";
const HYDRA_TOKEN = process.env.HYDRA_TOKEN ?? "local-development-token-32-bytes";
const HYDRA_NAMESPACE = process.env.HYDRA_NAMESPACE ?? "default";
const HYDRA_GRAPH = process.env.HYDRA_GRAPH ?? "default";
const HYDRA_CELL = process.env.HYDRA_CELL ?? "cell-0";

// A stuck HydraDB backend (container alive, TCP accepting, never responding —
// the actual failure mode a degraded bind mount produces) otherwise hangs a
// bare fetch() forever: no error, no timeout, just a promise that never
// settles. Every endpoint in server.js awaits runQuery(), so one wedged
// connection freezes the entire demo with no user-facing signal at all.
// AbortController turns that into a real, catchable error on a bound clock.
//
// The body is read INSIDE the guarded window, and that is the whole reason
// this returns a plain object rather than the Response. Clearing the timer as
// soon as fetch() resolves only bounds the wait for response *headers*: a
// backend that sends headers and then stalls mid-body leaves the subsequent
// res.json() unguarded and hanging forever. Verified directly against a
// server that writes a partial JSON body and never ends it — with the timer
// disarmed at header time that read never returns. Reading to completion here
// keeps the abort signal live across the whole exchange.
const DEFAULT_TIMEOUT_MS = 10_000;

export async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const text = await res.text();
    return {
      ok: res.ok,
      status: res.status,
      // Exposed for Retry-After, which is how the npm registry says how long
      // to wait after a 429 — see the retry loop in ingest.js.
      headers: res.headers,
      text: () => text,
      json: () => JSON.parse(text),
    };
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(`request to ${url} timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// Runs one openCypher statement against HydraDB's HTTP query API and returns
// rows as plain JS values (unwrapped from HydraDB's {type, value} envelopes).
//
// Ordinary reads and writes build their query strings with cypherString()
// below rather than binding values, because the documented HTTP API only
// shows a bare `query` string.
//
// `parameters` exists for the native path procedures (algo.SSpaths and
// friends), which cannot be called any other way — `algo.SSpaths({sourceNode:
// 123, ...})` is rejected, the source vertex has to arrive as a bound
// parameter. Two things about that binding were found only by probing, and
// both are easy to lose an afternoon to:
//
//   * The request field is `parameters`. A field named `params` is accepted
//     by the transport and then silently ignored, so the server answers
//     "missing OpenCypher query parameter $sourceNode" while the parameter
//     is sitting right there in the request body.
//   * Only scalars bind. A list parameter comes back as "composite parameter
//     $x is only supported as an UNWIND input", so relTypes has to be an
//     inline list literal even though sourceNode must not be inline.
export async function runQuery(query, parameters) {
  const payload = { cell_id: HYDRA_CELL, query };
  if (parameters) payload.parameters = parameters;
  const res = await fetchWithTimeout(`${HYDRA_HTTP_ADDR}/v1/graphs/${HYDRA_GRAPH}/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${HYDRA_TOKEN}`,
      "X-Graph-Namespace": HYDRA_NAMESPACE,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HydraDB query failed (${res.status}): ${text}`);
  }

  const body = await res.json();
  const columns = body.columns ?? [];
  return (body.rows ?? []).map((row) =>
    Object.fromEntries(columns.map((col, i) => [col, unwrap(row[i])]))
  );
}

// HydraDB returns typed envelopes: {"type":"string","value":"express"},
// {"type":"vertex_id","value":222}, {"type":"null"}. Note the null envelope
// carries NO "value" key — returning it as-is would leak a truthy object
// into results (a missing `name` would survive `.filter(Boolean)` and render
// as "[object Object]"), so it is mapped explicitly to null.
function unwrap(cell) {
  if (cell && typeof cell === "object") {
    if (cell.type === "null") return null;
    if ("value" in cell) return cell.value;
  }
  return cell;
}

// Runs many independent queries with bounded concurrency, preserving input
// order in the results. HydraDB answers a single traversal in tens of
// milliseconds, so anything that fans out over N packages is dominated by
// round-trip count, not by the engine — issuing those sequentially is what
// makes a fast database look slow.
//
// A single failed query yields an empty result for that slot rather than
// rejecting the whole batch: these are used for the draw-only edge lookups,
// where one missing node's edges should not discard an otherwise-complete
// answer. The failure is logged so it is not silent.
// HydraDB caps EVERY query result at 1024 rows. Not just the path procedures —
// measured directly against the engine, `MATCH (a)-[:DEPENDS_ON]->(b) RETURN
// a.name, b.name` on a graph with more edges than that returns exactly 1024,
// with nothing in the response marking it short. A blast radius of 1500
// packages therefore came back as 1024 and looked complete, which is precisely
// the under-reporting this project treats as its one unacceptable failure.
//
// SKIP/LIMIT are supported and, importantly, reach past the cap: `SKIP 1024`
// returns real rows. So the cap is on rows returned per request, not on rows
// the engine is willing to consider, and paging recovers the whole set.
//
// The query passed here must not already carry SKIP/LIMIT, and its ordering
// only has to be stable enough not to drop rows between pages — verified
// recovering all 1500 of a known 1500-row result both with and without an
// explicit ORDER BY.
const PAGE_SIZE = 1000; // under the cap, so a short page reliably means "done"

// Pages by SEEKING past the last key seen, not by offset.
//
// SKIP/LIMIT is unusable here, and not theoretically: measured. Taking page one
// of a 1500-row result, inserting 800 rows, then taking page two at SKIP 1000
// lost 528 rows that had been present the whole time and duplicated 260 others.
// An insert lands somewhere in the ordering, every later row shifts right, and
// the next offset steps straight over the ones that moved. Ordering the query
// does not save it — the offset is still measured from a start that has grown.
// For a tool whose entire claim is "here is everything exposed", quietly
// dropping a third of the answer whenever someone ingests during a query is not
// a tolerable failure.
//
// Seeking is immune to the same interleaving: a row inserted after the current
// key is picked up by a later page, and one inserted before it was already
// passed. A row present for the whole query is therefore never skipped.
//
// `template` must contain the marker {{SEEK}} where a WHERE clause can go, and
// must already end with `ORDER BY <keyAlias>`. `keyExpr` is the ordered
// expression as written in the MATCH (e.g. `d.name`); `keyAlias` is its
// returned column. The key must be UNIQUE per row, or rows sharing a key on a
// page boundary are lost — which is why the maintainer query, whose rows are
// (maintainer, package) pairs, is paged per maintainer instead of as pairs.
export async function runQueryPagedKeyset(template, keyExpr, keyAlias, parameters, maxPages = 500) {
  if (!template.includes("{{SEEK}}")) {
    throw new Error("runQueryPagedKeyset: template must contain a {{SEEK}} marker");
  }
  const all = [];
  let last = null;
  for (let page = 0; page < maxPages; page++) {
    const seek = last === null ? "" : `WHERE ${keyExpr} > ${cypherString(last)}`;
    const rows = await runQuery(
      `${template.replace("{{SEEK}}", seek)} LIMIT ${PAGE_SIZE}`,
      parameters
    );
    all.push(...rows);
    if (rows.length < PAGE_SIZE) return all;
    const nextKey = rows[rows.length - 1]?.[keyAlias];
    // Without a usable key there is no way to resume, and continuing would
    // silently repeat or skip. Stop loudly instead.
    if (nextKey == null || nextKey === last) {
      throw new Error(`runQueryPagedKeyset: cannot resume paging after key ${JSON.stringify(nextKey)}`);
    }
    last = nextKey;
  }
  throw new Error(
    `query exceeded ${maxPages * PAGE_SIZE} rows while paging; refusing to return a partial result`
  );
}

export async function runQueriesConcurrent(queries, limit = 16) {
  const results = new Array(queries.length);
  let next = 0;
  async function worker() {
    while (next < queries.length) {
      const i = next++;
      try {
        results[i] = await runQuery(queries[i]);
      } catch (err) {
        console.error(`query ${i} failed, continuing with empty result: ${err.message}`);
        results[i] = [];
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, queries.length) }, worker));
  return results;
}

// Escapes a JS string for safe inline use as a single-quoted Cypher string literal.
export function cypherString(value) {
  return `'${String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
}

// HydraDB's current (alpha) MERGE implementation only upserts vertices by an
// *integer* `id` property — MERGE with a string key, UNWIND-batched MERGE,
// and MERGE-then-SET all error out (confirmed empirically against the local
// dev node; see README's documented endpoints/verify flow for the baseline
// this was probed from). So package names are mapped to stable integer ids
// via this hash, and `name` is carried as an ordinary string property set
// inline in the same MERGE — the one pattern that reliably works:
//   MERGE (a:Package {id: 111, name: 'express'})-[:DEPENDS_ON]->(b:Package {id: 222, name: 'body-parser'})
// FNV-1a 64-bit, folded into JS's safe integer range (2^53) rather than a
// bare 32-bit hash, to keep collision risk negligible at hackathon scale
// (thousands of packages).
export function packageId(name) {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < name.length; i++) {
    hash ^= BigInt(name.charCodeAt(i));
    hash = (hash * prime) & 0xffffffffffffffffn;
  }
  return Number(hash & 0x1fffffffffffffn); // mask to 53 bits
}

// Maintainer ids MUST live in a separate hash namespace from package ids.
// HydraDB keys vertices on `id` alone — the label does not scope identity —
// and labels accumulate: MERGE-ing a :Package onto an id already held by a
// :Maintainer silently overwrites that vertex's properties and leaves one
// vertex answering to both labels while keeping both sets of edges
// (verified against the running node). Since it is entirely normal for an
// npm user to publish a package under their own handle, an un-namespaced
// hash would fuse maintainer "ljharb" with a package named "ljharb" with
// probability 1. npm forbids spaces in both package names and usernames, so
// the space in the prefix guarantees the two namespaces cannot alias.
export function maintainerId(name) {
  return packageId(`npm-maintainer ${name}`);
}

// One further engine constraint, found the same way and worth stating because
// it shapes the API: a variable-length pattern may name only ONE relationship
// type. `[:REQUIRED_BY|MAINTAINS*1..3]` is rejected with "relationship
// pattern must have exactly one type in Query engine". So the two ways a
// compromise spreads — through code you depend on, and through credentials
// that can publish to you — cannot be walked in a single traversal. They are
// queried separately (blastRadius.js and sharedMaintainers.js) and unioned in
// the API layer, which is why /api/blast-radius reports `unifiedExposure`
// alongside the per-channel numbers rather than getting it from one query.

