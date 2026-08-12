const HYDRA_HTTP_ADDR = process.env.HYDRA_HTTP_ADDR ?? "http://127.0.0.1:8443";
const HYDRA_TOKEN = process.env.HYDRA_TOKEN ?? "local-development-token-32-bytes";
const HYDRA_NAMESPACE = process.env.HYDRA_NAMESPACE ?? "default";
const HYDRA_GRAPH = process.env.HYDRA_GRAPH ?? "default";
const HYDRA_CELL = process.env.HYDRA_CELL ?? "cell-0";

// Runs one openCypher statement against HydraDB's HTTP query API and returns
// rows as plain JS values (unwrapped from HydraDB's {type, value} envelopes).
//
// The documented HTTP API (README "Verify a running node") only shows a bare
// `query` string, no parameter binding — so query strings are built with
// cypherString() below rather than relying on undocumented param support.
export async function runQuery(query) {
  const res = await fetch(`${HYDRA_HTTP_ADDR}/v1/graphs/${HYDRA_GRAPH}/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${HYDRA_TOKEN}`,
      "X-Graph-Namespace": HYDRA_NAMESPACE,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ cell_id: HYDRA_CELL, query }),
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
export async function runQueriesConcurrent(queries, limit = 16) {
  const results = new Array(queries.length);
  let next = 0;
  async function worker() {
    while (next < queries.length) {
      const i = next++;
      results[i] = await runQuery(queries[i]);
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

