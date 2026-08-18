// Given a package name, returns every package that transitively depends on
// it — i.e. what's exposed if that package is compromised.
//
// This is a forward traversal over the mirrored REQUIRED_BY edge (see
// src/ingest.js for why: HydraDB's variable-length MATCH requires the fixed
// id to sit at the true edge-direction source, so "who depends on X" is
// modeled as walking forward from X along REQUIRED_BY rather than backward
// along DEPENDS_ON).
//
// Usage: node src/blastRadius.js <package-name> [--depth=6]

import { pathToFileURL } from "node:url";
import {
  runQuery,
  runQueryPagedKeyset,
  runQueriesConcurrent,
  packageId,
  TRAVERSAL_TIMEOUT_MS,
} from "./hydra.js";

function parseArgs(argv) {
  const [name, ...rest] = argv;
  if (!name) {
    console.error("Usage: node src/blastRadius.js <package-name> [--depth=6]");
    process.exit(1);
  }
  let depth = 6;
  for (const arg of rest) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    // Validated like every other CLI's numeric flag. Unvalidated, the value is
    // interpolated straight into the traversal's `*1..N` bound, so a typo left
    // the user staring at a raw HydraDB 400 with an OpenCypher parse error in
    // it — the engine's internals surfacing as the answer to a mistyped flag.
    if (key === "depth") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--depth must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      depth = n;
    }
  }
  return { name, depth };
}

export async function blastRadius(name, depth = 6) {
  const id = packageId(name);
  // Paged, because the engine truncates any result at 1024 rows without saying
  // so. This traversal is the authoritative answer to "what is exposed" and the
  // fallback the native path defers to, so a silent cut here would under-report
  // the blast radius on exactly the large graphs where the question matters
  // most. Measured: a known 1500-package radius returned 1024 unpaged.
  //
  // Seek-paged rather than offset-paged: package names are unique, and an
  // ingest running against the same graph during the query would otherwise
  // shift the offsets out from under it (measured at 528 rows lost).
  const template =
    `MATCH (target:Package {id: ${id}})-[:REQUIRED_BY*1..${depth}]->(dependent:Package) {{SEEK}} ` +
    `RETURN DISTINCT dependent.name AS name ORDER BY name`;
  const rows = await runQueryPagedKeyset(template, "dependent.name", "name");
  return rows.map((r) => r.name).filter(Boolean);
}

// Upper bound on paths requested from the native procedure. If the engine
// returns this many the answer may be incomplete, and an incomplete blast
// radius presented as complete is the one failure this tool cannot afford —
// that case falls back to the exhaustive method below.
//
// This is 1024 because that is the engine's OWN ceiling, measured rather than
// assumed: asking for 100/500/1000 returns exactly that many, but asking for
// 2000, 5000 or 20000 all return exactly 1024. An earlier version of this file
// requested 2000 and treated "returned >= 2000" as the partial-result signal,
// which could therefore never fire — so on a graph big enough to saturate,
// truncated results were silently reported as complete. That was not
// hypothetical: on a 1024-package graph the native path reported 68 packages
// exposed by `chalk` against a true 89, 72 for `tslib` against 84, and 109 for
// `semver` against 120. Requesting exactly the ceiling makes saturation
// detectable. If a later image raises the ceiling, this stays correct — it
// just falls back to the exhaustive path more eagerly than strictly necessary,
// which is the right way to be wrong here.
const PATH_COUNT = 1024;

// The whole question — what is exposed, how far away each thing is, and the
// edges that connect them — answered by ONE call to HydraDB's native
// single-source path procedure.
//
// This is the same question blastRadiusFanout() answers with 1 + probes + N
// queries. algo.SSpaths returns whole paths rather than endpoints, and a path
// carries everything the fan-out version had to go back and ask for:
//
//   * the exposed set          — the endpoint of each path
//   * hop distance             — the length of the shortest path reaching it
//   * the edges among them     — the relationships along each path
//
// Verified to return byte-identical node sets, edge sets and hop distances to
// the fan-out implementation on every package in the demo graph, in 1 query
// instead of 10.
export async function blastRadiusNative(name, maxDepth = 6) {
  const start = Date.now();
  // relTypes must be an inline literal and sourceNode must be a bound
  // parameter — see the note on runQuery() in hydra.js.
  // Traversal budget, not the default one: this enumerates paths, so its cost
  // grows with graph density and it is exactly the query that outgrows a 10s
  // clock first.
  const rows = await runQuery(
    `CALL algo.SSpaths({sourceNode: $sourceNode, relTypes: ["REQUIRED_BY"], ` +
      `maxLen: ${maxDepth}, pathCount: ${PATH_COUNT}}) YIELD path RETURN path`,
    { sourceNode: packageId(name) },
    TRAVERSAL_TIMEOUT_MS
  );
  const coreQueryMs = Date.now() - start;

  if (rows.length >= PATH_COUNT) {
    throw new Error(
      `algo.SSpaths returned ${rows.length} paths, at the engine's ceiling; ` +
        `result may be partial`
    );
  }

  const nameOfVertex = new Map(); // vertex id -> package name
  const hopOf = new Map(); // package name -> shortest hop distance
  const edges = new Map(); // "dependent dependency" -> {from, to}

  for (const row of rows) {
    const path = row.path;
    if (!path || !Array.isArray(path.nodes)) continue;
    for (const node of path.nodes) {
      // Node properties arrive in their own envelope ({"String": "debug"}),
      // which is not the {type, value} shape unwrap() handles.
      const label = node.properties?.name?.String;
      if (label) nameOfVertex.set(node.id, label);
    }

    const names = path.nodes.map((node) => nameOfVertex.get(node.id));
    if (names.some((n) => !n)) continue; // a nameless vertex means a partial write; skip
    const endpoint = names[names.length - 1];
    const hops = names.length - 1;
    if (!hopOf.has(endpoint) || hopOf.get(endpoint) > hops) hopOf.set(endpoint, hops);

    // A REQUIRED_BY edge runs dependency -> dependent. The visualization draws
    // DEPENDS_ON, so each relationship is read back the other way round.
    for (const rel of path.relationships ?? []) {
      const from = nameOfVertex.get(rel.dst);
      const to = nameOfVertex.get(rel.src);
      if (from && to) edges.set(`${from} ${to}`, { from, to });
    }
  }

  // The target reaches itself through any dependency cycle; it is already the
  // hop-0 node, so listing it again would over-count the exposed total by one.
  hopOf.delete(name);

  return {
    target: name,
    nodes: [{ name, hop: 0 }, ...[...hopOf.entries()].map(([n, hop]) => ({ name: n, hop }))],
    edges: [...edges.values()],
    coreQueryMs,
    queryCount: 1,
    engine: "algo.SSpaths",
  };
}

// Tries the native procedure first and falls back to the portable
// variable-length traversal if it is unavailable or could not answer
// completely. HydraDB is a fast-moving alpha, so the fallback is not
// ceremony: the demo keeps working against an image where algo.SSpaths is
// missing or behaves differently, and the fallback is also what guarantees a
// complete answer if the path cap is ever hit.
export async function blastRadiusWithHops(name, maxDepth = 6) {
  try {
    return await blastRadiusNative(name, maxDepth);
  } catch (err) {
    // Why the fallback happened travels with the result rather than only
    // reaching a server log. The two reasons mean opposite things to whoever
    // is reading the answer: a saturated path ceiling means the fast path
    // would have UNDER-REPORTED this specific blast radius and the slower
    // exhaustive walk is what makes the number trustworthy, which is worth
    // saying out loud on a security tool. An unavailable procedure just means
    // a different engine build, with no bearing on completeness.
    const saturated = err.message.includes("ceiling");
    console.error(
      `algo.SSpaths unavailable or incomplete (${err.message.slice(0, 140)}); ` +
        `falling back to variable-length traversal`
    );
    const result = await blastRadiusFanout(name, maxDepth);
    return {
      ...result,
      fallbackReason: saturated ? "path-ceiling" : "procedure-unavailable",
    };
  }
}

// Same question as blastRadius(), but also reports each dependent's hop
// distance from the target and the DEPENDS_ON edges among the exposed set —
// the extra shape a radial-by-hop visualization needs. Every step is a real
// HydraDB traversal, not a client-side re-implementation of the graph walk.
//
// Kept as the fallback for blastRadiusWithHops() above: it needs no native
// procedure support, so it works against any build of the engine.
//
// Timing is reported in two separate numbers on purpose. `coreQueryMs` is
// the single traversal that actually answers "what is exposed" — the honest
// figure for how fast HydraDB answers the security question. The hop-layering
// probes and per-node edge lookups exist only to *draw* the result; they are
// kept out of that figure so presentation cost cannot masquerade as query
// cost. Their own cost is held down two ways: probing stops as soon as every
// exposed package has a hop (adaptive, so it scales with the graph's real
// depth rather than maxDepth), and the edge lookups — the part that grows
// with result size — are fanned out concurrently.
export async function blastRadiusFanout(name, maxDepth = 6) {
  // The core question: one traversal, one query.
  const coreStart = Date.now();
  const exposed = await blastRadius(name, maxDepth);
  const coreQueryMs = Date.now() - coreStart;

  // Hop distance = the shallowest depth bound at which a package still
  // shows up. Because the full result size is already known, probing can
  // stop the moment every exposed package has been assigned a hop — on a
  // graph that saturates at 2 hops that is 2 probes, not maxDepth of them.
  // Anything still unassigned when probing ends is, by elimination, exactly
  // maxDepth hops out.
  const hopOf = new Map();
  let probeCount = 0;
  for (let hop = 1; hop < maxDepth && hopOf.size < exposed.length; hop++) {
    const atThisDepth = await blastRadius(name, hop);
    probeCount++;
    for (const pkg of atThisDepth) {
      if (!hopOf.has(pkg)) hopOf.set(pkg, hop);
    }
  }
  for (const pkg of exposed) {
    if (!hopOf.has(pkg)) hopOf.set(pkg, maxDepth);
  }
  // The target can reappear in its own blast radius via a dependency cycle
  // (peerDeps merged into DEPENDS_ON routinely create these). It is already
  // the hop-0 node, so drop it here to avoid listing it twice and
  // over-counting the exposed total by one.
  hopOf.delete(name);

  // Edges among the exposed set, fetched concurrently rather than one
  // round trip at a time.
  const nodeNames = [name, ...hopOf.keys()];
  const nameSet = new Set(nodeNames);
  const edgeRows = await runQueriesConcurrent(
    nodeNames.map(
      (pkg) => `MATCH (a:Package {id: ${packageId(pkg)}})-[:DEPENDS_ON]->(b:Package) RETURN b.name AS name`
    )
  );

  const edges = [];
  nodeNames.forEach((pkg, i) => {
    for (const row of edgeRows[i]) {
      if (row.name && nameSet.has(row.name)) edges.push({ from: pkg, to: row.name });
    }
  });

  return {
    target: name,
    nodes: [{ name, hop: 0 }, ...[...hopOf.entries()].map(([n, hop]) => ({ name: n, hop }))],
    edges,
    coreQueryMs,
    queryCount: 1 + probeCount + nodeNames.length,
    engine: "variable-length MATCH",
  };
}

async function main() {
  const { name, depth } = parseArgs(process.argv.slice(2));

  // Confirm the package is actually in the graph before claiming "0 exposed".
  const exists = await runQuery(
    `MATCH (p:Package {id: ${packageId(name)}}) RETURN p.name AS name`
  );
  if (exists.length === 0) {
    // Only one thing can bring you here: the vertex does not exist. A package
    // that IS in the graph but has nothing depending on it passes this check
    // and reports "0 package(s) transitively exposed" below. The message used
    // to offer "or it has no known dependents" as an alternative explanation,
    // which cannot be true here and points the reader at the reassuring
    // reading — "nothing depends on it" — when the actual situation is that
    // the package was never ingested and nothing has been checked at all.
    console.log(`"${name}" is not in the ingested graph, so nothing has been checked — run ingestion for it first.`);
    return;
  }

  const exposed = await blastRadius(name, depth);
  console.log(`Blast radius for "${name}" (up to ${depth} hops): ${exposed.length} package(s) transitively exposed`);
  for (const pkg of exposed) console.log(`  - ${pkg}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Blast radius query failed:", err);
    process.exit(1);
  });
}
