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
import { runQuery, runQueriesConcurrent, packageId } from "./hydra.js";

function parseArgs(argv) {
  const [name, ...rest] = argv;
  if (!name) {
    console.error("Usage: node src/blastRadius.js <package-name> [--depth=6]");
    process.exit(1);
  }
  let depth = 6;
  for (const arg of rest) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "depth") depth = Number(value);
  }
  return { name, depth };
}

export async function blastRadius(name, depth = 6) {
  const id = packageId(name);
  const query = `MATCH (target:Package {id: ${id}})-[:REQUIRED_BY*1..${depth}]->(dependent:Package) RETURN DISTINCT dependent.name AS name`;
  const rows = await runQuery(query);
  return rows.map((r) => r.name).filter(Boolean);
}

// Same question as blastRadius(), but also reports each dependent's hop
// distance from the target and the DEPENDS_ON edges among the exposed set —
// the extra shape a radial-by-hop visualization needs. Every step is a real
// HydraDB traversal, not a client-side re-implementation of the graph walk.
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
export async function blastRadiusWithHops(name, maxDepth = 6) {
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
  };
}

async function main() {
  const { name, depth } = parseArgs(process.argv.slice(2));

  // Confirm the package is actually in the graph before claiming "0 exposed".
  const exists = await runQuery(
    `MATCH (p:Package {id: ${packageId(name)}}) RETURN p.name AS name`
  );
  if (exists.length === 0) {
    console.log(`"${name}" is not in the ingested graph — run ingestion first, or it has no known dependents.`);
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
