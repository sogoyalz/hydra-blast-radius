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
import { runQuery, packageId } from "./hydra.js";

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
// distance from the target and the DEPENDS_ON edges connecting the whole
// set — the extra shape a graph visualization needs (radial-by-hop layout).
// Every step is still a real HydraDB traversal query, not a client-side
// re-implementation of the graph walk: hop distance is found by re-running
// the variable-length query at increasing depth and diffing newly
// discovered names against the previous depth's result, stopping once a
// depth stops finding anything new (which is guaranteed to mean deeper
// depths won't find more, since results are monotonically cumulative).
export async function blastRadiusWithHops(name, maxDepth = 6) {
  const seen = new Map(); // name -> hop
  let previousSize = 0;
  for (let hop = 1; hop <= maxDepth; hop++) {
    const atThisDepth = await blastRadius(name, hop);
    if (atThisDepth.length === previousSize) break;
    for (const pkg of atThisDepth) {
      if (!seen.has(pkg)) seen.set(pkg, hop);
    }
    previousSize = atThisDepth.length;
  }

  const nodeNames = [name, ...seen.keys()];
  const nameSet = new Set(nodeNames);
  const edges = [];
  for (const pkg of nodeNames) {
    const rows = await runQuery(
      `MATCH (a:Package {id: ${packageId(pkg)}})-[:DEPENDS_ON]->(b:Package) RETURN b.name AS name`
    );
    for (const row of rows) {
      if (nameSet.has(row.name)) edges.push({ from: pkg, to: row.name });
    }
  }

  return {
    target: name,
    nodes: [{ name, hop: 0 }, ...[...seen.entries()].map(([n, hop]) => ({ name: n, hop }))],
    edges,
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
