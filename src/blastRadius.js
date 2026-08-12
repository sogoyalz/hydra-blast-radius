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
