// "Which other packages share a maintainer with the compromised one?"
//
// This is a different attack path from the dependency graph, and the one
// that actually mattered in the incident the track brief opens with: the
// TanStack worm spread through compromised *publish access*, pushing 84
// malicious artifacts across 42 packages in six minutes. None of those
// packages depended on each other — they shared a credential. A blast
// radius computed only over DEPENDS_ON edges would have missed all of it.
//
// The query is a two-hop traversal across two different edge types:
//   (target)-[:MAINTAINED_BY]->(maintainer)-[:MAINTAINS]->(sibling)
//
// Usage: node src/sharedMaintainers.js <package-name>

import { pathToFileURL } from "node:url";
import { runQuery, runQueryPagedKeyset, packageId, maintainerId } from "./hydra.js";

// Returns [{ maintainer, packages: [...] }], excluding the target itself.
export async function sharedMaintainers(name) {
  // Two steps rather than one, and the reason is paging rather than taste.
  //
  // This has to be paged at all because it yields one row per (maintainer,
  // package) pair, so a widely-trusted publisher passes the engine's silent
  // 1024-row cap long before the package count does — and this traversal IS
  // the project's headline finding, the reach a dependency scanner cannot see.
  //
  // But seek-paging needs a key that is unique per row, and neither column is:
  // one package appears once per maintainer, one maintainer once per package.
  // Seeking on either would drop the rows sharing a key with a page boundary.
  // Fetching the maintainers first (there are a handful — four for
  // `body-parser`, and the count is bounded by how many people can publish one
  // package) makes each follow-up query single-keyed on a unique package name,
  // which pages safely.
  const maintainerRows = await runQuery(
    `MATCH (target:Package {id: ${packageId(name)}})-[:MAINTAINED_BY]->(m:Maintainer) RETURN DISTINCT m.name AS maintainer`
  );

  const byMaintainer = new Map();
  for (const { maintainer } of maintainerRows) {
    if (!maintainer) continue;
    const rows = await runQueryPagedKeyset(
      `MATCH (m:Maintainer {id: ${maintainerId(maintainer)}})-[:MAINTAINS]->(sibling:Package) {{SEEK}} ` +
      `RETURN DISTINCT sibling.name AS pkg ORDER BY pkg`,
      "sibling.name",
      "pkg"
    );
    for (const row of rows) {
      if (!row.pkg || row.pkg === name) continue;
      if (!byMaintainer.has(maintainer)) byMaintainer.set(maintainer, new Set());
      byMaintainer.get(maintainer).add(row.pkg);
    }
  }

  return [...byMaintainer.entries()]
    .map(([maintainer, packages]) => ({ maintainer, packages: [...packages].sort() }))
    .filter((entry) => entry.packages.length > 0)
    .sort((a, b) => b.packages.length - a.packages.length);
}

// The union of everything reachable through shared publish rights.
export async function sharedMaintainerReach(name) {
  const groups = await sharedMaintainers(name);
  const reach = new Set();
  for (const g of groups) for (const p of g.packages) reach.add(p);
  return { groups, reach: [...reach].sort() };
}

async function main() {
  const name = process.argv[2];
  if (!name) {
    console.error("Usage: node src/sharedMaintainers.js <package-name>");
    process.exit(1);
  }

  const exists = await runQuery(`MATCH (p:Package {id: ${packageId(name)}}) RETURN p.name AS name`);
  if (exists.length === 0) {
    console.log(`"${name}" is not in the ingested graph — run ingestion first.`);
    return;
  }

  const { groups, reach } = await sharedMaintainerReach(name);
  if (groups.length === 0) {
    console.log(`No other ingested package shares a maintainer with "${name}".`);
    return;
  }

  console.log(
    `${reach.length} other package(s) share publish rights with "${name}", via ${groups.length} maintainer(s):\n`
  );
  for (const g of groups) {
    console.log(`  ${g.maintainer} also maintains ${g.packages.length}:`);
    for (const p of g.packages) console.log(`    - ${p}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Shared-maintainer query failed:", err);
    process.exit(1);
  });
}
