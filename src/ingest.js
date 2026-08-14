// Walks the npm dependency graph starting at a root package (breadth-first,
// bounded by depth and node count) and loads it into HydraDB as
// (:Package {name})-[:DEPENDS_ON]->(:Package {name}) edges.
//
// Usage: node src/ingest.js <package-name> [--depth=4] [--max-nodes=300]

import { pathToFileURL } from "node:url";
import { runQuery, cypherString, packageId, maintainerId, fetchWithTimeout } from "./hydra.js";

const REGISTRY = "https://registry.npmjs.org";
const CRAWL_CONCURRENCY = 8;
const WRITE_CONCURRENCY = 16;

function parseArgs(argv) {
  const [root, ...rest] = argv;
  if (!root) {
    console.error("Usage: node src/ingest.js <package-name> [--depth=4] [--max-nodes=300]");
    process.exit(1);
  }
  const opts = { root, depth: 4, maxNodes: 300 };
  for (const arg of rest) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    // Validate positive integers: an unnoticed typo like --max-nodes=abc
    // yields NaN, and `visited.size >= NaN` / `depth < NaN` are always false,
    // which silently disables the crawl cap (unbounded walk) or the depth
    // bound (empty result). Fail loudly instead.
    if (key === "depth" || key === "max-nodes") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--${key} must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      if (key === "depth") opts.depth = n;
      else opts.maxNodes = n;
    }
  }
  return opts;
}

// npm registry path for a package's manifest. Dependency names come from
// third-party manifests, so a malformed key like "../../-/user/x" must not be
// able to steer the fetch off the manifest endpoint. encodeURIComponent
// escapes everything (including "/", "?", "#", ".."), then the one legitimate
// slash in a scoped name is restored as the registry-accepted "%2f".
function registryUrl(name) {
  const scoped = name.startsWith("@") && name.includes("/");
  if (scoped) {
    const [scope, pkg] = name.split("/", 2);
    return `${REGISTRY}/${encodeURIComponent(scope)}%2f${encodeURIComponent(pkg)}/latest`;
  }
  return `${REGISTRY}/${encodeURIComponent(name)}/latest`;
}

async function fetchManifest(name) {
  // A single stalled registry request must not stall the whole crawl —
  // callers already treat a thrown error as "skip this package" (see the
  // try/catch around fetchManifest() in crawl() below).
  const res = await fetchWithTimeout(registryUrl(name), {}, 10_000);
  if (!res.ok) return null; // unpublished, deprecated-and-removed, private, etc. — skip
  const manifest = await res.json();
  return {
    dependencies: {
      ...(manifest.dependencies ?? {}),
      ...(manifest.peerDependencies ?? {}),
    },
    // Publish rights are an attack path in their own right: the TanStack
    // worm spread through compromised publishing access, not through a
    // vulnerable dependency edge. Capturing maintainers lets the graph
    // answer "who else could this actor push to".
    maintainers: (manifest.maintainers ?? []).map((m) => m?.name).filter(Boolean),
  };
}

async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// `maxNodes` is a hard cap on how many distinct packages end up in the
// graph, and `visited` is exactly the set that gets written — every edge
// emitted has both endpoints in `visited`, so the count reported to the
// user matches what is actually in HydraDB. (An earlier version added the
// whole frontier to `visited` before checking the cap, which both blew past
// maxNodes and under-reported the true vertex count.)
//
// `truncated` is returned so callers can say so out loud: a blast radius
// computed over a truncated graph is a *lower bound*, and silently
// presenting a partial answer as complete is the one failure mode a
// supply-chain tool cannot afford.
export async function crawl(root, maxDepth, maxNodes) {
  const visited = new Set([root]);
  const edges = []; // {from, to} — both endpoints always in `visited`
  const maintainedBy = []; // {pkg, maintainer}
  let frontier = [{ name: root, depth: 0 }];
  let truncated = false;

  while (frontier.length > 0) {
    const toFetch = frontier.filter((node) => node.depth < maxDepth);
    if (toFetch.length === 0) break;

    const results = await mapWithConcurrency(toFetch, CRAWL_CONCURRENCY, async (node) => {
      let manifest;
      try {
        manifest = await fetchManifest(node.name);
      } catch {
        manifest = null;
      }
      return { node, manifest };
    });

    const nextFrontier = [];
    for (const { node, manifest } of results) {
      if (!manifest) continue;
      const deps = manifest.dependencies;
      for (const maintainer of manifest.maintainers) {
        maintainedBy.push({ pkg: node.name, maintainer });
      }
      for (const depName of Object.keys(deps)) {
        if (!visited.has(depName)) {
          if (visited.size >= maxNodes) {
            truncated = true;
            continue; // skip the edge too, so every edge endpoint stays in `visited`
          }
          visited.add(depName);
          nextFrontier.push({ name: depName, depth: node.depth + 1 });
        }
        edges.push({ from: node.name, to: depName });
      }
    }
    frontier = nextFrontier;
    process.stderr.write(`\rvisited ${visited.size} packages, ${edges.length} edges found...`);
  }
  process.stderr.write("\n");

  // Only keep publish-rights facts for packages that made the node cap, so
  // the maintainer graph stays consistent with the dependency graph.
  return {
    nodes: visited,
    edges,
    maintainedBy: maintainedBy.filter((m) => visited.has(m.pkg)),
    truncated,
  };
}

// HydraDB's current MERGE implementation only upserts vertices by an integer
// `id`, and neither UNWIND-batched MERGE nor MERGE-then-SET are supported
// yet (confirmed against the local dev node) — so each edge is written as
// its own request, with both endpoint names carried inline as properties:
//   MERGE (a:Package {id: 111, name: 'express'})-[:DEPENDS_ON]->(b:Package {id: 222, name: 'body-parser'})
// See src/hydra.js's packageId() for the name -> id mapping.
//
// A REQUIRED_BY edge (dependency -> dependent) is written alongside every
// DEPENDS_ON edge (dependent -> dependency). This is because HydraDB's
// variable-length MATCH requires the *edge-direction source* to carry the
// fixed id ("variable-length MATCH requires a fixed source id") — it can
// only expand forward from a known starting vertex, not backward into one.
// Blast-radius queries need "everything that transitively depends on X"
// starting from a fixed X, which is exactly a forward traversal over
// REQUIRED_BY. Mirroring the edge at write time is the standard way to get
// O(1)-per-hop traversal in both directions out of a single ingest pass.
export async function writeEdges(edges) {
  let written = 0;
  let failed = 0;
  // MERGE cannot be followed by another clause (including a second MERGE) in
  // this engine, so the forward and mirrored-reverse edges are two requests.
  await mapWithConcurrency(edges, WRITE_CONCURRENCY, async (edge) => {
    const fromId = packageId(edge.from);
    const toId = packageId(edge.to);
    const fromName = cypherString(edge.from);
    const toName = cypherString(edge.to);
    try {
      await runQuery(
        `MERGE (a:Package {id: ${fromId}, name: ${fromName}})-[:DEPENDS_ON]->(b:Package {id: ${toId}, name: ${toName}})`
      );
      await runQuery(
        `MERGE (b:Package {id: ${toId}, name: ${toName}})-[:REQUIRED_BY]->(a:Package {id: ${fromId}, name: ${fromName}})`
      );
      written++;
    } catch (err) {
      failed++;
      process.stderr.write(`\nfailed to write ${edge.from} -> ${edge.to}: ${err.message}\n`);
    }
    process.stderr.write(`\rwrote ${written}/${edges.length} edges${failed ? ` (${failed} failed)` : ""}...`);
  });
  process.stderr.write("\n");
  return { written, failed };
}

// Publish-rights edges, mirrored for the same reason dependency edges are:
// "which packages share a maintainer with X" has to start from a fixed X and
// walk outward, so both directions are materialised at write time.
export async function writeMaintainers(links) {
  let written = 0;
  let failed = 0;
  await mapWithConcurrency(links, WRITE_CONCURRENCY, async (link) => {
    const pkgId = packageId(link.pkg);
    const mId = maintainerId(link.maintainer); // separate id namespace — see hydra.js
    const pkgName = cypherString(link.pkg);
    const mName = cypherString(link.maintainer);
    try {
      await runQuery(
        `MERGE (p:Package {id: ${pkgId}, name: ${pkgName}})-[:MAINTAINED_BY]->(m:Maintainer {id: ${mId}, name: ${mName}})`
      );
      await runQuery(
        `MERGE (m:Maintainer {id: ${mId}, name: ${mName}})-[:MAINTAINS]->(p:Package {id: ${pkgId}, name: ${pkgName}})`
      );
      written++;
    } catch (err) {
      failed++;
      process.stderr.write(`\nfailed to write ${link.pkg} -> ${link.maintainer}: ${err.message}\n`);
    }
    process.stderr.write(`\rwrote ${written}/${links.length} maintainer links${failed ? ` (${failed} failed)` : ""}...`);
  });
  process.stderr.write("\n");
  return { written, failed };
}

async function main() {
  const { root, depth, maxNodes } = parseArgs(process.argv.slice(2));
  console.log(`Crawling npm dependency graph from "${root}" (depth=${depth}, maxNodes=${maxNodes})`);

  const start = Date.now();
  const { nodes, edges, maintainedBy, truncated } = await crawl(root, depth, maxNodes);
  const distinctMaintainers = new Set(maintainedBy.map((m) => m.maintainer)).size;
  console.log(
    `Discovered ${nodes.size} packages, ${edges.length} DEPENDS_ON edges and ` +
    `${distinctMaintainers} maintainers in ${((Date.now() - start) / 1000).toFixed(1)}s`
  );

  if (truncated) {
    console.log(
      `NOTE: hit the --max-nodes=${maxNodes} cap, so this crawl is partial. Blast-radius\n` +
      `      results over this graph are a lower bound. Raise --max-nodes for full coverage.`
    );
  }

  if (edges.length === 0 && maintainedBy.length === 0) {
    console.log("Nothing to write — no dependencies and no maintainers found.");
    return;
  }

  let depResult = { written: 0, failed: 0 };
  if (edges.length > 0) {
    console.log(`Writing dependency edges to HydraDB...`);
    depResult = await writeEdges(edges);
  } else {
    // A package with no dependencies used to be dropped entirely here, which
    // silently excluded exactly the shape a typosquat usually takes: freshly
    // published, zero dependencies, riding on a name. Its publish-rights
    // links still carry it into the graph — and they have to, because
    // HydraDB rejects a bare single-vertex MERGE outside UNWIND ("only
    // one-hop edge patterns are executable in Query engine MERGE"), so an
    // edge is the only way to create the vertex at all.
    console.log(
      `"${root}" has no dependencies — writing its publish-rights links so the\n` +
      `package still enters the graph.`
    );
  }

  let maintResult = { failed: 0 };
  if (maintainedBy.length > 0) {
    console.log(`Writing maintainer edges to HydraDB...`);
    maintResult = await writeMaintainers(maintainedBy);
  }

  // A failed write is not cosmetic: every blast-radius answer traverses the
  // REQUIRED_BY mirror, so a dropped write makes an exposed package silently
  // invisible. Exit non-zero so a partial ingest can't pass as a clean graph
  // (and so setup.sh's `set -e` stops rather than serving bad data).
  const totalFailed = depResult.failed + maintResult.failed;
  if (totalFailed > 0) {
    console.error(
      `\nERROR: ${totalFailed} edge write(s) failed. The graph is incomplete — ` +
      `blast-radius results would under-report. Re-run ingestion.`
    );
    process.exit(1);
  }

  console.log(
    `Done. Ingested ${nodes.size} packages, ${edges.length} dependency edges and ` +
    `${maintainedBy.length} publish-rights links rooted at "${root}".`
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Ingestion failed:", err);
    process.exit(1);
  });
}
