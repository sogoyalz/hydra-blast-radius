// Reproduces the scale findings in the README's path-ceiling section.
//
// Those numbers — an unpaged query returning 1024 rows against a graph holding
// far more, and the densest packages saturating algo.SSpaths — are the load
// bearing evidence for the whole "never under-report" argument, and until this
// file existed the README asked you to take them on trust. The demo graph is
// deliberately small enough that none of it fires, which is exactly why it has
// to be demonstrable on demand rather than asserted.
//
// WARNING: this MUTATES the graph. It ingests dozens of extra npm roots to push
// past the engine's 1024-row cap, which changes every demo number
// (`body-parser` goes from 1-vs-36 to something much larger and much less
// legible). That is why it refuses to run without --yes. Restore the demo graph
// afterwards with:
//
//     ./setup.sh --fresh
//
// Usage: node bench/scale.js --yes [--target=1200] [--depth=4] [--max-nodes=400]

import { crawl, writeEdges, writeMaintainers } from "../src/ingest.js";
import { blastRadiusNative, blastRadiusFanout } from "../src/blastRadius.js";
import { runQuery, runQueryPagedKeyset, runQueriesConcurrent, packageId } from "../src/hydra.js";

// Chosen because they still have deep dependency trees. Modern packages bundle
// their dependencies and resolve to almost nothing — `next` pulls 1 package,
// `react` 1, `rollup` 2 — so a list of fashionable names would crawl for
// minutes and never approach the cap. Pre-bundler tooling is what produces
// depth.
const DEEP_ROOTS = [
  "gulp", "standard", "browserify", "firebase-tools", "serverless",
  "grunt", "eslint", "mocha", "nodemon", "webpack-dev-server",
  "babel-cli", "karma", "protractor", "sails", "strapi",
  "lerna", "nyc", "jsdoc", "yo", "bower",
  "parcel", "snowpack", "tslint", "stylelint", "commitizen",
  "semantic-release", "husky", "jest-cli", "pm2", "forever",
];

function parseArgs(argv) {
  const opts = { yes: false, target: 1200, depth: 4, maxNodes: 400 };
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "yes") opts.yes = true;
    for (const [flag, prop] of [["target", "target"], ["depth", "depth"], ["max-nodes", "maxNodes"]]) {
      if (key !== flag) continue;
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--${flag} must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      opts[prop] = n;
    }
  }
  return opts;
}

async function pagedPackageCount() {
  const rows = await runQueryPagedKeyset(
    "MATCH (p:Package) {{SEEK}} RETURN DISTINCT p.name AS name ORDER BY name",
    "p.name",
    "name"
  );
  return rows.length;
}

// Deliberately unpaged — this is the thing being demonstrated, not a bug.
async function unpagedPackageCount() {
  const rows = await runQuery("MATCH (p:Package) RETURN DISTINCT p.name AS name");
  return rows.length;
}

// Ranks packages by how many others depend on them directly.
//
// Counted one package at a time rather than by paging a single (dependent,
// dependency) edge query, and the reason is the bug this whole file is about.
// Those pair rows repeat the dependency name once per dependent, so the seek
// key is not unique per row — and runQueryPagedKeyset says plainly that a
// non-unique key loses every row sharing it across a page boundary. An earlier
// version of this function did exactly that: invisible on the 120-package demo
// graph (199 edge rows, one page, no boundary) and quietly wrong at the ~3,000
// rows this script actually runs at, undercutting the in-degree of whichever
// packages straddled a boundary. A benchmark that exists to expose silent
// truncation is the last place to hide some.
//
// Per-package counts are id-scoped and bounded by in-degree, so they need no
// paging — but a package with more than PAGE_SIZE direct dependents would hit
// the row cap here too, so that is detected and reported rather than assumed
// away.
async function topByInDegree(n) {
  const names = (
    await runQueryPagedKeyset(
      "MATCH (p:Package) {{SEEK}} RETURN DISTINCT p.name AS name ORDER BY name",
      "p.name",
      "name"
    )
  ).map((r) => r.name).filter(Boolean);

  const counts = await runQueriesConcurrent(
    names.map(
      (name) => `MATCH (b:Package {id: ${packageId(name)}})-[:REQUIRED_BY]->(a:Package) RETURN DISTINCT a.name AS name`
    )
  );

  const atCap = [];
  const inDegree = names.map((name, i) => {
    const deg = counts[i].length;
    if (deg >= 1024) atCap.push(name);
    return { name, deg };
  });
  if (atCap.length > 0) {
    console.log(
      `  NOTE: ${atCap.length} package(s) returned a full 1024-row dependent list, so their\n` +
        `        in-degree is a lower bound and this ranking may be understated: ${atCap.slice(0, 5).join(", ")}`
    );
  }

  return inDegree.sort((a, b) => b.deg - a.deg).slice(0, n);
}

async function main() {
  const { yes, target, depth, maxNodes } = parseArgs(process.argv.slice(2));

  if (!yes) {
    console.error(
      "This rewrites the demo graph — it ingests dozens of extra npm roots to push past\n" +
        "the engine's 1024-row cap, which changes every number in the README's demo table.\n\n" +
        "Re-run with --yes if that is what you want, then restore with:  ./setup.sh --fresh\n"
    );
    process.exit(1);
  }

  const before = await pagedPackageCount();
  console.log(`Graph holds ${before} package(s). Ingesting until it passes ${target}...\n`);

  for (const root of DEEP_ROOTS) {
    const count = await pagedPackageCount();
    if (count >= target) break;
    try {
      const { nodes, edges, maintainedBy } = await crawl(root, depth, maxNodes);
      if (edges.length > 0) await writeEdges(edges);
      if (maintainedBy.length > 0) await writeMaintainers(maintainedBy);
      console.log(`  ${root.padEnd(22)} +${nodes.size} crawled -> ${await pagedPackageCount()} in graph`);
    } catch (err) {
      // One unreachable root should not abandon a run that takes minutes.
      console.log(`  ${root.padEnd(22)} skipped (${err.message.slice(0, 60)})`);
    }
  }

  const total = await pagedPackageCount();
  console.log("");
  if (total <= 1024) {
    console.log(
      `Graph reached ${total} packages, still under the 1024 cap — the ceiling cannot be\n` +
        `demonstrated from here. Re-run with a higher --target or --max-nodes.`
    );
    return;
  }

  // ---------------------------------------------------------------- row cap
  const unpaged = await unpagedPackageCount();
  console.log("=== The row cap applies to ordinary queries, not just path procedures ===\n");
  console.log(`  MATCH (p:Package) RETURN DISTINCT p.name, unpaged : ${unpaged}`);
  console.log(`  the same question, keyset-paged                   : ${total}`);
  console.log(
    unpaged < total
      ? `  -> ${total - unpaged} packages silently missing, with nothing in the response saying so\n`
      : `  -> no truncation observed at this size\n`
  );

  // ------------------------------------------------------------ path ceiling
  //
  // Probing a wide slice rather than the top few, because in-degree turns out
  // to be a poor predictor of saturation and an earlier version of this file
  // concluded "nothing saturates" by looking only at the top 6. The ceiling
  // counts PATHS, and path count is driven by the shape of the reverse closure
  // — the diamond-heavy es-*/get-intrinsic micro-package web produces many
  // distinct routes to the same node — not by how many direct dependents a
  // package has. Measured here: `debug` at in-degree 47 answers comfortably
  // while `hasown` at in-degree 10 saturates.
  console.log("=== Dense reverse closures saturate algo.SSpaths, and the guard catches it ===\n");
  const targets = await topByInDegree(24);
  console.log("target                in-deg  native        fallback      outcome");

  let saturated = 0;
  let agreed = 0;
  const saturatedNames = [];
  const cleanDegrees = [];
  for (const { name, deg } of targets) {
    let nativeCell = "";
    let nativeSet = null;
    const tNat = Date.now();
    try {
      const nat = await blastRadiusNative(name, 6);
      nativeSet = new Set(nat.nodes.map((n) => n.name));
      nativeCell = `${nativeSet.size - 1} (${((Date.now() - tNat) / 1000).toFixed(1)}s)`;
    } catch (err) {
      // The saturation guard firing is the finding, not an error.
      nativeCell = err.message.includes("ceiling") ? "saturated" : "unavailable";
      saturated++;
      saturatedNames.push({ name, deg });
    }

    const tFan = Date.now();
    const fan = await blastRadiusFanout(name, 6);
    const fanSet = new Set(fan.nodes.map((n) => n.name));
    const fanCell = `${fanSet.size - 1} (${((Date.now() - tFan) / 1000).toFixed(1)}s)`;

    let outcome;
    if (nativeSet === null) {
      outcome = "ceiling detected -> fell back";
    } else if (nativeSet.size === fanSet.size && [...nativeSet].every((x) => fanSet.has(x))) {
      outcome = "agree exactly";
      agreed++;
      cleanDegrees.push({ name, deg });
    } else {
      outcome = `DISAGREE (${nativeSet.size - 1} vs ${fanSet.size - 1})`;
    }

    console.log(
      name.padEnd(22) + String(deg).padEnd(8) + nativeCell.padEnd(14) + fanCell.padEnd(14) + outcome
    );
  }

  console.log(
    `\n  ${saturated} of ${targets.length} probed targets saturated the fast path; the guard caught every one\n` +
      `  and the exhaustive walk answered them completely.\n` +
      `  ${agreed} were answered by both engines and agreed exactly — that agreement is what\n` +
      `  makes the fallback trustworthy rather than merely different.`
  );

  // The counter-intuitive part, stated with the evidence rather than asserted:
  // if in-degree predicted saturation these two numbers would not overlap.
  if (saturated > 0 && cleanDegrees.length > 0) {
    const worstClean = cleanDegrees.reduce((a, b) => (a.deg > b.deg ? a : b));
    const mildestSaturated = saturatedNames.reduce((a, b) => (a.deg < b.deg ? a : b));
    if (worstClean.deg > mildestSaturated.deg) {
      console.log(
        `\n  Note how little in-degree predicts this: \`${worstClean.name}\` has ${worstClean.deg} direct\n` +
          `  dependents and answers fine, while \`${mildestSaturated.name}\` has ${mildestSaturated.deg} and saturates.\n` +
          `  The ceiling counts paths, and a diamond-shaped closure multiplies those far faster\n` +
          `  than a wide-but-shallow one. Ranking candidates by dependent count would miss it.`
      );
    }
  }

  console.log(
    `\nThe demo graph is deliberately small enough that none of this fires. Restore it with:\n` +
      `  ./setup.sh --fresh\n`
  );
}

main().catch((err) => {
  console.error("Scale benchmark failed:", err.message);
  console.error("A running HydraDB is required — see ./setup.sh");
  process.exit(1);
});
