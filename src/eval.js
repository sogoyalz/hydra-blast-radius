// Correctness eval for the blast-radius query.
//
// The Hack Hydra brief says Track 2A submissions are scored on precision,
// recall, query latency, and cost against ground truth from OSV and the
// GitHub Advisory Database, with recent advisories held out. We don't have
// access to HydraDB's own held-out harness, so this script builds the
// closest honest self-check we can:
//
//   1. Crawl a dependency tree (as ingest.js does) and keep the edge list
//      in memory.
//   2. Compute "ground truth" blast radius by BFS directly over that
//      in-memory edge list — no HydraDB involved.
//   3. Ingest the same edges into HydraDB, then ask HydraDB's own
//      REQUIRED_BY traversal for the same targets.
//   4. Compare the two sets (precision/recall/F1) and report latency.
//
// A mismatch here would mean the ingest/traversal logic is wrong — the two
// methods should agree exactly. This also cross-references targets against
// real OSV advisories so the demo has a genuine "this package actually has
// a known CVE" narrative, not just a synthetic example.
//
// Note: HydraDB accumulates whatever was previously ingested (that's the
// desired behavior for a real ecosystem graph — more ingested history means
// more complete blast-radius answers). This eval's precision comparison is
// only apples-to-apples against a *clean* database, since the ground truth
// here only knows about the current crawl's edges. Reset the container
// (see README) before running this for a clean precision/recall number;
// running it against an already-populated graph is still useful as a smoke
// test (recall should stay 1.0; precision may look artificially low from
// correct extra matches found elsewhere in the graph).
//
// Usage: node src/eval.js <root-package> [--depth=3] [--max-nodes=150] [--targets=a,b,c]

import { crawl, writeEdges } from "./ingest.js";
import { blastRadius } from "./blastRadius.js";

function parseArgs(argv) {
  const [root, ...rest] = argv;
  if (!root) {
    console.error("Usage: node src/eval.js <root-package> [--depth=3] [--max-nodes=150] [--targets=a,b,c]");
    process.exit(1);
  }
  const opts = { root, depth: 3, maxNodes: 150, targets: null };
  for (const arg of rest) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "depth") opts.depth = Number(value);
    if (key === "max-nodes") opts.maxNodes = Number(value);
    if (key === "targets") opts.targets = value.split(",").map((s) => s.trim());
  }
  return opts;
}

// BFS over the in-memory edge list to find every package that transitively
// depends on `target` — the same question blastRadius() asks HydraDB.
function groundTruthBlastRadius(edges, target, maxDepth) {
  const reverseAdj = new Map(); // package -> [packages that depend on it]
  for (const { from, to } of edges) {
    if (!reverseAdj.has(to)) reverseAdj.set(to, []);
    reverseAdj.get(to).push(from);
  }

  const visited = new Set();
  let frontier = [target];
  for (let hop = 0; hop < maxDepth && frontier.length > 0; hop++) {
    const next = [];
    for (const pkg of frontier) {
      for (const dependent of reverseAdj.get(pkg) ?? []) {
        if (!visited.has(dependent)) {
          visited.add(dependent);
          next.push(dependent);
        }
      }
    }
    frontier = next;
  }
  return visited;
}

function precisionRecall(predicted, actual) {
  const tp = [...predicted].filter((x) => actual.has(x)).length;
  const precision = predicted.size === 0 ? 1 : tp / predicted.size;
  const recall = actual.size === 0 ? 1 : tp / actual.size;
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1, truePositives: tp };
}

async function fetchOsvAdvisories(packageName) {
  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" } }),
    });
    if (!res.ok) return [];
    const body = await res.json();
    return body.vulns ?? [];
  } catch {
    return [];
  }
}

// Picks a handful of non-trivial targets automatically: packages with the
// most incoming edges (most depended-upon), which make the most interesting
// blast-radius demos.
function pickDefaultTargets(edges, count = 5) {
  const inDegree = new Map();
  for (const { to } of edges) inDegree.set(to, (inDegree.get(to) ?? 0) + 1);
  return [...inDegree.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, count)
    .map(([name]) => name);
}

async function main() {
  const { root, depth, maxNodes, targets: targetArg } = parseArgs(process.argv.slice(2));

  console.log(`Crawling "${root}" (depth=${depth}, maxNodes=${maxNodes})...`);
  const { nodes, edges, truncated } = await crawl(root, depth, maxNodes);
  console.log(`Discovered ${nodes.size} packages, ${edges.length} edges.`);
  if (truncated) {
    console.log(`NOTE: hit the --max-nodes=${maxNodes} cap; this graph is partial.`);
  }

  // Guard against a vacuous pass: an empty crawl has no targets, and
  // precision/recall over empty sets both default to 1, so without this the
  // script would print "All targets match" having compared nothing.
  if (edges.length === 0) {
    console.error(`No edges discovered for "${root}" — nothing to evaluate. Try a package with dependencies.`);
    process.exit(1);
  }

  console.log(`Writing to HydraDB...`);
  await writeEdges(edges);

  const targets = targetArg ?? pickDefaultTargets(edges);
  console.log(`\nEvaluating ${targets.length} target(s): ${targets.join(", ")}\n`);

  const rows = [];
  for (const target of targets) {
    const truth = groundTruthBlastRadius(edges, target, depth);

    const start = Date.now();
    const hydraResult = new Set(await blastRadius(target, depth));
    const latencyMs = Date.now() - start;

    const { precision, recall, f1, truePositives } = precisionRecall(hydraResult, truth);
    const advisories = await fetchOsvAdvisories(target);

    rows.push({
      target,
      groundTruth: truth.size,
      hydraResult: hydraResult.size,
      truePositives,
      precision,
      recall,
      f1,
      latencyMs,
      knownAdvisories: advisories.length,
    });
  }

  console.log("target".padEnd(20), "truth".padEnd(7), "hydra".padEnd(7), "P".padEnd(6), "R".padEnd(6), "F1".padEnd(6), "ms".padEnd(6), "OSV advisories");
  for (const r of rows) {
    console.log(
      r.target.padEnd(20),
      String(r.groundTruth).padEnd(7),
      String(r.hydraResult).padEnd(7),
      r.precision.toFixed(2).padEnd(6),
      r.recall.toFixed(2).padEnd(6),
      r.f1.toFixed(2).padEnd(6),
      String(r.latencyMs).padEnd(6),
      r.knownAdvisories
    );
  }

  const allMatch = rows.every((r) => r.precision === 1 && r.recall === 1);
  console.log(
    allMatch
      ? "\nAll targets: HydraDB's blast radius exactly matches the independently computed ground truth."
      : "\nMismatch found — HydraDB's traversal disagrees with the in-memory ground truth on at least one target."
  );
}

main().catch((err) => {
  console.error("Eval failed:", err);
  process.exit(1);
});
