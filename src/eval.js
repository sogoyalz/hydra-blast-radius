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
// WHAT THIS DOES AND DOES NOT PROVE. It is a correctness gate on the
// ingest -> store -> traverse round trip: it answers "does HydraDB return
// exactly the set that is actually reachable in the graph we wrote". It is
// NOT a measure of vulnerability-detection accuracy against OSV/GHSA, and
// 1.00/1.00 here should not be read as one — the ground truth is BFS over
// the same edge list that was just written, so the score can only drop if
// ingestion or traversal is broken. That makes it a strong regression test
// and a weak accuracy claim, and it is reported as such. Measuring true
// detection accuracy needs the organizers' held-out advisory set, which
// entrants do not have.
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

import { pathToFileURL } from "node:url";
import { crawl, writeEdges } from "./ingest.js";
import { blastRadius } from "./blastRadius.js";
import { fetchWithTimeout } from "./hydra.js";

function parseArgs(argv) {
  const [root, ...rest] = argv;
  if (!root) {
    console.error("Usage: node src/eval.js <root-package> [--depth=3] [--max-nodes=150] [--targets=a,b,c]");
    process.exit(1);
  }
  const opts = { root, depth: 3, maxNodes: 150, targets: null };
  for (const arg of rest) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    // Same validation as ingest.js: Number("abc") is NaN, and every
    // comparison against NaN is false, so an unnoticed typo silently turns
    // the crawl cap or the depth bound off instead of erroring. An eval that
    // quietly measured the wrong thing would be worse than one that stopped.
    if (key === "depth" || key === "max-nodes") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--${key} must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      if (key === "depth") opts.depth = n;
      else opts.maxNodes = n;
    }
    if (key === "targets") {
      opts.targets = value.split(",").map((s) => s.trim()).filter(Boolean);
      if (opts.targets.length === 0) {
        console.error(`--targets needs at least one package name`);
        process.exit(1);
      }
    }
  }
  return opts;
}

// BFS over the in-memory edge list to find every package that transitively
// depends on `target` — the same question blastRadius() asks HydraDB.
export function groundTruthBlastRadius(edges, target, maxDepth) {
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

export function precisionRecall(predicted, actual) {
  const tp = [...predicted].filter((x) => actual.has(x)).length;
  const precision = predicted.size === 0 ? 1 : tp / predicted.size;
  const recall = actual.size === 0 ? 1 : tp / actual.size;
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1, truePositives: tp };
}

// OSV lookups are shared between target selection and the results table, so
// each package is fetched at most once per run.
const osvCache = new Map();
async function osvAdvisoryCount(packageName) {
  if (osvCache.has(packageName)) return osvCache.get(packageName);
  let count = 0;
  try {
    const res = await fetchWithTimeout(
      "https://api.osv.dev/v1/query",
      { method: "POST", body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" } }) },
      8_000
    );
    if (res.ok) {
      const body = await res.json();
      count = (body.vulns ?? []).length;
    }
  } catch {
    count = 0;
  }
  osvCache.set(packageName, count);
  return count;
}

// Picks targets that make the eval say something.
//
// Ranking purely by in-degree (most depended-upon) gives the biggest blast
// radii, but in a typical npm tree the highest-in-degree packages are stable
// low-level utilities — `statuses`, `depd`, `content-type` — that have never
// had an advisory. That made the OSV column print all zeros on every default
// run, so the ground-truth cross-reference looked like a dead integration
// even though it works. Instead: rank a wider slice by in-degree, prefer the
// ones carrying real advisories, then backfill by in-degree so the table
// still covers the most-connected packages.
async function pickDefaultTargets(edges, count = 5) {
  const inDegree = new Map();
  for (const { to } of edges) inDegree.set(to, (inDegree.get(to) ?? 0) + 1);
  const ranked = [...inDegree.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name]) => name);

  const pool = ranked.slice(0, Math.max(count * 4, 20));
  const counts = await Promise.all(pool.map((name) => osvAdvisoryCount(name)));
  const picked = pool.filter((_, i) => counts[i] > 0).slice(0, count);

  for (const name of ranked) {
    if (picked.length >= count) break;
    if (!picked.includes(name)) picked.push(name);
  }
  return picked;
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

  const targets = targetArg ?? (await pickDefaultTargets(edges));
  console.log(`\nEvaluating ${targets.length} target(s): ${targets.join(", ")}\n`);

  const rows = [];
  for (const target of targets) {
    const truth = groundTruthBlastRadius(edges, target, depth);

    const start = Date.now();
    const hydraResult = new Set(await blastRadius(target, depth));
    const latencyMs = Date.now() - start;

    const { precision, recall, f1, truePositives } = precisionRecall(hydraResult, truth);
    const knownAdvisories = await osvAdvisoryCount(target);

    // Not every "extra" is an error. HydraDB accumulates every graph ever
    // ingested, so on a database that already holds another crawl it can
    // return dependents this crawl never saw — those are correct answers the
    // in-memory ground truth simply has no way to know about. Splitting the
    // extras by whether the package was part of THIS crawl separates the two
    // cases: a package outside the crawl is prior knowledge, while one inside
    // the crawl that the BFS did not reach is a genuine disagreement and the
    // only kind that should fail the run.
    //
    // Without this split the eval printed a red FAIL on any non-fresh
    // database — including the obvious path of running ./setup.sh and then
    // the eval command the README suggests — which looks like a broken
    // project rather than the expected consequence of a richer graph.
    const extras = [...hydraResult].filter((p) => !truth.has(p));
    const fromPriorIngest = extras.filter((p) => !nodes.has(p));
    const contradictions = extras.filter((p) => nodes.has(p));

    rows.push({
      target,
      groundTruth: truth.size,
      hydraResult: hydraResult.size,
      truePositives,
      precision,
      recall,
      f1,
      latencyMs,
      knownAdvisories,
      priorIngest: fromPriorIngest.length,
      contradictions,
    });
  }

  const priorTotal = rows.reduce((n, r) => n + r.priorIngest, 0);

  console.log("target".padEnd(20), "truth".padEnd(7), "hydra".padEnd(7), "P".padEnd(6), "R".padEnd(6), "F1".padEnd(6), "ms".padEnd(6), "prior".padEnd(6), "OSV advisories");
  for (const r of rows) {
    console.log(
      r.target.padEnd(20),
      String(r.groundTruth).padEnd(7),
      String(r.hydraResult).padEnd(7),
      r.precision.toFixed(2).padEnd(6),
      r.recall.toFixed(2).padEnd(6),
      r.f1.toFixed(2).padEnd(6),
      String(r.latencyMs).padEnd(6),
      String(r.priorIngest).padEnd(6),
      r.knownAdvisories
    );
  }

  // Recall must be perfect (nothing reachable may be missed — the failure that
  // matters for a security tool) and nothing inside this crawl may be claimed
  // that the independent BFS did not reach.
  const missed = rows.filter((r) => r.recall < 1);
  const contradicted = rows.filter((r) => r.contradictions.length > 0);
  const clean = missed.length === 0 && contradicted.length === 0;

  if (!clean) {
    console.log("\nFAIL — HydraDB's traversal disagrees with the independently computed ground truth.");
    for (const r of missed) {
      console.log(`       ${r.target}: recall ${r.recall.toFixed(2)} — reachable packages were NOT returned.`);
    }
    for (const r of contradicted) {
      console.log(
        `       ${r.target}: returned ${r.contradictions.length} package(s) from this crawl that the BFS ` +
        `never reached (${r.contradictions.slice(0, 5).join(", ")}).`
      );
    }
    process.exitCode = 1;
  } else if (priorTotal > 0) {
    console.log(
      `\nPASS — every package reachable in this crawl was returned, and nothing from this crawl\n` +
      `       was returned that should not have been (recall 1.00, no contradictions).\n\n` +
      `       The precision column is below 1.00 only because this database already held other\n` +
      `       ingests: ${priorTotal} returned package(s) are real dependents from an earlier crawl that\n` +
      `       this run's in-memory ground truth cannot know about — correct answers scored as\n` +
      `       false positives. For a clean 1.00/1.00 table the graph has to hold nothing but\n` +
      `       this crawl: ./setup.sh --fresh --no-ingest, then re-run. (Plain --fresh reloads\n` +
      `       the demo graph, which this eval then correctly counts as prior knowledge.)\n\n` +
      `       This gates the ingest -> store -> traverse round trip; it is not a\n` +
      `       vulnerability-detection accuracy score (see the note at the top of this file).`
    );
  } else {
    console.log(
      "\nPASS — HydraDB's blast radius exactly matches the independently computed ground truth\n" +
      "       on every target. This gates the ingest -> store -> traverse round trip; it is not\n" +
      "       a vulnerability-detection accuracy score (see the note at the top of this file)."
    );
  }
}

// Same entry-point guard the other CLI files use. Without it, merely
// importing this module to reuse groundTruthBlastRadius() or precisionRecall()
// — which the test suite does — kicks off a full npm crawl and writes to
// HydraDB as a side effect of the import.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Eval failed:", err);
    process.exit(1);
  });
}
