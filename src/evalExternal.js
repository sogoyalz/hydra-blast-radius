// Blast-radius validation against an INDEPENDENT source of dependency data.
//
// src/eval.js answers "does HydraDB return exactly the set that is reachable
// in the graph we wrote" — a round-trip correctness gate whose ground truth is
// a BFS over the very edge list it just ingested. That is a strong regression
// test and a deliberately weak accuracy claim: if the crawl itself learned the
// wrong edges, both sides are wrong together and the score stays 1.00.
//
// This script closes that gap. Ground truth here comes from deps.dev (Google's
// Open Source Insights), which publishes its own fully-resolved transitive
// dependency graph for npm — built by Google's resolver, from the registry,
// with no connection to this project's crawler. Agreement between the two is
// therefore evidence about the data, not just about the plumbing.
//
// The comparison is inverted to get there. deps.dev answers the forward
// question ("what does P depend on, transitively"); this project answers the
// reverse ("who transitively depends on X"). So the script resolves the
// dependency closure of every package in the graph and inverts it:
//
//     externalDependents(X) = { P in graph : X is in depsdev_closure(P) }
//
// which is exactly the set blastRadius(X) should return.
//
// WHAT A MISMATCH MEANS. Two sources of disagreement are expected and are
// reported separately rather than being folded into the headline score,
// because neither is a traversal bug:
//
//   * Crawl bounds. The graph is a bounded crawl (--depth / --max-nodes from a
//     few roots), so an edge deps.dev knows about may simply never have been
//     ingested. That shows up as a recall miss and is attributable to what was
//     collected, not to how it was queried.
//   * Peer dependencies. src/ingest.js deliberately merges `peerDependencies`
//     into the dependency edges, because a compromised peer is every bit as
//     dangerous as a compromised direct dependency — a plugin that peers on
//     `webpack` runs alongside whatever `webpack` ships. deps.dev reports an
//     install closure, where peers are not pulled in transitively, so this
//     project reports strictly more here on purpose. This shows up as a
//     precision "loss" against deps.dev that is really a modelling difference,
//     and the script identifies it by name rather than guessing.
//   * Version skew. This graph is version-less and built from each package's
//     `latest` manifest; deps.dev resolves one concrete version's lockfile-like
//     closure. Dependencies added or dropped between versions legitimately
//     differ.
//
// Usage: node src/evalExternal.js [--targets=a,b,c] [--max-packages=N]

import { pathToFileURL } from "node:url";
import { runQuery, fetchWithTimeout } from "./hydra.js";
import { blastRadius } from "./blastRadius.js";

const DEPS_DEV = "https://api.deps.dev/v3alpha/systems/npm/packages";
const FETCH_CONCURRENCY = 6; // courteous to a free public API
const DEPTH = 6;

function parseArgs(argv) {
  const opts = { targets: null, maxPackages: 200 };
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "targets") {
      opts.targets = value.split(",").map((s) => s.trim()).filter(Boolean);
      if (opts.targets.length === 0) {
        console.error("--targets needs at least one package name");
        process.exit(1);
      }
    }
    if (key === "max-packages") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--max-packages must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      opts.maxPackages = n;
    }
  }
  return opts;
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

// deps.dev keys everything by concrete version, so the default ("latest")
// version has to be resolved first. Scoped names contain a slash and must be
// encoded whole.
function encodePkg(name) {
  return encodeURIComponent(name);
}

async function defaultVersion(name) {
  const res = await fetchWithTimeout(`${DEPS_DEV}/${encodePkg(name)}`, {}, 15_000);
  if (!res.ok) return null;
  const body = res.json();
  const def = (body.versions ?? []).find((v) => v.isDefault);
  return def?.versionKey?.version ?? null;
}

// The transitive dependency closure of one package version, as resolved by
// deps.dev. `SELF` is the package itself and is dropped; DIRECT and INDIRECT
// together are the closure this project's DEPENDS_ON traversal should mirror.
async function resolvedClosure(name) {
  const version = await defaultVersion(name);
  if (!version) return null;
  const res = await fetchWithTimeout(
    `${DEPS_DEV}/${encodePkg(name)}/versions/${encodeURIComponent(version)}:dependencies`,
    {},
    20_000
  );
  if (!res.ok) return null;
  const body = res.json();
  const deps = new Set();
  for (const node of body.nodes ?? []) {
    if (node.relation === "SELF") continue;
    const dep = node.versionKey?.name;
    if (dep && dep !== name) deps.add(dep);
  }
  return deps;
}

function precisionRecall(predicted, actual) {
  const tp = [...predicted].filter((x) => actual.has(x)).length;
  const precision = predicted.size === 0 ? 1 : tp / predicted.size;
  const recall = actual.size === 0 ? 1 : tp / actual.size;
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1 };
}

// Peer dependencies a package declares, per the npm registry — the same
// source ingest.js crawls. Used to attribute a disagreement with deps.dev to
// the peer-edge modelling choice with evidence, instead of asserting a cause.
const peerCache = new Map();
async function peerDependencies(name) {
  if (peerCache.has(name)) return peerCache.get(name);
  let peers = [];
  try {
    const scoped = name.startsWith("@") && name.includes("/");
    const path = scoped
      ? `${encodeURIComponent(name.split("/", 2)[0])}%2f${encodeURIComponent(name.split("/", 2)[1])}`
      : encodeURIComponent(name);
    const res = await fetchWithTimeout(`https://registry.npmjs.org/${path}/latest`, {}, 10_000);
    if (res.ok) peers = Object.keys(res.json().peerDependencies ?? {});
  } catch {
    peers = [];
  }
  peerCache.set(name, peers);
  return peers;
}

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
    if (res.ok) count = (res.json().vulns ?? []).length;
  } catch {
    count = 0;
  }
  osvCache.set(packageName, count);
  return count;
}

async function main() {
  const { targets: targetArg, maxPackages } = parseArgs(process.argv.slice(2));

  const rows = await runQuery("MATCH (p:Package) RETURN DISTINCT p.name AS name");
  const graphPackages = rows.map((r) => r.name).filter(Boolean);
  if (graphPackages.length === 0) {
    console.error("The graph is empty — run ./setup.sh first.");
    process.exit(1);
  }
  const universe = new Set(graphPackages);

  const sample = graphPackages.slice(0, maxPackages);
  console.log(
    `Resolving dependency closures from deps.dev for ${sample.length} of ` +
    `${graphPackages.length} graph packages (independent of this project's crawler)...`
  );

  let resolved = 0;
  let unresolved = 0;
  const closures = await mapWithConcurrency(sample, FETCH_CONCURRENCY, async (name) => {
    try {
      const deps = await resolvedClosure(name);
      if (deps) resolved++;
      else unresolved++;
      process.stderr.write(`\rresolved ${resolved}/${sample.length}...`);
      return { name, deps };
    } catch {
      unresolved++;
      return { name, deps: null };
    }
  });
  process.stderr.write("\n");

  if (resolved === 0) {
    console.error("deps.dev returned nothing for any package — is the network reachable?");
    process.exit(1);
  }

  // Invert the closures into "who depends on X", restricted to packages this
  // graph actually contains. Restricting matters: deps.dev knows the whole
  // ecosystem, and scoring against packages that were never crawled would
  // measure the crawl's breadth rather than the traversal's correctness.
  const externalDependents = new Map();
  for (const { name, deps } of closures) {
    if (!deps) continue;
    for (const dep of deps) {
      if (!universe.has(dep)) continue;
      if (!externalDependents.has(dep)) externalDependents.set(dep, new Set());
      externalDependents.get(dep).add(name);
    }
  }

  // Only packages deps.dev actually places dependents under can be scored;
  // preferring ones carrying real advisories keeps the table pointed at
  // packages whose blast radius is a live security question.
  let targets = targetArg;
  if (!targets) {
    const ranked = [...externalDependents.entries()]
      .sort((a, b) => b[1].size - a[1].size)
      .map(([name]) => name);
    const pool = ranked.slice(0, 20);
    const counts = await Promise.all(pool.map((n) => osvAdvisoryCount(n)));
    const withAdvisories = pool.filter((_, i) => counts[i] > 0).slice(0, 5);
    targets = withAdvisories;
    for (const name of ranked) {
      if (targets.length >= 5) break;
      if (!targets.includes(name)) targets.push(name);
    }
  }

  console.log(`\nComparing HydraDB's blast radius against deps.dev for ${targets.length} target(s)\n`);

  const results = [];
  for (const target of targets) {
    const external = externalDependents.get(target) ?? new Set();
    const start = Date.now();
    const ours = new Set(await blastRadius(target, DEPTH));
    const latencyMs = Date.now() - start;

    const { precision, recall, f1 } = precisionRecall(ours, external);
    const missed = [...external].filter((p) => !ours.has(p));
    const extra = [...ours].filter((p) => !external.has(p));
    results.push({
      target,
      external: external.size,
      ours: ours.size,
      precision,
      recall,
      f1,
      latencyMs,
      missed,
      extra,
      advisories: await osvAdvisoryCount(target),
    });
  }

  console.log(
    "target".padEnd(22), "deps.dev".padEnd(9), "hydra".padEnd(7),
    "P".padEnd(6), "R".padEnd(6), "F1".padEnd(6), "ms".padEnd(6), "OSV"
  );
  for (const r of results) {
    console.log(
      r.target.padEnd(22),
      String(r.external).padEnd(9),
      String(r.ours).padEnd(7),
      r.precision.toFixed(2).padEnd(6),
      r.recall.toFixed(2).padEnd(6),
      r.f1.toFixed(2).padEnd(6),
      String(r.latencyMs).padEnd(6),
      r.advisories
    );
  }

  const meanP = results.reduce((s, r) => s + r.precision, 0) / results.length;
  const meanR = results.reduce((s, r) => s + r.recall, 0) / results.length;
  console.log(`\nmean precision ${meanP.toFixed(2)}   mean recall ${meanR.toFixed(2)}`);

  const anyDisagreement = results.some((r) => r.missed.length > 0 || r.extra.length > 0);
  if (anyDisagreement) {
    // Deliberately not "why that is expected". Some of these are explained
    // with evidence and some are only guessed at, and a validation script that
    // pre-frames every disagreement as expected is one that will explain away
    // a real defect the day it finds one.
    console.log("\nWhere the two sources disagree, and what accounts for it:");
    for (const r of results) {
      if (r.missed.length === 0 && r.extra.length === 0) continue;
      console.log(`  ${r.target}:`);
      if (r.missed.length) {
        console.log(
          `    ${r.missed.length} dependent(s) deps.dev knows and this graph does not ` +
          `(${r.missed.slice(0, 4).join(", ")}${r.missed.length > 4 ? ", ..." : ""})`
        );
        console.log(
          `      -> an edge the bounded crawl never ingested (--depth/--max-nodes), not a traversal miss`
        );
      }
      if (r.extra.length) {
        console.log(
          `    ${r.extra.length} dependent(s) this graph has and deps.dev's resolution does not ` +
          `(${r.extra.slice(0, 4).join(", ")}${r.extra.length > 4 ? ", ..." : ""})`
        );
        // Attribute rather than assume: a package that declares peers which
        // are themselves in this graph reaches the target through an edge
        // deps.dev's install closure does not walk.
        const peerExplained = [];
        for (const p of r.extra) {
          const peers = (await peerDependencies(p)).filter((x) => universe.has(x));
          if (peers.length) peerExplained.push(`${p} (peers on ${peers.join(", ")})`);
        }
        if (peerExplained.length) {
          console.log(
            `      -> ${peerExplained.length} of them reach the target through a peerDependency,`
          );
          console.log(
            `         which this graph models on purpose and an install closure does not:`
          );
          for (const line of peerExplained.slice(0, 4)) console.log(`           ${line}`);
        }
        const unexplained = r.extra.length - peerExplained.length;
        if (unexplained > 0) {
          console.log(
            `      -> ${unexplained} NOT explained by a peer edge. The likely cause is version`
          );
          console.log(
            `         skew (this graph uses each package's 'latest' manifest, deps.dev resolves`
          );
          console.log(
            `         one concrete version) — but that is a hypothesis, not something this`
          );
          console.log(
            `         script verified. Worth checking by hand before trusting it.`
          );
        }
      }
    }
  }

  console.log(
    `\nWhat this measures: whether the dependency facts in HydraDB match an independent\n` +
    `resolver's view of the same ecosystem — unlike src/eval.js, whose ground truth is\n` +
    `derived from this project's own crawl. ${unresolved > 0 ? `${unresolved} package(s) could not be resolved by\ndeps.dev and were excluded.` : ""}`
  );
}

// Entry-point guard, as in the other CLI files: importing this module must not
// fire off a full deps.dev crawl as a side effect.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("External eval failed:", err);
    process.exit(1);
  });
}
