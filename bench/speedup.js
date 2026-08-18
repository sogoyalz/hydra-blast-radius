// Reproduces the speedup table in the README.
//
// It exists because that table used to quote a single run as though it were
// reproducible, and it was not: the same target measured 4.9x and 12.7x on
// different passes of this very loop against the same graph. A number nobody
// can re-derive is a claim, not a measurement, so the measurement ships.
//
// What it compares, per target:
//   * blastRadiusNative  — one algo.SSpaths call
//   * blastRadiusFanout  — the portable variable-length traversal, which needs
//                          one query per hop probe plus one per node for edges
//
// It reports the median and the full observed range, and it verifies the two
// engines agree exactly — identical node sets, edge sets and hop distances.
// That agreement is the part that matters: the speedup is a nice-to-have, the
// equivalence is what makes the fallback trustworthy.
//
// Usage: node bench/speedup.js [--trials=7] [--targets=a,b,c]
//        (requires a running HydraDB with the demo graph — ./setup.sh)

import { blastRadiusNative, blastRadiusFanout } from "../src/blastRadius.js";

function parseArgs(argv) {
  const opts = { trials: 7, targets: ["debug", "qs", "send", "body-parser"] };
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "trials") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--trials must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      opts.trials = n;
    }
    if (key === "targets") {
      opts.targets = value.split(",").map((s) => s.trim()).filter(Boolean);
      if (opts.targets.length === 0) {
        console.error("--targets needs at least one package name");
        process.exit(1);
      }
    }
  }
  return opts;
}

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
};

// Same node/edge/hop comparison the README's "identical" claim rests on.
function sameAnswer(a, b) {
  const nodes = (r) => new Set(r.nodes.map((n) => `${n.name}@${n.hop}`));
  const edges = (r) => new Set(r.edges.map((e) => `${e.from}>${e.to}`));
  const eq = (x, y) => x.size === y.size && [...x].every((v) => y.has(v));
  return eq(nodes(a), nodes(b)) && eq(edges(a), edges(b));
}

async function main() {
  const { trials, targets } = parseArgs(process.argv.slice(2));

  // Warm the connection so the first target does not absorb setup cost and
  // report a flattering ratio.
  await blastRadiusNative(targets[0], 6).catch(() => {});

  const results = new Map(targets.map((t) => [t, { nat: [], fan: [], ratio: [], agree: true, q: null }]));

  for (let i = 0; i < trials; i++) {
    for (const t of targets) {
      const r = results.get(t);

      let s = Date.now();
      const nat = await blastRadiusNative(t, 6);
      const natMs = Date.now() - s;

      s = Date.now();
      const fan = await blastRadiusFanout(t, 6);
      const fanMs = Date.now() - s;

      if (!sameAnswer(nat, fan)) r.agree = false;
      r.q = { native: nat.queryCount, fanout: fan.queryCount };
      r.nat.push(natMs);
      r.fan.push(fanMs);
      // Guard the divisor: a sub-millisecond traversal would otherwise report
      // an infinite speedup, which is exactly the kind of number this file
      // exists to stop printing.
      r.ratio.push(fanMs / Math.max(natMs, 1));
    }
  }

  console.log(`\nMedian of ${trials} trials per target, 120-package demo graph.\n`);
  console.log("target         queries      native   fanout   median    range           identical");
  for (const t of targets) {
    const r = results.get(t);
    console.log(
      t.padEnd(15) +
        `${r.q.native} vs ${r.q.fanout}`.padEnd(13) +
        `${median(r.nat)}ms`.padEnd(9) +
        `${median(r.fan)}ms`.padEnd(9) +
        `${median(r.ratio).toFixed(1)}x`.padEnd(10) +
        `${Math.min(...r.ratio).toFixed(1)}x-${Math.max(...r.ratio).toFixed(1)}x`.padEnd(16) +
        (r.agree ? "yes" : "NO — ENGINES DISAGREE")
    );
  }

  const allRatios = targets.flatMap((t) => results.get(t).ratio);
  console.log(
    `\nAcross every trial: ${Math.min(...allRatios).toFixed(1)}x - ${Math.max(...allRatios).toFixed(1)}x.`
  );
  console.log(
    "The query-count column is the durable claim — it is structural and identical every run.\n" +
      "The latency ratio moves with machine load; quote the median and the range, never one run."
  );

  // Disagreement between the engines is a correctness failure, not a slow
  // benchmark: the fallback is only worth having if it answers the same thing.
  const disagreed = targets.filter((t) => !results.get(t).agree);
  if (disagreed.length > 0) {
    console.error(`\nFAIL: native and fallback returned different answers for ${disagreed.join(", ")}`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error("Benchmark failed:", err.message);
  console.error("A running HydraDB with the demo graph is required — see ./setup.sh");
  process.exit(1);
});
