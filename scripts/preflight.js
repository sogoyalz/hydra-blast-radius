// One command that answers "is the demo safe to show right now".
//
// It exists because the answer changed silently. The stack was healthy when
// last checked and dead the next morning — HTTP still listening, container
// still "Up", but Colima's virtiofs mount had degraded underneath it, so the
// database could not read its own store. Nothing surfaced that until a query
// was attempted. Remembering to run the right curl and interpret the output is
// exactly the sort of step that gets skipped when you are about to record.
//
// Checks, in the order they can fail:
//   1. the database is reachable and ready
//   2. it can READ  — the whole demo is reads
//   3. it can WRITE — version history is ingested on demand, and a wedged
//      write path is invisible until someone clicks a package
//   4. the graph holds what the README claims
//   5. version history is warm for everything the demo touches, so no click
//      costs seconds on camera (webpack cold is ~8s, warm ~40ms)
//
// Warms anything cold rather than only complaining about it, so a green run
// leaves the demo actually ready rather than merely audited.
//
// Usage: node scripts/preflight.js [--base=http://127.0.0.1:8787] [--no-warm]

import { runQuery, packageId, versionId } from "../src/hydra.js";

const DEMO_PACKAGES = ["qs", "express", "body-parser", "debug", "send", "cookie", "serve-static", "webpack"];

// The figures the README leads with. If these drift, the demo contradicts the
// document a judge is reading beside it.
const EXPECTED = {
  packages: 120,
  "body-parser": { total: 36, dep: 0, cred: 35, both: 1 },
  qs: { total: 10, dep: 2, cred: 8, both: 0 },
  debug: { total: 7, dep: 6, cred: 1, both: 0 },
};

function parseArgs(argv) {
  const opts = { base: "http://127.0.0.1:8787", warm: true };
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "no-warm") opts.warm = false;
    if (key === "base") {
      if (!value || !/^https?:\/\//.test(value)) {
        console.error(`--base must be an http(s) URL, got "${value}"`);
        process.exit(1);
      }
      opts.base = value.replace(/\/$/, "");
    }
  }
  return opts;
}

const problems = [];
const ok = (m) => console.log(`  ok    ${m}`);
const bad = (m, remedy) => {
  console.log(`  FAIL  ${m}`);
  problems.push({ m, remedy });
};

async function getJson(url, timeoutMs = 30_000) {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}

const RESTART = "colima restart  (or restart Docker Desktop), then ./setup.sh --fresh";

async function main() {
  const { base, warm } = parseArgs(process.argv.slice(2));
  console.log(`\nPreflight against ${base}\n`);

  // 1 + 2. reachable, and can read
  let canRead = false;
  try {
    const rows = await runQuery("MATCH (p:Package) RETURN p.name AS n LIMIT 1");
    if (rows.length === 0) bad("database answered but the graph is empty", "./setup.sh --fresh");
    else { ok("database reachable and reading"); canRead = true; }
  } catch (err) {
    // The failure that started all this looks exactly like a timeout here.
    bad(`database read failed — ${err.message.slice(0, 90)}`, RESTART);
  }

  // 3. can write. Reads working proves nothing about this, and version
  //    ingestion is the one write path a viewer can trigger.
  if (canRead) {
    const probe = "__preflight_probe";
    try {
      await runQuery(
        `MERGE (p:Package {id: ${packageId(probe)}, name: '${probe}'})-[:HAS_VERSION]->` +
          `(v:Version {id: ${versionId(probe, "1.0.0")}, package: '${probe}', version: '1.0.0', publishedAt: 'x', historyTotal: 1})`
      );
      await runQuery(`MATCH (v:Version {id: ${versionId(probe, "1.0.0")}}) DETACH DELETE v`);
      await runQuery(`MATCH (p:Package {id: ${packageId(probe)}}) DETACH DELETE p`);
      ok("database accepting writes");
    } catch (err) {
      bad(`database refuses writes — ${err.message.slice(0, 90)}`, RESTART);
    }
  }

  // 4. the server is up and the graph matches the README
  let serverUp = false;
  try {
    const { names } = await getJson(`${base}/api/packages`, 15_000);
    serverUp = true;
    if (names.length === EXPECTED.packages) ok(`${names.length} packages ingested`);
    else bad(`${names.length} packages, README says ${EXPECTED.packages}`, "./setup.sh --fresh");
  } catch (err) {
    bad(`demo server not answering — ${err.message.slice(0, 80)}`, "./setup.sh");
  }

  if (serverUp) {
    for (const [name, want] of Object.entries(EXPECTED)) {
      if (name === "packages") continue;
      try {
        const r = await getJson(`${base}/api/blast-radius?name=${encodeURIComponent(name)}&depth=6`);
        const u = r.unifiedExposure;
        const got = `${u.total} (${u.viaDependencyOnly}/${u.viaMaintainerOnly}/${u.viaBoth})`;
        const expect = `${want.total} (${want.dep}/${want.cred}/${want.both})`;
        if (got === expect) ok(`${name} = ${got}, via ${r.engine}`);
        else bad(`${name} = ${got}, README says ${expect}`, "./setup.sh --fresh");
      } catch (err) {
        bad(`${name} blast radius failed — ${err.message.slice(0, 70)}`, RESTART);
      }
    }

    // 5. warm the on-demand path so nothing costs seconds on camera
    if (warm) {
      let warmed = 0;
      let slow = 0;
      for (const name of DEMO_PACKAGES) {
        try {
          const s = Date.now();
          const r = await getJson(`${base}/api/versions?name=${encodeURIComponent(name)}`, 120_000);
          const ms = Date.now() - s;
          if (r.writesAborted) { bad(`${name}: writes aborted mid-ingest`, RESTART); continue; }
          if (ms > 500) slow++;
          warmed++;
        } catch (err) {
          bad(`${name} version history failed — ${err.message.slice(0, 70)}`, RESTART);
        }
      }
      if (warmed === DEMO_PACKAGES.length) {
        ok(`version history warm for all ${warmed} demo packages${slow ? ` (${slow} were cold and are now warmed)` : ""}`);
      }
    }
  }

  console.log("");
  if (problems.length === 0) {
    console.log("READY — the demo is safe to show.\n");
    return;
  }
  console.log(`NOT READY — ${problems.length} problem(s):\n`);
  for (const p of problems) console.log(`  - ${p.m}\n    fix: ${p.remedy}`);
  console.log("");
  process.exitCode = 1;
}

main().catch((err) => {
  console.error("\nPreflight itself failed:", err.message);
  console.error("That usually means the database is unreachable — " + RESTART + "\n");
  process.exit(1);
});
