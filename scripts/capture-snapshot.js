// Records the demo's real API responses into frontend/snapshot.json, so the
// UI can be explored from a static host with no Docker and no database.
//
// WHY THIS EXISTS, and the line it must not cross. The submission form asks
// for a deployed link, and hosting an alpha graph database publicly is not a
// thing to attempt the week of a deadline. A recorded snapshot gets a judge
// clicking through the real graph — real traces, real maintainer reach, real
// OSV advisories — in five seconds instead of five minutes.
//
// What it is NOT is a live database, and the page says so in a banner rather
// than letting anyone assume otherwise. Every number in here came out of an
// actual HydraDB traversal against the 120-package demo graph; none of it is
// synthesised, and none of it is presented as something it isn't. A project
// whose entire argument is "we never quietly report the wrong thing" cannot
// ship a fake live demo.
//
// Usage: node scripts/capture-snapshot.js [--base=http://127.0.0.1:8787]
//        (requires ./setup.sh running)

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { execSync } from "node:child_process";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const OUT = join(__dirname, "..", "frontend", "snapshot.json");

// Version history is ingested on demand, so a snapshot can only carry it for
// packages someone has asked about. These are the ones the README and the demo
// script actually point at, plus the deepest advisory cases.
const VERSION_PACKAGES = [
  "qs",
  "express",
  "body-parser",
  "debug",
  "send",
  "cookie",
  "serve-static",
  "webpack",
];

function parseArgs(argv) {
  let base = "http://127.0.0.1:8787";
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "base") {
      if (!value || !/^https?:\/\//.test(value)) {
        console.error(`--base must be an http(s) URL, got "${value}"`);
        process.exit(1);
      }
      base = value.replace(/\/$/, "");
    }
  }
  return { base };
}

async function get(base, path) {
  const res = await fetch(`${base}${path}`);
  const body = await res.json();
  if (!res.ok) throw new Error(`${path} -> ${res.status} ${JSON.stringify(body).slice(0, 120)}`);
  return body;
}

async function main() {
  const { base } = parseArgs(process.argv.slice(2));

  // Fail loudly and early rather than writing a half-empty snapshot that looks
  // fine until a judge clicks the one thing that is missing.
  let packages;
  try {
    packages = (await get(base, "/api/packages")).names;
  } catch (err) {
    console.error(`Could not reach the demo API at ${base} (${err.message}).`);
    console.error("Start it with ./setup.sh first — this records real responses, it cannot invent them.");
    process.exit(1);
  }
  if (!packages?.length) {
    console.error("The graph is empty; nothing to record. Run ./setup.sh.");
    process.exit(1);
  }
  console.log(`Recording ${packages.length} packages from ${base}...`);

  const snapshot = {
    capturedAt: new Date().toISOString(),
    commit: (() => {
      try {
        return execSync("git rev-parse --short HEAD", { encoding: "utf8" }).trim();
      } catch {
        return null;
      }
    })(),
    // Pinned so the UI can say what it is holding rather than implying it can
    // answer anything.
    depth: 6,
    packages,
    blastRadius: {},
    versions: {},
    typosquat: null,
  };

  // The whole point is that every package in the dropdown actually works, so
  // every one gets recorded — a snapshot where most clicks dead-end is worse
  // than no snapshot.
  let done = 0;
  for (const name of packages) {
    snapshot.blastRadius[name] = await get(
      base,
      `/api/blast-radius?name=${encodeURIComponent(name)}&depth=${snapshot.depth}`
    );
    done++;
    process.stderr.write(`\r  blast radius ${done}/${packages.length}`);
  }
  process.stderr.write("\n");

  snapshot.typosquat = await get(base, "/api/typosquat");
  console.log(`  typosquat scan: ${snapshot.typosquat.suspects.length} suspect(s)`);

  for (const name of VERSION_PACKAGES) {
    if (!packages.includes(name)) continue;
    try {
      const v = await get(base, `/api/versions?name=${encodeURIComponent(name)}`);
      // A recorded "OSV was unreachable" is a useless artifact — it would show
      // a judge an error state as though it were the finding. Skip it and say
      // so, rather than baking a transient outage into the demo.
      if (v.osvUnavailable) {
        console.log(`  versions ${name}: SKIPPED (OSV was unreachable during capture)`);
        continue;
      }
      snapshot.versions[name] = v;
      console.log(`  versions ${name}: ${v.versionCount} version(s), ${v.advisories.length} advisory(ies)`);
    } catch (err) {
      console.log(`  versions ${name}: skipped (${err.message.slice(0, 60)})`);
    }
  }

  writeFileSync(OUT, JSON.stringify(snapshot));
  const kb = (JSON.stringify(snapshot).length / 1024).toFixed(0);
  console.log(`\nWrote ${OUT} (${kb} KB)`);
  console.log(
    `  ${Object.keys(snapshot.blastRadius).length} blast radii, ` +
      `${Object.keys(snapshot.versions).length} version histories, depth ${snapshot.depth}`
  );
}

main().catch((err) => {
  console.error("Snapshot capture failed:", err.message);
  process.exit(1);
});
