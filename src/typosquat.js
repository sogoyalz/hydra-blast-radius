// Flags package names in the ingested graph that are suspiciously close to
// a well-known popular package — the classic typosquat pattern (e.g.
// "reqeusts" instead of "requests"). Per the track brief: "are there likely
// typosquat packages nearby" is one of the questions a blast-radius tool
// should be able to answer about a compromised package's neighborhood.
//
// Usage: node src/typosquat.js [--max-distance=2]

import { pathToFileURL } from "node:url";
import { runQuery } from "./hydra.js";

// A static, defensible "popular package" reference set rather than a live
// popularity API call per candidate (faster, no rate limits, no flakiness
// mid-demo). Anything this close in edit distance to one of these, while
// not being an exact match itself, is worth a human look.
const POPULAR_PACKAGES = [
  "react", "react-dom", "vue", "angular", "lodash", "underscore", "express",
  "koa", "fastify", "axios", "request", "node-fetch", "chalk", "commander",
  "yargs", "inquirer", "webpack", "babel-core", "@babel/core", "typescript",
  "eslint", "prettier", "jest", "mocha", "chai", "moment", "dayjs",
  "uuid", "dotenv", "cors", "body-parser", "morgan", "helmet", "jsonwebtoken",
  "bcrypt", "mongoose", "sequelize", "pg", "mysql", "redis", "socket.io",
  "lodash.merge", "async", "rxjs", "immutable", "classnames", "styled-components",
  "next", "nuxt", "gatsby", "webpack-cli", "rollup", "vite", "esbuild",
  "semver", "glob", "minimatch", "rimraf", "mkdirp", "fs-extra", "chokidar",
  "debug", "colors", "figlet", "ora", "cli-progress", "nodemon", "pm2",
  "left-pad", "is-number", "is-array", "is-odd", "is-even", "kind-of",
  "qs", "cookie", "cookies", "content-type", "accepts", "type-is",
  "multer", "passport", "passport-local", "connect", "compression",
  "winston", "pino", "bunyan", "joi", "yup", "ajv", "zod",
  "graphql", "apollo-server", "prisma", "typeorm", "knex",
  "puppeteer", "playwright", "cypress", "selenium-webdriver",
  "lru-cache", "node-cache", "ioredis", "bull", "agenda",
];

// Classic edit distance (Levenshtein). Small inputs (package names), so the
// naive O(n*m) DP table is plenty fast.
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

async function fetchWeeklyDownloads(name) {
  try {
    const res = await fetch(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`);
    if (!res.ok) return 0;
    const body = await res.json();
    return body.downloads ?? 0;
  } catch {
    return 0;
  }
}

// Returns candidates whose name is within `maxDistance` edits of a popular
// package (and isn't the popular package itself), ranked by how suspicious
// they look: close in spelling AND far lower in download volume than the
// package they resemble.
export async function findTyposquats(candidateNames, maxDistance = 2) {
  const popularSet = new Set(POPULAR_PACKAGES);
  const suspects = [];

  for (const candidate of candidateNames) {
    if (popularSet.has(candidate)) continue;
    let closest = null;
    let closestDistance = Infinity;
    for (const popular of POPULAR_PACKAGES) {
      // Skip pairs where length differs too much — cheap short-circuit
      // before paying for the full DP table.
      if (Math.abs(candidate.length - popular.length) > maxDistance) continue;
      const d = levenshtein(candidate, popular);
      if (d < closestDistance) {
        closestDistance = d;
        closest = popular;
      }
    }
    if (closest && closestDistance > 0 && closestDistance <= maxDistance) {
      suspects.push({ candidate, resembles: closest, distance: closestDistance });
    }
  }

  // Confirm with real download data: a genuine typosquat has far fewer
  // downloads than the package it's impersonating. Edit distance alone
  // produces false positives — e.g. "isarray" is a real, independently
  // popular package that happens to be one edit from "is-array"; it has
  // *more* downloads than "is-array", which the ratio correctly flags as
  // "not a typosquat" rather than a spelling coincidence.
  for (const suspect of suspects) {
    const [candidateDownloads, popularDownloads] = await Promise.all([
      fetchWeeklyDownloads(suspect.candidate),
      fetchWeeklyDownloads(suspect.resembles),
    ]);
    suspect.candidateWeeklyDownloads = candidateDownloads;
    suspect.resemblesWeeklyDownloads = popularDownloads;
    suspect.downloadRatio = popularDownloads === 0 ? null : candidateDownloads / popularDownloads;
    suspect.suspicion =
      suspect.downloadRatio === null || suspect.downloadRatio >= 1
        ? "likely coincidence"
        : suspect.downloadRatio < 0.01
          ? "high"
          : suspect.downloadRatio < 0.2
            ? "medium"
            : "low";
  }

  const suspicionRank = { high: 0, medium: 1, low: 2, "likely coincidence": 3 };
  return suspects.sort(
    (a, b) => suspicionRank[a.suspicion] - suspicionRank[b.suspicion] || a.distance - b.distance
  );
}

async function allIngestedPackageNames() {
  const rows = await runQuery("MATCH (p:Package) RETURN DISTINCT p.name AS name");
  return rows.map((r) => r.name).filter(Boolean);
}

function parseArgs(argv) {
  let maxDistance = 2;
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "max-distance") maxDistance = Number(value);
  }
  return { maxDistance };
}

async function main() {
  const { maxDistance } = parseArgs(process.argv.slice(2));
  console.log("Scanning ingested packages for typosquat candidates...");
  const names = await allIngestedPackageNames();
  console.log(`${names.length} packages in graph.`);

  const suspects = await findTyposquats(names, maxDistance);
  if (suspects.length === 0) {
    console.log("No typosquat candidates found.");
    return;
  }

  console.log(`\n${suspects.length} candidate(s) (edit distance <= ${maxDistance} from a popular package):\n`);
  for (const s of suspects) {
    const ratioText =
      s.downloadRatio === null
        ? "n/a"
        : `${(s.downloadRatio * 100).toFixed(3)}% of "${s.resembles}"'s downloads`;
    console.log(
      `  [${s.suspicion.toUpperCase()}] "${s.candidate}" (distance ${s.distance} from "${s.resembles}") — ${s.candidateWeeklyDownloads} weekly downloads vs ${s.resemblesWeeklyDownloads} for "${s.resembles}" (${ratioText})`
    );
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Typosquat scan failed:", err);
    process.exit(1);
  });
}
