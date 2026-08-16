// Flags package names in the ingested graph that are suspiciously close to
// a well-known popular package — the classic typosquat pattern (e.g.
// "reqeusts" instead of "requests"). Per the track brief: "are there likely
// typosquat packages nearby" is one of the questions a blast-radius tool
// should be able to answer about a compromised package's neighborhood.
//
// Usage: node src/typosquat.js [--max-distance=2]

import { pathToFileURL } from "node:url";
import { runQueryPagedKeyset, fetchWithTimeout } from "./hydra.js";

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
export function levenshtein(a, b) {
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
    // Bounded well under the frontend's own timeout: this runs once per
    // candidate and a stalled npm API must not be able to hang the whole
    // /api/typosquat response (the page calls it unconditionally on load).
    const res = await fetchWithTimeout(
      `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`,
      {},
      5_000
    );
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
// Absolute edit distance is close to meaningless on very short names: "ms"
// is one edit from "qs" and "acorn" is two from "cors", and neither pair has
// anything to do with impersonation — they are simply short. Both filters
// below exist to keep that noise out of the report, because a scanner that
// cries wolf on `ms` is one nobody reads.
const MIN_NAME_LENGTH = 4;
// Distance must also be small *relative* to the name, so one edit in a
// 2-character name is rejected while one edit in "express" is not. 0.34
// keeps the genuinely interesting cases (isarray/is-array at 0.14,
// reqeust/request at 0.29) and drops the short-name coincidences.
const MAX_DISTANCE_RATIO = 0.34;

export async function findTyposquats(candidateNames, maxDistance = 2) {
  const popularSet = new Set(POPULAR_PACKAGES);
  const suspects = [];

  for (const candidate of candidateNames) {
    if (popularSet.has(candidate)) continue;
    if (candidate.length < MIN_NAME_LENGTH) continue;
    let closest = null;
    let closestDistance = Infinity;
    for (const popular of POPULAR_PACKAGES) {
      if (popular.length < MIN_NAME_LENGTH) continue;
      // Skip pairs where length differs too much — cheap short-circuit
      // before paying for the full DP table.
      if (Math.abs(candidate.length - popular.length) > maxDistance) continue;
      const d = levenshtein(candidate, popular);
      if (d < closestDistance) {
        closestDistance = d;
        closest = popular;
      }
    }
    if (
      closest &&
      closestDistance > 0 &&
      closestDistance <= maxDistance &&
      closestDistance / Math.min(candidate.length, closest.length) <= MAX_DISTANCE_RATIO
    ) {
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

// Paged past HydraDB's undocumented 1024-row cap (see runQueryPagedKeyset in
// hydra.js). An unpaged scan here would silently truncate the package list —
// and with it the typosquat scan's coverage — on any graph past 1024
// packages, exactly the failure mode this project treats as unacceptable
// everywhere else. This used to be a plain runQuery, inconsistent with the
// paged version server.js uses for the same question.
async function allIngestedPackageNames() {
  const rows = await runQueryPagedKeyset(
    "MATCH (p:Package) {{SEEK}} RETURN DISTINCT p.name AS name ORDER BY name",
    "p.name",
    "name"
  );
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
