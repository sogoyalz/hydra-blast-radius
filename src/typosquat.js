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

// Returns a real weekly download count, or null meaning "could not check".
//
// The distinction carries the whole weight of the verdict below, so it is not
// cosmetic. Returning 0 for a failed lookup used to collapse both halves of
// the ratio to zero, which produced a null ratio, which scored the candidate
// "likely coincidence" — so an npm downloads outage silently downgraded a
// genuine typosquat to background noise and the UI headlined "No likely
// typosquats." Measured directly against a stubbed 500 and a refused
// connection: `expres`/`express` went from "high" to "likely coincidence" in
// both. That is the same under-reporting-reads-as-safety failure this project
// refuses everywhere else, and it was hiding behind an argument that the
// number "only feeds a ratio".
//
// A 404 is deliberately NOT a failure: npm answers that way for a package it
// has no download record for, which is a real answer of zero and is the
// strongest signal a fresh squat can give. Only a transport error or a server
// error means "unknown".
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
    if (res.status === 404) return 0; // no download record — a real zero
    if (!res.ok) return null; // 5xx and friends — we do not know
    const body = await res.json();
    return body.downloads ?? 0;
  } catch {
    return null; // timeout, DNS, refused connection — we do not know
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
    // Either lookup failing means the confirming signal is missing, which is a
    // different thing from the signal saying "harmless" — and it must not be
    // allowed to read as the latter. The name is still suspiciously close to a
    // popular package; all that is unknown is whether download volume backs
    // that up. Reported as its own verdict so it stays visible instead of
    // being filed under coincidence.
    suspect.downloadsUnavailable = candidateDownloads === null || popularDownloads === null;
    suspect.candidateWeeklyDownloads = candidateDownloads;
    suspect.resemblesWeeklyDownloads = popularDownloads;

    if (suspect.downloadsUnavailable) {
      suspect.downloadRatio = null;
      suspect.suspicion = "unconfirmed";
      continue;
    }

    // A genuine zero on the popular side makes the comparison meaningless
    // rather than unknown: nothing is impersonating a package nobody installs.
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

  // "unconfirmed" ranks directly below "high" because that is the honest place
  // for it: it could have been a high and nothing ruled that out.
  const suspicionRank = { high: 0, unconfirmed: 1, medium: 2, low: 3, "likely coincidence": 4 };
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
    // Validated for the same reason ingest.js validates its caps, and the
    // consequence here is worse than an error would be. Number("abc") is NaN,
    // and every comparison against NaN is false — so `distance <= maxDistance`
    // never matches, every candidate is discarded, and the scan prints "No
    // typosquat candidates found" over a graph that contains a real one.
    // Measured: `--max-distance=abc` silently suppressed the genuine
    // `expres`/`express` detection the demo graph exists to surface. A typo
    // must not be able to turn a security scanner into a clean bill of health.
    if (key === "max-distance") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--max-distance must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      maxDistance = n;
    }
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
    if (s.downloadsUnavailable) {
      console.log(
        `  [UNCONFIRMED] "${s.candidate}" (distance ${s.distance} from "${s.resembles}") — the npm\n` +
          `                downloads API could not be reached, so this was NOT cleared. The name is\n` +
          `                close to a popular package and nothing checked whether volume backs it up.`
      );
      continue;
    }
    const ratioText =
      s.downloadRatio === null
        ? "n/a"
        : `${(s.downloadRatio * 100).toFixed(3)}% of "${s.resembles}"'s downloads`;
    console.log(
      `  [${s.suspicion.toUpperCase()}] "${s.candidate}" (distance ${s.distance} from "${s.resembles}") — ${s.candidateWeeklyDownloads} weekly downloads vs ${s.resemblesWeeklyDownloads} for "${s.resembles}" (${ratioText})`
    );
  }

  // A scan that could not confirm anything must not end on a reassuring note.
  const unconfirmed = suspects.filter((s) => s.downloadsUnavailable).length;
  if (unconfirmed > 0) {
    console.log(
      `\nNOTE: ${unconfirmed} candidate(s) could not be checked against download volume because the\n` +
        `      npm downloads API did not answer. They are unresolved, not cleared — re-run to confirm.`
    );
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Typosquat scan failed:", err);
    process.exit(1);
  });
}
