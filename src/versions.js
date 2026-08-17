// "Which version introduced the vulnerability?" — the version-level question
// the dependency graph alone cannot answer.
//
// The rest of this project models packages, not versions: enough to say "qs is
// exposed", never "qs 6.9.0 is exposed and 6.9.7 is not". This adds a
// (:Package)-[:HAS_VERSION]->(:Version) edge carrying each release's real
// publish date, then cross-references OSV's advisory ranges against the
// versions actually published to say which of them are inside an affected
// window and exactly where each window closes.
//
// A NOTE ON FRAMING, because the brief's wording invites a degenerate answer.
// "Which version introduced it" sounds like it wants one number, and for many
// advisories that number is trivially "the first version ever published" —
// OSV writes `introduced: "0"` when a bug predates all releases, which is the
// single most common case. Reporting "0.0.1 introduced it" over and over is
// technically true and useless. The question worth answering, and the one the
// data actually supports, is *which published versions fall inside an affected
// range, and where does the fix boundary sit* — so that is what this reports,
// with the literal introduced version alongside it when OSV names a real one.
// Measured on qs: of 7 advisories, 2 name a real introduced version and the
// rest start at 0, and one carries 9 separate affected windows.
//
// Usage: node src/versions.js <package-name> [--max-versions=500]

import { pathToFileURL } from "node:url";
import {
  runQuery,
  runQueryPagedKeyset,
  cypherString,
  packageId,
  versionId,
  fetchWithTimeout,
} from "./hydra.js";
import { mapWithConcurrency } from "./ingest.js";

const REGISTRY = process.env.NPM_REGISTRY ?? "https://registry.npmjs.org";
// Overridable for the same reason NPM_REGISTRY is: the "OSV could not be
// reached" path reports something quite different from "no advisories", and
// that distinction is only worth making if it can actually be exercised
// against a stub instead of by waiting for OSV to have a bad day.
const OSV_API = process.env.OSV_API ?? "https://api.osv.dev/v1/query";
const WRITE_CONCURRENCY = 16;

// Versions kept per package, newest first. The same bargain --max-nodes makes
// in crawl(): a cap that is announced is fine, a silent partial answer is not.
// Some npm packages carry well over a thousand releases, and every one is an
// HTTP round trip to write, so an uncapped ingest on a pathological package
// would stall a request the browser is waiting on.
const DEFAULT_MAX_VERSIONS = 500;

// Marks an error as coming from an upstream service rather than from HydraDB.
// server.js maps a bare "timed out" to "HydraDB isn't responding", which is
// the right message for every other endpoint in this project but actively
// misleading here: this module also talks to the npm registry and to OSV, and
// telling someone their database is down when npm is slow points them at the
// wrong thing at the worst moment. The tag travels with the error so the
// handler can name the service that actually failed.
function upstreamError(service, err) {
  const tagged = new Error(`${service} request failed: ${err.message}`);
  tagged.upstream = service;
  return tagged;
}

// Same URL-encoding rules as ingest.js's registryUrl — a dependency name is
// third-party data and must not be able to steer the fetch off the manifest
// endpoint — but without the /latest suffix. The full packument is the only
// form carrying the `time` map, which is where publish dates live.
function packumentUrl(name) {
  if (name.startsWith("@") && name.includes("/")) {
    const [scope, pkg] = name.split("/", 2);
    return `${REGISTRY}/${encodeURIComponent(scope)}%2f${encodeURIComponent(pkg)}`;
  }
  return `${REGISTRY}/${encodeURIComponent(name)}`;
}

const TRANSIENT_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const FETCH_ATTEMPTS = 3;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Retried on the same statuses ingest.js retries, and for the same reason: a
// rate limit that clears in a second should not cost the whole answer. A full
// packument is a much larger response than the /latest manifest (qs is ~360KB
// across 149 versions), so the timeout is correspondingly longer.
export async function fetchPackument(name) {
  let lastStatus = 0;
  for (let attempt = 1; attempt <= FETCH_ATTEMPTS; attempt++) {
    let res;
    try {
      res = await fetchWithTimeout(packumentUrl(name), {}, 20_000);
    } catch (err) {
      throw upstreamError("npm registry", err);
    }
    if (res.status === 404) return null; // unpublished or private: a real answer
    if (res.ok) {
      try {
        return res.json();
      } catch (err) {
        throw upstreamError("npm registry", new Error(`malformed packument: ${err.message}`));
      }
    }

    lastStatus = res.status;
    if (!TRANSIENT_STATUS.has(res.status) || attempt === FETCH_ATTEMPTS) break;
    const retryAfter = Number(res.headers?.get?.("retry-after"));
    const waitMs =
      Number.isFinite(retryAfter) && retryAfter > 0
        ? Math.min(retryAfter * 1000, 8000)
        : Math.min(300 * 2 ** (attempt - 1), 4000);
    await sleep(waitMs);
  }
  throw upstreamError(
    "npm registry",
    new Error(`returned ${lastStatus} after ${FETCH_ATTEMPTS} attempts`)
  );
}

// The packument's `time` map is version -> ISO8601 publish date, plus two
// non-version keys ("created"/"modified") that must not be mistaken for
// releases. Cross-checked against `versions` so a date left behind by an
// unpublished release does not become a phantom vertex.
export function extractVersionDates(packument) {
  const time = packument?.time ?? {};
  const published = packument?.versions ?? {};
  const out = [];
  for (const [version, publishedAt] of Object.entries(time)) {
    if (version === "created" || version === "modified") continue;
    if (!Object.hasOwn(published, version)) continue;
    out.push({ version, publishedAt });
  }
  return out;
}

// --- semver ------------------------------------------------------------
// Implemented here rather than pulled in, because this project ships zero
// third-party dependencies and CI fails if that stops being true.
//
// Deliberately strict about what it accepts and honest about what it does
// not: an unparseable version returns null rather than being coerced into
// something sortable. A version silently mis-ordered into or out of an
// affected range is exactly the kind of quiet wrongness this whole project
// treats as its one unacceptable failure, so the caller is made to decide
// what to do about it (analyzeVersions counts and reports them).
const SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseSemver(version) {
  if (typeof version !== "string") return null;
  const m = SEMVER_RE.exec(version.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    // Build metadata is dropped entirely: semver §10 says it is ignored when
    // determining precedence, so 1.0.0+a and 1.0.0+b are the same version.
    prerelease: m[4] === undefined ? null : m[4].split("."),
  };
}

// semver.org §11 precedence. Returns -1/0/1, or null if either side is not a
// version this can reason about.
export function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;

  for (const part of ["major", "minor", "patch"]) {
    if (pa[part] !== pb[part]) return pa[part] < pb[part] ? -1 : 1;
  }

  // A release outranks a prerelease of the same core version: 1.0.0-rc < 1.0.0.
  if (pa.prerelease === null && pb.prerelease === null) return 0;
  if (pa.prerelease === null) return 1;
  if (pb.prerelease === null) return -1;

  const len = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < len; i++) {
    const x = pa.prerelease[i];
    const y = pb.prerelease[i];
    // A larger set of identifiers wins when all preceding ones are equal.
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const nx = Number(x);
      const ny = Number(y);
      if (nx !== ny) return nx < ny ? -1 : 1;
    } else if (xNum !== yNum) {
      return xNum ? -1 : 1; // numeric identifiers rank below alphanumeric ones
    } else if (x !== y) {
      return x < y ? -1 : 1; // ASCII order
    }
  }
  return 0;
}

// --- OSV ranges --------------------------------------------------------

// OSV's own range semantics, not a single introduced..fixed window.
//
// A range is a *sequence of events* walked in order, each flipping a bit: an
// `introduced` at or below the version turns it on, a `fixed` at or below
// turns it off again, and the version is affected if the bit is still on at
// the end. That structure is what lets one advisory describe a bug fixed on
// several release lines independently, or reintroduced later — and collapsing
// it to "between the first introduced and the first fixed" would report whole
// release lines as safe when they are not. This is not hypothetical: qs's
// GHSA-hrpp-h998-j3pp carries nine separate windows (6.4.x, 6.5.x, 6.6.x and
// so on each patched on their own line), and a single-window reading marks
// most of them clean.
//
// A range with an `introduced` and no closing event means "still affected",
// which must resolve to affected rather than to "no information".
//
// `introduced: "0"` is the sentinel for "since the first release" and is
// treated as negative infinity rather than parsed. Parsing it as 0.0.0 would
// be wrong for any package whose earliest release is a prerelease, since
// 0.0.0-alpha sorts *below* 0.0.0 and would fall outside a range meant to
// cover everything.
//
// GIT-type ranges are skipped rather than guessed at: they express commit
// reachability, which no registry version comparator can decide. They are
// counted and returned so the caller can say the analysis was partial instead
// of quietly presenting it as complete.
export function isAffectedByRange(version, ranges) {
  let affected = false;
  let skippedGitRanges = 0;
  let undecidable = false;

  for (const range of ranges ?? []) {
    if (range?.type === "GIT") {
      skippedGitRanges++;
      continue;
    }
    if (range?.type && range.type !== "SEMVER" && range.type !== "ECOSYSTEM") {
      skippedGitRanges++;
      continue;
    }

    let inRange = false;
    for (const event of range?.events ?? []) {
      if (event.introduced !== undefined) {
        if (event.introduced === "0") {
          inRange = true;
        } else {
          const cmp = compareSemver(version, event.introduced);
          if (cmp === null) { undecidable = true; continue; }
          if (cmp >= 0) inRange = true;
        }
      } else if (event.fixed !== undefined) {
        const cmp = compareSemver(version, event.fixed);
        if (cmp === null) { undecidable = true; continue; }
        if (cmp >= 0) inRange = false;
      } else if (event.last_affected !== undefined) {
        const cmp = compareSemver(version, event.last_affected);
        if (cmp === null) { undecidable = true; continue; }
        if (cmp > 0) inRange = false;
      } else if (event.limit !== undefined) {
        const cmp = compareSemver(version, event.limit);
        if (cmp === null) { undecidable = true; continue; }
        if (cmp >= 0) inRange = false;
      }
    }
    if (inRange) affected = true;
  }

  return { affected, skippedGitRanges, undecidable };
}

// Every advisory OSV holds for this package, flattened to the shape the
// analysis needs.
//
// Failure here is NOT reported as "no advisories". typosquat.js can default a
// failed download lookup to zero because that number only feeds a ratio, but
// this call IS the finding: rendering "0 known vulnerabilities" because the
// network hiccupped tells a reader the package is clean when nothing was
// actually checked, which is the same under-reporting-reads-as-safety failure
// this project refuses everywhere else. The error is tagged and propagated so
// the caller can say "could not check" instead.
export async function fetchOsvAdvisories(packageName) {
  let res;
  try {
    res = await fetchWithTimeout(
      OSV_API,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" } }),
      },
      15_000
    );
  } catch (err) {
    throw upstreamError("OSV", err);
  }
  if (!res.ok) {
    throw upstreamError("OSV", new Error(`returned ${res.status}`));
  }

  let body;
  try {
    body = res.json();
  } catch (err) {
    throw upstreamError("OSV", new Error(`malformed response: ${err.message}`));
  }

  return (body.vulns ?? []).map((v) => ({
    id: v.id,
    summary: v.summary ?? "",
    aliases: v.aliases ?? [],
    // One advisory can carry several `affected` entries, each with its own
    // ranges — that is how OSV expresses a fix landing separately on multiple
    // release lines. They are flattened here because the affected-or-not
    // question is a union across all of them.
    ranges: (v.affected ?? [])
      .filter((a) => !a.package?.name || a.package.name === packageName)
      .flatMap((a) => a.ranges ?? []),
  }));
}

// --- graph -------------------------------------------------------------

// A LIMIT 1 probe rather than count(). Nothing in this engine's documented
// subset promises aggregation works, no other query in this project uses one,
// and the cost of finding out otherwise mid-demo is not worth the tidier
// query — every existence check here is a bare MATCH ... LIMIT for the same
// reason.
async function hasVersions(name) {
  const rows = await runQuery(
    `MATCH (p:Package {id: ${packageId(name)}})-[:HAS_VERSION]->(v:Version) RETURN v.version AS version LIMIT 1`
  );
  return rows.length > 0;
}

// Paged for the same reason every other read here is: a package with more
// than 1024 releases would otherwise come back silently truncated, and a
// truncated version list makes "the earliest affected version" a fiction.
// Seeks on the version string — it only has to be unique and stably ordered
// for paging to be correct; real semver ordering is applied client-side after.
//
// `historyTotal` comes back alongside each row because truncation has to
// survive the write. See writeVersions for why storing it per-vertex is the
// shape the engine allows.
export async function versionsForPackage(name) {
  const rows = await runQueryPagedKeyset(
    `MATCH (p:Package {id: ${packageId(name)}})-[:HAS_VERSION]->(v:Version) {{SEEK}} ` +
      `RETURN v.version AS version, v.publishedAt AS publishedAt, v.historyTotal AS historyTotal ORDER BY version`,
    "v.version",
    "version"
  );
  const versions = rows
    .filter((r) => r.version)
    .map((r) => ({ version: r.version, publishedAt: r.publishedAt ?? null }));
  // The largest value any stored vertex carries. They should all agree, but a
  // package re-ingested after publishing more releases will hold a mix, and
  // the newest number is the right one.
  const totals = rows.map((r) => Number(r.historyTotal)).filter((n) => Number.isFinite(n) && n > 0);
  return { versions, historyTotal: totals.length ? Math.max(...totals) : null };
}

// One MERGE per version, as one HTTP request each: the engine rejects
// UNWIND-batched MERGE and bare single-vertex MERGE, so a one-hop edge
// pattern with both endpoints' properties inline is the only shape that
// reliably writes a vertex here. Concurrency keeps that from being slow.
//
// `historyTotal` — how many versions the registry actually published, which
// may be more than the number being written — is stamped onto every vertex,
// and that redundancy is deliberate. Truncation has to be recoverable on a
// later read or it is not recoverable at all: the cap is applied at ingest
// time, so a warm read that only counts stored rows cannot tell "this package
// has 5 releases" from "this package has 35 and we kept 5", and would present
// an analysis over a partial history as complete. The natural place for the
// number is a property on the :Package vertex, but this engine cannot SET a
// property on an existing vertex from a MERGE, and MERGE cannot be followed
// by another clause — so the only field that reliably writes is one carried
// inline on a vertex already being created. It costs one integer per row.
export async function writeVersions(name, versions, historyTotal) {
  const pkgId = packageId(name);
  const pkgName = cypherString(name);
  const total = Number.isFinite(historyTotal) ? historyTotal : versions.length;
  let written = 0;
  let failed = 0;

  await mapWithConcurrency(versions, WRITE_CONCURRENCY, async (v) => {
    try {
      await runQuery(
        `MERGE (p:Package {id: ${pkgId}, name: ${pkgName}})-[:HAS_VERSION]->` +
          `(v:Version {id: ${versionId(name, v.version)}, package: ${pkgName}, ` +
          `version: ${cypherString(v.version)}, publishedAt: ${cypherString(v.publishedAt ?? "")}, ` +
          `historyTotal: ${total}})`
      );
      written++;
    } catch (err) {
      failed++;
      process.stderr.write(`\nfailed to write ${name}@${v.version}: ${err.message}\n`);
    }
  });

  return { written, failed };
}

// Whether a stored history is partial, derived from what was written rather
// than assumed from what came back.
//
// A stored history is not automatically a complete one: the cap is applied at
// ingest time, so a read that only counts the rows it got cannot tell "this
// package has 5 releases" from "this package has 35 and we kept 5". Getting
// that wrong scores an advisory against a partial history and reports fewer
// affected versions than there are — the one direction this project refuses to
// be wrong in. Measured before `historyTotal` was stored: `cookie` capped to 5
// of its 35 releases came back `truncated: false` and reported **0 of 5**
// affected for GHSA-pxg6-pf52-xh8x, which over the full history affects **25**.
//
// `historyTotal` is null only for vertices written before it was recorded;
// those are treated as complete, which is the pre-existing behaviour.
export function deriveTruncation(storedCount, historyTotal) {
  const total = Number.isFinite(historyTotal) && historyTotal > 0 ? historyTotal : storedCount;
  return { truncated: total > storedCount, totalKnown: total };
}

// Loads a package's version history into the graph if it is not already
// there. Returns the versions either way, so a cold call does not have to
// read back what it just wrote.
export async function ingestVersions(name, { maxVersions = DEFAULT_MAX_VERSIONS } = {}) {
  if (await hasVersions(name)) {
    const { versions, historyTotal } = await versionsForPackage(name);
    const { truncated, totalKnown } = deriveTruncation(versions.length, historyTotal);
    return { versions, ingested: false, truncated, writeFailures: 0, totalKnown };
  }

  const packument = await fetchPackument(name);
  if (!packument) {
    return { versions: [], ingested: false, truncated: false, writeFailures: 0, notPublished: true };
  }

  const all = extractVersionDates(packument);
  // Newest first, so a cap keeps the releases anyone is actually running.
  // ISO8601 sorts correctly as plain strings, so no date parsing is needed.
  all.sort((a, b) => (a.publishedAt < b.publishedAt ? 1 : a.publishedAt > b.publishedAt ? -1 : 0));
  const truncated = all.length > maxVersions;
  const kept = truncated ? all.slice(0, maxVersions) : all;

  const { failed } = await writeVersions(name, kept, all.length);
  return { versions: kept, ingested: true, truncated, writeFailures: failed, totalKnown: all.length };
}

// The whole question, answered: which published versions of this package sit
// inside a known advisory's affected range, and where does each range close.
export async function analyzeVersions(name, { maxVersions = DEFAULT_MAX_VERSIONS } = {}) {
  const ingestStart = Date.now();
  const ingest = await ingestVersions(name, { maxVersions });
  const ingestMs = Date.now() - ingestStart;

  const versions = ingest.versions;
  const parseable = versions.filter((v) => parseSemver(v.version) !== null);
  const nonSemverCount = versions.length - parseable.length;

  const osvStart = Date.now();
  let advisories = null;
  let osvUnavailable = null;
  try {
    advisories = await fetchOsvAdvisories(name);
  } catch (err) {
    // Explicitly NOT an empty advisory list — see fetchOsvAdvisories.
    osvUnavailable = err.message;
    advisories = [];
  }
  const osvMs = Date.now() - osvStart;

  const sorted = parseable
    .slice()
    .sort((a, b) => compareSemver(a.version, b.version) ?? 0);

  const analyzed = advisories.map((adv) => {
    let skippedGitRanges = 0;
    let undecidable = false;
    const affected = [];
    for (const v of sorted) {
      const r = isAffectedByRange(v.version, adv.ranges);
      skippedGitRanges = Math.max(skippedGitRanges, r.skippedGitRanges);
      // An unparseable boundary means a window could not be evaluated, and an
      // unevaluated window fails CLOSED — the version is reported unaffected.
      // That is under-reporting, so it has to be visible rather than inferred
      // from a suspiciously low count. Not observed on any of 416 real npm
      // advisory boundaries sampled, but the signal is computed either way and
      // dropping it is what would make it silent.
      if (r.undecidable) undecidable = true;
      if (r.affected) affected.push(v);
    }

    // The literal introduced boundaries OSV names, carried through rather
    // than collapsed into one number — an advisory with nine windows has nine
    // real answers to "where did this start", and picking one would be a
    // summary that hides the shape of the fix.
    const introducedVersions = [
      ...new Set(
        adv.ranges.flatMap((r) =>
          (r.events ?? []).filter((e) => e.introduced !== undefined).map((e) => e.introduced)
        )
      ),
    ];
    const fixedVersions = [
      ...new Set(
        adv.ranges.flatMap((r) =>
          (r.events ?? []).filter((e) => e.fixed !== undefined).map((e) => e.fixed)
        )
      ),
    ];

    return {
      id: adv.id,
      summary: adv.summary,
      aliases: adv.aliases,
      affectedCount: affected.length,
      // "Known" is load-bearing: these are the earliest/latest affected
      // versions among the ones in the graph, which is not the same as the
      // earliest ever published if the ingest was capped.
      earliestKnownAffected: affected[0]?.version ?? null,
      latestKnownAffected: affected[affected.length - 1]?.version ?? null,
      introducedVersions,
      fixedVersions,
      windowCount: adv.ranges.length,
      skippedGitRanges,
      undecidable,
    };
  });

  return {
    package: name,
    versionCount: versions.length,
    totalKnownVersions: ingest.totalKnown ?? versions.length,
    earliestVersion: sorted[0]?.version ?? null,
    latestVersion: sorted[sorted.length - 1]?.version ?? null,
    nonSemverCount,
    truncated: ingest.truncated,
    notPublished: ingest.notPublished ?? false,
    ingested: ingest.ingested,
    writeFailures: ingest.writeFailures,
    osvUnavailable,
    advisories: analyzed,
    ingestMs,
    osvMs,
  };
}

function parseArgs(argv) {
  const [name, ...rest] = argv;
  if (!name) {
    console.error("Usage: node src/versions.js <package-name> [--max-versions=500]");
    process.exit(1);
  }
  let maxVersions = DEFAULT_MAX_VERSIONS;
  for (const arg of rest) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "max-versions") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) {
        console.error(`--max-versions must be a positive integer, got "${value}"`);
        process.exit(1);
      }
      maxVersions = n;
    }
  }
  return { name, maxVersions };
}

async function main() {
  const { name, maxVersions } = parseArgs(process.argv.slice(2));

  console.log(`Loading version history for "${name}"...`);
  const r = await analyzeVersions(name, { maxVersions });

  if (r.notPublished) {
    console.log(`"${name}" is not published on the npm registry (404).`);
    return;
  }
  if (r.versionCount === 0) {
    console.log(`No versions found for "${name}".`);
    return;
  }

  console.log(
    `${r.versionCount} version(s) in the graph` +
      (r.ingested ? " (just ingested)" : " (already ingested)") +
      `, ${r.earliestVersion} -> ${r.latestVersion}, in ${r.ingestMs}ms`
  );
  if (r.truncated) {
    console.log(
      `NOTE: the graph holds ${r.versionCount} of ${r.totalKnownVersions} published version(s), newest first.\n` +
        `      Every count below is over that subset — "earliest affected" is the earliest among\n` +
        `      these, not ever, and older affected releases may exist outside them.` +
        (r.ingested ? `\n      Raise --max-versions (currently ${maxVersions}) for full coverage.` : "")
    );
  }
  if (r.nonSemverCount > 0) {
    console.log(`NOTE: ${r.nonSemverCount} version string(s) are not valid semver and were excluded from range analysis.`);
  }
  if (r.writeFailures > 0) {
    console.log(`NOTE: ${r.writeFailures} version write(s) failed; the history is incomplete.`);
  }

  if (r.osvUnavailable) {
    console.error(
      `\nERROR: could not reach OSV (${r.osvUnavailable}).\n` +
        `       This is NOT the same as "no known vulnerabilities" — nothing was checked.`
    );
    process.exitCode = 1;
    return;
  }

  if (r.advisories.length === 0) {
    console.log(`\nOSV reports no known advisories for "${name}".`);
    return;
  }

  console.log(`\n${r.advisories.length} advisory(ies) from OSV, checked in ${r.osvMs}ms:\n`);
  for (const a of r.advisories) {
    const alias = a.aliases.length ? ` (${a.aliases.join(", ")})` : "";
    console.log(`  ${a.id}${alias}`);
    if (a.summary) console.log(`    ${a.summary.slice(0, 96)}`);
    console.log(
      `    ${a.affectedCount} of ${r.versionCount} known version(s) affected` +
        (a.affectedCount > 0 ? `: ${a.earliestKnownAffected} -> ${a.latestKnownAffected}` : "")
    );
    const introduced = a.introducedVersions
      .map((v) => (v === "0" ? "0 (all earlier releases)" : v))
      .join(", ");
    console.log(`    introduced at: ${introduced || "unstated"}`);
    console.log(`    fixed in: ${a.fixedVersions.join(", ") || "no fix published"}`);
    if (a.windowCount > 1) {
      console.log(`    ${a.windowCount} separate affected windows (fixed on multiple release lines)`);
    }
    if (a.skippedGitRanges > 0) {
      console.log(`    NOTE: ${a.skippedGitRanges} GIT-type range(s) skipped — not decidable by version`);
    }
    if (a.undecidable) {
      console.log(
        `    WARNING: this advisory has a version boundary that could not be parsed, so some\n` +
          `             windows went unevaluated. The count above is a LOWER BOUND.`
      );
    }
    console.log("");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Version analysis failed:", err);
    process.exit(1);
  });
}
