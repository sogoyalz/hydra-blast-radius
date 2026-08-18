// Regression tests, run with `npm test` (node:test — no dependency added).
//
// These are deliberately not coverage for its own sake. Every case below
// guards a decision that was made for a reason, or a bug that actually
// happened during this project and would be silent if it came back. Each test
// says which. Nothing here needs a running HydraDB or a network connection:
// the graph-dependent behaviour is covered by src/eval.js (round trip) and
// src/evalExternal.js (independent source).

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import { packageId, maintainerId, versionId, cypherString, fetchWithTimeout } from "../src/hydra.js";
import { levenshtein, findTyposquats } from "../src/typosquat.js";
import { groundTruthBlastRadius, precisionRecall } from "../src/eval.js";
import {
  parseSemver,
  compareSemver,
  isAffectedByRange,
  extractVersionDates,
  deriveTruncation,
} from "../src/versions.js";

describe("vertex ids", () => {
  // HydraDB keys vertices on the integer id ALONE — labels do not scope
  // identity and they accumulate. An un-namespaced hash therefore fuses a
  // maintainer with a package of the same name into one vertex holding both
  // sets of edges, which is not hypothetical: npm users routinely publish a
  // package under their own handle. This is the single most damaging silent
  // corruption available in this data model.
  test("a package and a maintainer of the same name never collide", () => {
    for (const name of ["ljharb", "sindresorhus", "dougwilson", "express"]) {
      assert.notEqual(packageId(name), maintainerId(name));
    }
  });

  // The third vertex type has to hold the same line as the second. A :Version
  // sharing an id with the :Package it belongs to would fuse them, which is
  // the same silent corruption maintainerId exists to prevent.
  test("a version never collides with its own package or a maintainer", () => {
    for (const name of ["qs", "express", "ljharb"]) {
      const ids = new Set([packageId(name), maintainerId(name), versionId(name, "1.0.0")]);
      assert.equal(ids.size, 3, `${name} fused two vertex types`);
    }
  });

  test("different versions of one package get different ids", () => {
    assert.notEqual(versionId("qs", "6.9.0"), versionId("qs", "6.9.7"));
  });

  // The separator between name and version has to be a character that cannot
  // appear in either half, or two different (package, version) pairs collapse
  // into one vertex. With a naive separator, package "a" at version "b 1.0"
  // and package "a b" at version "1.0" produce the same string.
  test("the name/version separator cannot be forged from either half", () => {
    assert.notEqual(versionId("a", "b 1.0"), versionId("a b", "1.0"));
  });

  test("ids are stable across calls", () => {
    assert.equal(packageId("express"), packageId("express"));
    assert.equal(maintainerId("ljharb"), maintainerId("ljharb"));
  });

  test("ids stay inside the JS safe-integer range", () => {
    // They are written straight into Cypher as integer literals, so a value
    // above 2^53 would serialise imprecisely and silently address the wrong
    // vertex.
    for (const name of ["a", "express", "@babel/preset-typescript", "x".repeat(200)]) {
      for (const id of [packageId(name), maintainerId(name)]) {
        assert.ok(Number.isSafeInteger(id), `${name} -> ${id}`);
        assert.ok(id >= 0);
      }
    }
  });

  test("distinct names get distinct ids across a realistic set", () => {
    const names = [
      "express", "expres", "body-parser", "qs", "ms", "debug", "@babel/core",
      "@babel/types", "is-array", "isarray", "side-channel", "side-channel-map",
    ];
    const ids = new Set(names.map(packageId));
    assert.equal(ids.size, names.length);
  });
});

describe("cypherString escaping", () => {
  // Package and maintainer names come from third-party manifests, and they are
  // interpolated into query text rather than bound (the HTTP API documents
  // only a bare query string). Escaping is therefore the boundary that keeps
  // an arbitrary registry name from terminating the literal.
  test("single quotes are escaped, not dropped", () => {
    assert.equal(cypherString("o'brien"), "'o\\'brien'");
  });

  test("backslashes are escaped before quotes so the escape cannot be broken out of", () => {
    // A trailing backslash would otherwise escape the closing quote.
    assert.equal(cypherString("back\\slash"), "'back\\\\slash'");
    assert.equal(cypherString("ends-with\\"), "'ends-with\\\\'");
  });

  test("an injection attempt stays inside the literal", () => {
    const hostile = "x' }) MATCH (n) DETACH DELETE n //";
    const escaped = cypherString(hostile);
    // Every quote in the payload is neutralised, so the only unescaped quotes
    // are the delimiters this function added.
    const unescaped = [...escaped.matchAll(/(?<!\\)'/g)].length;
    assert.equal(unescaped, 2, `expected only the delimiters, got ${escaped}`);
  });

  test("non-strings are coerced rather than throwing", () => {
    assert.equal(cypherString(42), "'42'");
  });
});

describe("fetchWithTimeout", () => {
  // Both halves of a real bug. A wedged HydraDB accepts the connection and
  // never answers, which hung every endpoint forever with no error. The first
  // fix cleared its timer once headers arrived, which left a body that stalls
  // mid-stream just as unbounded — the same hang one step later.
  test("aborts when the server never responds at all", async () => {
    const server = createServer(() => { /* never respond */ });
    await new Promise((r) => server.listen(0, r));
    const port = server.address().port;
    try {
      const start = Date.now();
      await assert.rejects(
        () => fetchWithTimeout(`http://127.0.0.1:${port}/`, {}, 300),
        /timed out/
      );
      assert.ok(Date.now() - start < 3000, "should abort on the clock, not hang");
    } finally {
      server.close();
    }
  });

  test("aborts when headers arrive but the body stalls", async () => {
    const server = createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"rows":['); // partial body, never ended
    });
    await new Promise((r) => server.listen(0, r));
    const port = server.address().port;
    try {
      const start = Date.now();
      await assert.rejects(
        () => fetchWithTimeout(`http://127.0.0.1:${port}/`, {}, 300),
        /timed out/
      );
      assert.ok(Date.now() - start < 3000, "body read must be inside the guarded window");
    } finally {
      server.close();
    }
  });

  test("returns a body that parses, and reports non-ok status", async () => {
    const server = createServer((req, res) => {
      if (req.url === "/bad") {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end('{"error":"nope"}');
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"hello":"world"}');
    });
    await new Promise((r) => server.listen(0, r));
    const port = server.address().port;
    try {
      const ok = await fetchWithTimeout(`http://127.0.0.1:${port}/`, {}, 5000);
      assert.equal(ok.ok, true);
      assert.deepEqual(ok.json(), { hello: "world" });

      const bad = await fetchWithTimeout(`http://127.0.0.1:${port}/bad`, {}, 5000);
      assert.equal(bad.ok, false);
      assert.equal(bad.status, 503);
      assert.equal(bad.json().error, "nope");
    } finally {
      server.close();
    }
  });
});

describe("levenshtein", () => {
  test("known distances", () => {
    assert.equal(levenshtein("express", "express"), 0);
    assert.equal(levenshtein("expres", "express"), 1); // the real typosquat in the demo graph
    // Guards the documented example. `reqeust` (one trailing s) is distance 2
    // and is kept; `reqeusts` (two) is distance 3 and is rejected by both the
    // maxDistance and the ratio filter. The docs originally cited the latter
    // as a kept case — a typo in the example about typos.
    assert.equal(levenshtein("reqeust", "request"), 2);
    assert.equal(levenshtein("reqeusts", "request"), 3);
    assert.equal(levenshtein("", "abc"), 3);
    assert.equal(levenshtein("abc", ""), 3);
  });

  test("symmetric", () => {
    assert.equal(levenshtein("kitten", "sitting"), levenshtein("sitting", "kitten"));
  });

  test("the short-name pairs the ratio filter exists to reject are genuinely close", () => {
    // `ms`/`qs` and `acorn`/`cors` are 1 and 2 edits apart respectively, which
    // is why absolute distance alone cannot be the filter — they have nothing
    // to do with impersonation, they are just short.
    assert.equal(levenshtein("ms", "qs"), 1);
    assert.equal(levenshtein("acorn", "cors"), 2);
  });
});

describe("typosquat threshold handling", () => {
  // The CLI validates --max-distance now, but the reason is worth pinning at
  // the function boundary too: with NaN every `distance <= maxDistance` test is
  // false, so the scan discards every candidate and reports a clean graph.
  // Measured before the fix — `node src/typosquat.js --max-distance=abc`
  // printed "No typosquat candidates found" on the demo graph, silently
  // suppressing the real `expres`/`express` squat it exists to surface. A
  // security scanner must not be turnable into a clean bill of health by a typo.
  // Deliberately only the NaN case. It short-circuits before the
  // download-confirmation step, so it stays offline like the rest of this
  // suite; the matching positive case would fetch real download counts for
  // every suspect and put a live npm dependency into CI. That `expres` is
  // distance 1 from `express` is already pinned in the levenshtein block above.
  test("a NaN threshold discards every candidate — why the CLI rejects it", async () => {
    const found = await findTyposquats(["expres"], NaN);
    assert.equal(found.length, 0, "NaN silently matches nothing");
  });
});

describe("groundTruthBlastRadius", () => {
  // edges are {from: dependent, to: dependency}
  const edges = [
    { from: "express", to: "body-parser" },
    { from: "body-parser", to: "qs" },
    { from: "express", to: "qs" },
    { from: "unrelated", to: "lodash" },
  ];

  test("finds transitive dependents", () => {
    const r = groundTruthBlastRadius(edges, "qs", 6);
    assert.deepEqual([...r].sort(), ["body-parser", "express"]);
  });

  test("respects the depth bound", () => {
    // At depth 1 only the direct dependents of qs are reachable.
    const r = groundTruthBlastRadius(edges, "qs", 1);
    assert.deepEqual([...r].sort(), ["body-parser", "express"]);
    const deep = groundTruthBlastRadius(edges, "lodash", 1);
    assert.deepEqual([...deep], ["unrelated"]);
  });

  test("a package with no dependents has an empty radius", () => {
    assert.equal(groundTruthBlastRadius(edges, "express", 6).size, 0);
  });

  test("terminates on a dependency cycle", () => {
    // peerDependencies merged into DEPENDS_ON create these routinely, so a
    // naive walk here would not terminate.
    const cyclic = [
      { from: "a", to: "b" },
      { from: "b", to: "c" },
      { from: "c", to: "a" },
    ];
    const r = groundTruthBlastRadius(cyclic, "a", 6);
    assert.deepEqual([...r].sort(), ["a", "b", "c"]);
  });
});

describe("compareSemver", () => {
  // Version ordering decides which releases fall inside an advisory's affected
  // range. Getting it wrong does not throw — it silently moves the boundary,
  // reporting vulnerable versions as safe, which is the failure mode this
  // project treats as unacceptable everywhere else.
  test("orders by major, minor, then patch", () => {
    assert.equal(compareSemver("1.0.0", "1.0.1"), -1);
    assert.equal(compareSemver("1.1.0", "1.0.9"), 1);
    assert.equal(compareSemver("2.0.0", "1.9.9"), 1);
    assert.equal(compareSemver("1.0.0", "1.0.0"), 0);
  });

  test("a prerelease ranks below the release it leads to", () => {
    // semver §11: 1.0.0-alpha < 1.0.0. Getting this backwards would mark every
    // release candidate as safe from a bug its final release carries.
    assert.equal(compareSemver("1.0.0-alpha", "1.0.0"), -1);
    assert.equal(compareSemver("1.0.0", "1.0.0-alpha"), 1);
  });

  test("prerelease identifiers compare per semver precedence", () => {
    assert.equal(compareSemver("1.0.0-alpha", "1.0.0-beta"), -1);
    // Numeric identifiers compare numerically, NOT as strings — "9" vs "10"
    // is the case a lexical comparison gets wrong.
    assert.equal(compareSemver("1.0.0-alpha.9", "1.0.0-alpha.10"), -1);
    // Numeric identifiers rank below alphanumeric ones.
    assert.equal(compareSemver("1.0.0-1", "1.0.0-alpha"), -1);
    // More identifiers outrank fewer when all preceding ones are equal.
    assert.equal(compareSemver("1.0.0-alpha", "1.0.0-alpha.1"), -1);
  });

  test("build metadata is ignored for precedence", () => {
    // semver §10. Two builds of the same version are the same version.
    assert.equal(compareSemver("1.0.0+build1", "1.0.0+build2"), 0);
    assert.equal(compareSemver("1.0.0+build", "1.0.0"), 0);
  });

  test("unparseable versions return null rather than sorting wrongly", () => {
    // npm has published version strings that predate semver enforcement. The
    // caller counts and reports these; silently coercing them would put a
    // version on the wrong side of a range boundary.
    assert.equal(compareSemver("not-a-version", "1.0.0"), null);
    assert.equal(compareSemver("1.0", "1.0.0"), null);
    assert.equal(parseSemver("v1.0.0"), null);
    assert.equal(parseSemver(undefined), null);
  });
});

describe("isAffectedByRange", () => {
  const window = [{ type: "SEMVER", events: [{ introduced: "6.1.0" }, { fixed: "6.1.2" }] }];

  test("a range is inclusive of introduced and exclusive of fixed", () => {
    assert.equal(isAffectedByRange("6.0.9", window).affected, false);
    assert.equal(isAffectedByRange("6.1.0", window).affected, true);
    assert.equal(isAffectedByRange("6.1.1", window).affected, true);
    assert.equal(isAffectedByRange("6.1.2", window).affected, false);
  });

  // The case a naive "first introduced .. first fixed" reading gets wrong.
  // Real advisories carry one window per release line — qs's GHSA-hrpp-h998-j3pp
  // has nine — and collapsing them reports whole maintained lines as safe.
  test("multiple windows are independent, and the gap between them is safe", () => {
    const multi = [
      { type: "SEMVER", events: [{ introduced: "6.4.0" }, { fixed: "6.4.1" }] },
      { type: "SEMVER", events: [{ introduced: "6.9.0" }, { fixed: "6.9.7" }] },
    ];
    assert.equal(isAffectedByRange("6.4.0", multi).affected, true);
    assert.equal(isAffectedByRange("6.9.3", multi).affected, true);
    assert.equal(isAffectedByRange("6.6.0", multi).affected, false);
  });

  test("introduced '0' covers everything, including prereleases below 0.0.0", () => {
    // "0" is OSV's sentinel for "since the first release". Parsing it as the
    // literal version 0.0.0 would exclude 0.0.0-alpha, which sorts below it.
    const fromZero = [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }];
    assert.equal(isAffectedByRange("0.0.1", fromZero).affected, true);
    assert.equal(isAffectedByRange("0.0.0-alpha", fromZero).affected, true);
    assert.equal(isAffectedByRange("1.0.0", fromZero).affected, false);
  });

  test("a range with no fix is still affected, not unknown", () => {
    const open = [{ type: "SEMVER", events: [{ introduced: "2.0.0" }] }];
    assert.equal(isAffectedByRange("9.9.9", open).affected, true);
    assert.equal(isAffectedByRange("1.0.0", open).affected, false);
  });

  test("last_affected closes a range inclusively, unlike fixed", () => {
    const last = [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { last_affected: "2.0.0" }] }];
    assert.equal(isAffectedByRange("2.0.0", last).affected, true);
    assert.equal(isAffectedByRange("2.0.1", last).affected, false);
  });

  test("GIT ranges are skipped and counted, never guessed at", () => {
    // Commit reachability cannot be decided by comparing version numbers.
    // Reporting "not affected" would be an answer this cannot support.
    const git = [{ type: "GIT", events: [{ introduced: "abc123" }] }];
    const r = isAffectedByRange("1.0.0", git);
    assert.equal(r.affected, false);
    assert.equal(r.skippedGitRanges, 1);
  });

  // An unparseable boundary cannot open or close a window, so the version
  // falls through as unaffected — the analysis fails CLOSED, which
  // under-reports. That is survivable only because it is reported: the flag is
  // what turns a wrong number into a stated lower bound. It was computed and
  // then dropped by every caller until this test existed.
  test("an unparseable boundary is flagged, not silently treated as safe", () => {
    const bad = [{ type: "ECOSYSTEM", events: [{ introduced: "1.0" }, { fixed: "2.0" }] }];
    const r = isAffectedByRange("1.5.0", bad);
    assert.equal(r.affected, false, "an unevaluated window fails closed");
    assert.equal(r.undecidable, true, "and must say so, or the low count looks authoritative");
  });

  test("a decidable range reports nothing undecidable", () => {
    const good = [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }];
    assert.equal(isAffectedByRange("1.5.0", good).undecidable, false);
  });
});

describe("deriveTruncation", () => {
  // The bug this exists to prevent, exactly: `cookie` was ingested capped at 5
  // of its 35 releases, and every later read reported truncated:false and
  // scored GHSA-pxg6-pf52-xh8x as "0 of 5 affected". Over the full history it
  // affects 25. A partial history presented as complete turns a real finding
  // into a clean bill of health.
  test("a stored history smaller than the real total is truncated", () => {
    assert.deepEqual(deriveTruncation(5, 35), { truncated: true, totalKnown: 35 });
  });

  test("a complete history is not flagged", () => {
    assert.deepEqual(deriveTruncation(35, 35), { truncated: false, totalKnown: 35 });
  });

  test("a missing total falls back to the stored count rather than warning falsely", () => {
    // Vertices written before historyTotal was recorded carry no total. They
    // are treated as complete, which is the behaviour they already had.
    assert.deepEqual(deriveTruncation(12, null), { truncated: false, totalKnown: 12 });
    assert.deepEqual(deriveTruncation(12, undefined), { truncated: false, totalKnown: 12 });
    assert.deepEqual(deriveTruncation(12, 0), { truncated: false, totalKnown: 12 });
  });
});

describe("extractVersionDates", () => {
  test("skips the non-version keys in the registry's time map", () => {
    // `time` carries "created" and "modified" alongside real versions; both
    // would otherwise become phantom Version vertices.
    const out = extractVersionDates({
      time: { created: "2011-01-01", modified: "2026-01-01", "1.0.0": "2012-01-01" },
      versions: { "1.0.0": {} },
    });
    assert.deepEqual(out, [{ version: "1.0.0", publishedAt: "2012-01-01" }]);
  });

  test("drops versions that have a date but were unpublished", () => {
    // A date left behind by a removed release is not a version anyone can install.
    const out = extractVersionDates({ time: { "9.9.9": "2020-01-01" }, versions: {} });
    assert.deepEqual(out, []);
  });
});

describe("precisionRecall", () => {
  test("perfect agreement", () => {
    const r = precisionRecall(new Set(["a", "b"]), new Set(["a", "b"]));
    assert.equal(r.precision, 1);
    assert.equal(r.recall, 1);
    assert.equal(r.f1, 1);
  });

  test("a miss costs recall, an extra costs precision", () => {
    const missed = precisionRecall(new Set(["a"]), new Set(["a", "b"]));
    assert.equal(missed.recall, 0.5);
    assert.equal(missed.precision, 1);

    const extra = precisionRecall(new Set(["a", "b"]), new Set(["a"]));
    assert.equal(extra.precision, 0.5);
    assert.equal(extra.recall, 1);
  });

  test("empty sets do not produce NaN", () => {
    // Both defaults are 1 by convention here; the eval guards separately
    // against a vacuous all-empty run, which would otherwise 'pass' loudly.
    const r = precisionRecall(new Set(), new Set());
    assert.equal(r.precision, 1);
    assert.equal(r.recall, 1);
    assert.ok(!Number.isNaN(r.f1));
  });
});
