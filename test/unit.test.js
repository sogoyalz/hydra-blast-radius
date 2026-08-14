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

import { packageId, maintainerId, cypherString, fetchWithTimeout } from "../src/hydra.js";
import { levenshtein } from "../src/typosquat.js";
import { groundTruthBlastRadius, precisionRecall } from "../src/eval.js";

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
