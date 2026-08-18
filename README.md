# Supply Chain Blast Radius

[![test](https://github.com/sogoyalz/hydra-blast-radius/actions/workflows/test.yml/badge.svg)](https://github.com/sogoyalz/hydra-blast-radius/actions/workflows/test.yml)

Hack Hydra 2026 submission — Track 2, Option A ("Repos, Dependencies + Code as Graphs").

**The question:** if an npm package is compromised right now, what's exposed? This project builds the npm dependency graph in [HydraDB](https://github.com/hydra-db/hydradb) and answers that with a graph traversal — not a guess, not a vector search.

## Why this is a graph problem, and what HydraDB does here

A compromise spreads two ways, and they are different relationships in the graph:

1. **Through code you pull in** — the dependency tree. `(dependent)-[:DEPENDS_ON]->(dependency)`.
2. **Through credentials that can push code to you** — shared publish rights. `(package)-[:MAINTAINED_BY]->(maintainer)`.

Scanners model the first. The incident the track brief opens with was the second: the TanStack worm published 84 malicious artifacts across 42 packages in six minutes through compromised *publish access*, and those packages did not depend on each other. Modelling both as first-class edges and reporting their union is the core idea here.

The gap is not academic. On the demo graph:

| Package | Exposed via dependencies | Reachable via shared publish rights | **Total blast radius (union)** |
|---|---|---|---|
| `body-parser` | 1 | 36 | **36** |
| `qs` | 2 | 8 | **10** |
| `debug` | 6 | 1 | **7** |

`body-parser` looks nearly harmless through a dependency lens — **1** exposed package. Widen to publish rights and **36** packages are in range of the same credentials, **35 of them invisible to dependency scanning entirely**. The UI leads with the union for exactly this reason, and shows the per-channel split underneath so the number stays honest.

![One maintainer's publish reach from body-parser](docs/credential-reach.png)

*Clicking the maintainer `dougwilson` lights up everything one stolen credential reaches. The two-node core near the centre — `body-parser` and `express` — is the entire dependency blast radius; every other node is invisible to a dependency scanner. Both channels are drawn — squares are maintainers, dashed edges are publish rights.*

**Why a graph database rather than a table or a vector index.** The dependency answer is a transitive closure of unbounded depth — a self-join repeated until fixpoint in SQL, one traversal here. The publish-rights answer is a two-hop walk *across two different edge types* (`MAINTAINED_BY` then `MAINTAINS`). Neither is a similarity question, so an embedding index cannot answer either one: "which packages are semantically similar to `qs`" is not "which packages break when `qs` breaks."

**The whole picture is one query.** The exposed set, every package's hop distance, and every edge between them all come back from a single call to HydraDB's native single-source path procedure:

```cypher
CALL algo.SSpaths({sourceNode: $sourceNode, relTypes: ["REQUIRED_BY"], maxLen: 6, pathCount: 1024})
YIELD path RETURN path
```

Because it returns *paths* rather than endpoints, one round trip carries everything a fan-out implementation has to go back and ask for — the endpoint of each path is an exposed package, its length is the hop distance, and its relationships are the edges. `src/blastRadius.js` keeps the portable variable-length-`MATCH` version as `blastRadiusFanout()` and falls back to it automatically if the procedure is unavailable or hits its path cap, so the demo still runs against a build without it. The two produce **identical node sets, edge sets and hop distances** on every package in the demo graph — verified, not assumed:

| Target | Native | Fan-out fallback | Median speedup | Range over 7 runs |
|---|---|---|---|---|
| `debug` | **1 query** | 10 queries | **16x** | 12.8x – 21.3x |
| `qs` | **1 query** | 5 queries | **10x** | 8.0x – 12.3x |
| `send` | **1 query** | 5 queries | **11x** | 8.0x – 15.3x |
| `body-parser` | **1 query** | 4 queries | **9x** | 4.9x – 12.7x |

*Measured on the 120-package demo graph `./setup.sh` builds, median of 7 trials per target. Reproduce it yourself — the measurement ships with the project:*

```bash
node bench/speedup.js --trials=7
```

**The range column is there because a single timing is not reproducible, and quoting one as if it were would be the same kind of overclaim this project spends the rest of its time avoiding.** The same target measured 4.9x and 12.7x on different runs of that script against the same graph; an earlier single-run measurement of this table read as high as 29x. Your own run will land somewhere else again — that is the honest shape of the number, which is why the script prints the range and not just the middle. The query-count column is the durable claim — that one is structural and identical on every run — and the honest latency summary is **roughly 9–16x typical, occasionally as low as 5x**. It also does not hold at every scale, for reasons worth reading before trusting any of it: see [the path ceiling](#the-path-ceiling-and-why-the-fast-path-is-not-always-the-right-one).

Calling it at all took some finding, and both discoveries are the kind that cost an afternoon:

- The request field is **`parameters`**, not `params`. A field named `params` is accepted by the transport and silently ignored, so the server answers `missing OpenCypher query parameter $sourceNode` while the parameter is sitting in the request body.
- **Only scalars bind.** `sourceNode` *must* be a bound parameter and `relTypes` *must not* be — a list parameter is rejected with `composite parameter is only supported as an UNWIND input`.

**Engaging with the engine's real limits.** Three further constraints were found the same way, and each one visibly shaped the design rather than being worked around silently:

- Variable-length `MATCH` only expands **forward from a fixed source id**, so "who depends on X" is impossible as a reverse query. A mirrored `REQUIRED_BY` edge is written at ingest time so the question becomes a forward traversal. ([why](#why-the-mirrored-edge))
- Vertex identity is the integer `id` **alone — labels do not scope it**, and they accumulate. Hashing maintainer names in the same space as package names would have silently fused maintainer `ljharb` with a package named `ljharb`. Ids are namespaced per type. ([why](#why-vertex-ids-are-hashed-and-namespaced))
- A relationship pattern may name **exactly one type** — `[:REQUIRED_BY|MAINTAINS*1..3]` is rejected outright. So the two channels genuinely cannot be walked in one traversal; they are queried separately and unioned in `src/server.js`. That is a design consequence, not a shortcut.

### The path ceiling, and why the fast path is not always the right one

`algo.SSpaths` **silently caps at 1024 paths**, whatever you ask for. Requesting 100, 500 or 1000 returns exactly that many; requesting 2000, 5000 or 20000 all return exactly 1024. It is not documented and there is no flag, warning, or truncation marker in the response — the reply to a saturated query is shaped exactly like the reply to a complete one.

That matters far more here than a missing feature would, because this returns *paths*, and path count grows combinatorially with graph density while the answer we want — the exposed set — grows linearly. So the ceiling is reached long before the graph is large, and **the failure mode is a blast radius that is quietly too small.** Measured on a 1,024-package graph built from a dozen real roots:

| Target | Reported by the native path | Actually exposed | Silently missing |
|---|---|---|---|
| `chalk` | 68 | **89** | 21 packages |
| `tslib` | 72 | **84** | 12 packages |
| `semver` | 109 | **120** | 11 packages |

For a security tool that is the worst failure available: under-reporting exposure reads exactly like safety. `src/blastRadius.js` therefore requests **exactly the ceiling** and treats a full-ceiling response as *possibly truncated*, falling back to the variable-length traversal whenever it sees one. (Asking for more than the ceiling is what makes saturation undetectable: request 2000, receive 1024, and a "did we hit the cap?" check comparing against 2000 can never fire.)

**The cap is not the procedure's — it is every query's.** Falling back is only a fix if the thing fallen back to is complete, and it was not. `MATCH (a:Package)-[:DEPENDS_ON]->(b:Package) RETURN a.name, b.name` on a graph with more edges than that returns exactly **1024 rows**, and so does the plain traversal, and so does listing the packages. Nothing in the response says it was cut. Checked against a synthetic graph whose answer is known by construction — 1,500 packages depending directly on one target — the "exhaustive" fallback returned **1024**.

Paging past the cap works, but **not by offset**, and that distinction cost a second bug. `SKIP`/`LIMIT` do reach past the cap — `SKIP 1024` returns real rows — so an offset pager looks like the fix and passes every test run against a graph nobody is writing to. Run one against a graph that *is* being written to and it comes apart: taking page one of a 1,500-row result, ingesting 800 packages, then taking page two at `SKIP 1000` **lost 528 rows that had been present the entire time** and duplicated 260 others. Each insert lands somewhere in the ordering, every later row shifts right, and the next offset steps straight over the ones that moved. `ORDER BY` does not save it — the offset is still counted from a start that has grown.

`runQueryPagedKeyset()` in `src/hydra.js` therefore **seeks** rather than skips: each page resumes with `WHERE key > <last key seen>` instead of an offset, which is immune to the same interleaving — a row inserted after the current key gets picked up by a later page, and one inserted before it was already passed. Re-running the exact scenario that lost 528 rows now loses **none**.

That requires a key unique per row, which shapes the queries. The blast-radius traversal and the package list seek on the package name. The shared-maintainer traversal cannot, because its rows are (maintainer, package) pairs and neither column is unique — so it fetches the target's maintainers first (a handful) and pages each one's packages separately, where the name *is* unique. On the demo graph none of this is visible: every result fits in one page and the numbers are unchanged.

The consequence is worth stating plainly, because it cuts against the speedup table above: **on a large graph the popular packages — the ones whose blast radius you most want — are exactly the ones that fall back to the slower, exhaustive path.** The single-query result is real, and it is what the demo graph runs on; it is not a claim about every graph.

#### Reproduced on demand, at 1,505 packages

The 120-package demo graph never triggers any of this, so none of it is visible in the demo — which is a fair reason to be sceptical of it. Ingesting ~40 more npm roots brings the graph to **1,505 packages / 3,444 dependency edges**, and every mechanism above fires:

**The row cap truncates a plain query.** Asking for every package name in one query returns exactly **1,024** rows against a graph holding **1,505** — no error, no flag, no `next_cursor` marking the result short. The keyset pager returns all 1,505. **481 packages, silently absent** from a query that looked like it succeeded.

**The path ceiling saturates on the densest targets, and the fallback catches it.** Taking the six most depended-upon packages by in-degree:

| Target | `algo.SSpaths` | Exhaustive fallback | Outcome |
|---|---|---|---|
| `tslib` | **saturated** | 82 | ceiling detected → fell back |
| `es-errors` | **saturated** | 135 | ceiling detected → fell back |
| `call-bound` | **saturated** | 92 | ceiling detected → fell back |
| `debug` | 93 (1.2s) | 93 (5.7s) | agree |
| `semver` | 95 (1.4s) | 95 (6.2s) | agree |
| `@parcel/plugin` | 43 (0.6s) | 43 (1.9s) | agree |

Three of the six densest packages in the graph saturate the fast path. The guard catches all three and the slower walk answers them completely. The other three agree exactly between the two engines — which is the part that makes the fallback trustworthy rather than merely different: where the fast path *is* complete, it and the exhaustive path return the identical set.

**End to end through the API**, `/api/blast-radius?name=es-errors` reports `engine: "variable-length MATCH"` and `fallbackReason: "path-ceiling"`, and the UI says the radius is complete rather than truncated — a saturated ceiling means the fast path *would have* under-reported this specific answer, which is worth saying out loud on a security tool.

**And the honest cost.** `coreQueryMs` goes from 4–6ms on the demo graph to 0.6–1.4s here, and a saturating target costs ~2s on the fallback traversal plus several seconds more to assemble the drawing. Work is proportional to paths enumerated, not to answer size. The 9–16x speedup in the table above is a demo-graph number and does not survive to this scale; the correctness guarantee does.

Reproduce with `node src/eval.js`-style ingestion of additional roots — any ~40 npm roots will do it, since the thresholds are properties of the engine, not of the packages chosen.

**Proof the traversal is correct.** `src/eval.js` computes the blast radius independently by BFS over the raw edge list in memory, with no HydraDB involved, then asks HydraDB the same question and diffs the two sets: **1.00 precision and 1.00 recall** on every target. This is a correctness gate on the ingest → store → traverse round trip, not a vulnerability-detection accuracy score — the distinction matters and is spelled out in [the eval section](#correctness-eval).

**And proof the data itself is right.** That gate has a real limit: its ground truth is derived from this project's own crawl, so a crawler that learned the wrong edges would be graded against its own mistake and still score 1.00. `src/evalExternal.js` closes that loop by scoring against **deps.dev (Google's Open Source Insights)** — an independently resolved dependency graph for npm, built by Google's resolver with no connection to this crawler. Inverting its forward closures gives a true external answer to "who depends on X", and against it this project scores **recall 1.00, mean precision 0.92** — and every point of that precision gap is attributed by name, not hand-waved: it is `minimizer-webpack-plugin` reaching those targets through its `webpack` **peerDependency**, an edge this graph models deliberately (a compromised peer runs in your build exactly like a compromised dependency) and an install closure does not walk. See [validation against an independent source](#validation-against-an-independent-source).

**And the graph shows its work.** Click any node and the exact chain that exposes it lights up, reconstructed from the edges the traversal already returned — clicking `serve-static` on a `debug` blast radius traces `serve-static → send → debug`, each package depending on the next. Click a package reachable only through credentials and it says so explicitly, naming every maintainer who can publish to both it and the target. Click a maintainer and its entire publish reach lights up at once. Membership is the weak claim; the path is the evidence.

![Tracing the dependency chain that exposes serve-static](docs/traced-path.png)

## Try it without installing anything

There is a **[recorded snapshot of the running demo](https://sogoyalz.github.io/hydra-blast-radius/?pkg=body-parser&maintainer=dougwilson)** — the graph, click-to-trace, publish-rights reach, typosquat scan and version-level advisories, all explorable in the browser with no Docker and no database.

Every number in it is the real response from a real HydraDB traversal over the 120-package demo graph, captured by `scripts/capture-snapshot.js` and committed. **It is not a live database, and the page says so in a banner at the top.** A project whose whole argument is "this tool never quietly reports the wrong thing" does not get to ship a demo that pretends to be something it isn't. For live queries against any package at any depth, clone and run — it takes about fifteen seconds.

## Quick start

```bash
./setup.sh
```

That's the whole setup. It starts HydraDB, waits for it to accept queries, ingests a real npm dependency graph from the public registry, and serves the UI at `http://127.0.0.1:8787`. **Cold start to working UI took 15–18 seconds across three runs from a deleted container and a wiped store** — the database is accepting queries after 2 of those, and the rest is crawling npm, so your number moves with the registry rather than with this code. Re-running with everything already up returns in under a second; recreating just the container over an existing store took 3. Requires Docker and Node 18+ — the script checks both and tells you exactly what to do if either is missing. `./setup.sh --fresh` wipes the database and starts over.

> **Clone somewhere under your home directory.** HydraDB writes its store to a bind-mounted `hydradb-data/` as your own user, so the repo has to sit on a path your Docker VM shares writably. Some `/tmp` locations are mounted read-only or as root (this bites under Colima), and Docker Desktop only shares the directories in its File Sharing list. If you hit it, setup stops in about two seconds and says so explicitly rather than leaving you guessing.

Once it's up, try **`body-parser`**: one package exposed through dependencies, ~36 through shared publish rights. That gap is the point of the project.

## Status

Working end-to-end, including the demo UI. Of the six questions the track brief asks a submission to answer when a package is compromised, this answers five:

| Brief's question | Status |
|---|---|
| What is the complete blast radius? | ✅ `src/blastRadius.js` |
| Which services are transitively exposed? | ✅ `src/blastRadius.js`, reported with hop distance |
| Which packages share maintainers with it? | ✅ `src/sharedMaintainers.js` |
| Are there likely typosquats nearby? | ✅ `src/typosquat.js` |
| Which version introduced the vulnerability? | ✅ `src/versions.js`, against OSV's affected ranges |
| Which apps resolved the bad version while live? | ❌ needs lockfile ingestion |

The one remaining gap needs something the others did not: a concept of an *application* at all. This graph models packages and the people who can publish them; "which apps resolved the bad version while it was live" needs each app's resolved lockfile plus the window each bad version was installable in — a new vertex type and an ingestion source, not another query over what is already here. It is left undone and said so rather than approximated.

Version-level modelling arrived late and deliberately second. The first thing built after the dependency graph was the other *attack channel* (publish rights), because the incident the brief opens with spread through stolen credentials, and no amount of version resolution would have caught it. Versions are a second *dimension* on a channel already modelled — worth having, but worth less than the channel nobody else was modelling at all.

Plus two evals and a test suite: a [round-trip correctness gate](#correctness-eval) (independently-computed ground truth vs. HydraDB's own traversal, cross-referenced against real OSV advisories), [validation against deps.dev](#validation-against-an-independent-source) so the *data* is graded by an outside resolver and not only by this project's own crawl, and [45 unit tests](#unit-tests) (`npm test`) covering the id-collision, escaping, timeout, semver-ordering, advisory-range and filter logic. Served through a zero-dependency API + browser visualization (`node src/server.js`, then `http://127.0.0.1:8787`).

### Running the demo UI

```bash
node src/server.js --port=8787
```

Then open `http://127.0.0.1:8787`, type a package name that's already in the graph (the input autocompletes from `/api/packages`), and click "Compute blast radius". Try `body-parser`, `qs`, or `debug`.

**Both attack channels are drawn in one picture.** Circles are packages, coloured by hop distance; squares are maintainers — a different shape because they are a genuinely different vertex type in the graph. Solid arrows are dependency edges; dashed red edges are publish rights. Packages sitting on the outermost ring in red are reachable *only* through credentials: a dependency scanner reports none of them. A package already in the dependency tree that is *also* in credential range gets a dashed halo, because it is exposed twice over.

**Then click something.** Clicking a package traces the exact chain that exposes it — clicking `serve-static` on a `debug` radius lights up `serve-static → send → debug` and spells it out in the sidebar. Clicking a credential-only package says so explicitly and names every maintainer who can publish to both it and the target. Clicking a maintainer lights up its entire publish reach at once. All of it is reconstructed from data the blast-radius response already carried, so every interaction costs zero additional queries.

**Demo-ready example:** `./setup.sh` ingests `express --depth=4 --max-nodes=250` and `webpack --depth=3 --max-nodes=150` into one graph — **120 real packages**, including [`qs`](https://github.com/advisories?query=qs), which has 7 real GHSA advisories (prototype pollution, DoS). `node src/blastRadius.js qs` correctly returns `body-parser` and `express` as exposed, via the real `express -> body-parser -> qs` dependency chain — a genuine incident, not a synthetic example.

It also ingests `expres` — a real package someone published to npm, a genuine typosquat of `express` sitting about five orders of magnitude below it in weekly downloads (2,896 vs 109,881,741 when last checked on 2026-08-18) — so the typosquat scanner has an actual positive to find rather than an empty result. Nothing about it is synthetic; it is a squatted name that really exists. Those two counts are live figures and move every week; the ratio is the part that stays put.

**Deep links.** Any view is addressable, which makes a specific finding quotable rather than a list of steps to reproduce:

```
http://127.0.0.1:8787/?pkg=body-parser&maintainer=dougwilson   one credential's whole reach
http://127.0.0.1:8787/?pkg=debug&trace=serve-static            the chain that exposes a package
```

### The second attack path: shared publish rights

```bash
node src/sharedMaintainers.js body-parser
```

A dependency-only blast radius answers "what pulls this code in". It does not answer "who else can push code here" — and in the incident the track brief opens with, that was the actual vector: the TanStack worm published 84 malicious artifacts across 42 packages in six minutes through compromised *publish access*. Those packages did not depend on each other. They shared a credential.

So the graph also models `(:Package)-[:MAINTAINED_BY]->(:Maintainer)` (mirrored as `MAINTAINS`), and asks the question as a two-hop traversal across two different edge types:

```cypher
MATCH (target:Package {id: <id>})-[:MAINTAINED_BY]->(m:Maintainer)-[:MAINTAINS]->(sibling:Package)
RETURN m.name, sibling.name
```

The gap between the two answers is the point, and it is measured at the top of this README: `body-parser` exposes **1** package through dependencies and **36** through publish rights — **35** of them reachable by no dependency edge at all.

> Note: this models *blast radius*, not wrongdoing. These are the legitimate maintainers of widely-used packages; the point is that their credentials are a high-value target, which is what makes the exposure worth measuring.

### Version-level advisory ranges

```bash
node src/versions.js qs
```

The blast radius above is computed over packages, which is the right granularity for "what is exposed" and the wrong one for "is *my* version exposed". `src/versions.js` adds `(:Package)-[:HAS_VERSION]->(:Version)`, carrying each release's real publish date from the npm registry, and checks every published version against OSV's affected ranges.

**The brief's wording invites a useless answer, so this reports something better.** "Which version introduced the vulnerability" sounds like it wants one number, and for most advisories that number is trivially "the first release ever published" — OSV writes `introduced: "0"` whenever a bug predates every release, which is the most common case by far. Of `qs`'s 7 advisories, 5 start at `0`. Answering "0.0.1 introduced it" five times is technically correct and tells you nothing. What the data actually supports, and what this reports, is **which published versions fall inside an affected range and exactly where each range closes** — with the literal introduced version alongside it whenever OSV names a real one.

Measured against `qs`'s 149 published versions and its 7 real GHSA advisories:

| Advisory | Affected versions | Range | Introduced | Fixed |
|---|---|---|---|---|
| GHSA-hrpp-h998-j3pp | 98 of 149 | `0.0.1` → `6.10.2` | 9 separate windows | 9 separate fixes |
| GHSA-6rw7-vpxm-498p | 143 of 149 | `0.0.1` → `6.14.0` | first release | `6.14.1` |
| GHSA-w7fw-mjwx-w883 | 47 of 149 | `6.7.0` → `6.14.1` | **`6.7.0`** | `6.14.2` |
| GHSA-q8mj-m7cp-5q26 | 19 of 149 | `6.11.1` → `6.15.1` | **`6.11.1`** | `6.15.2` |

The two bolded rows are the ones where "which version introduced it" has a real answer, and it is not the first release.

**Why an advisory is a set of windows, not a range.** `GHSA-hrpp-h998-j3pp` carries **nine** independent affected windows, because the fix landed separately on nine maintained release lines (`6.3.x`, `6.4.x`, … `6.10.x`, plus everything below `6.2.4`). Reading it as a single `introduced..fixed` span — the obvious implementation — marks the gaps between those windows as affected when they are patched, or marks whole later lines safe when they are not. `isAffectedByRange()` walks OSV's events in order the way the spec describes: an `introduced` at or below the version opens a window, a `fixed` at or below closes it, and the version is affected if any window is still open at the end. Verified by re-deriving the same 98 versions through an independent interval-membership implementation: **both agree exactly, on all 149 versions, with zero disagreements**, and the boundaries land where they should — `6.2.3` affected, `6.2.4` not, `6.3.0` affected again, `6.10.2` affected, `6.10.3` not.

Three details that are easy to get silently wrong, and are handled rather than assumed:

- **`introduced: "0"` is a sentinel, not a version.** Parsing it as `0.0.0` would exclude a package whose first release was a prerelease, since `0.0.0-alpha` sorts *below* `0.0.0` and would fall outside a range meant to cover everything. It is treated as negative infinity.
- **A range with no `fixed` event means still vulnerable**, and must resolve to affected rather than to "no information".
- **`GIT`-type ranges express commit reachability**, which no version comparator can decide. They are skipped, counted, and surfaced — never quietly folded in as "not affected".

Version strings that are not valid semver return `null` from the comparator instead of being coerced into something sortable, and are counted and reported rather than dropped: a version silently mis-ordered across a range boundary is exactly the quiet wrongness this project refuses everywhere else.

**Cost.** Version history is ingested on demand and only once per package: a cold `send` (69 versions) costs 1168ms to crawl and write plus 337ms at OSV; warm, the same call is a 278ms paged read plus the same OSV round trip. Concurrent first-requests for the same package share one analysis rather than racing — measured against a counting registry proxy, six simultaneous cold requests produced **one** packument fetch.

**A capped history stays labelled as one, across restarts.** Ingest is capped at `--max-versions` (default 500, newest first), and the cap is reachable on ordinary packages — `webpack`, which the demo graph already contains, has published 883 versions. The trap is that truncation happens at *write* time: a later read that counts only the rows it got back cannot tell "this package has 5 releases" from "it has 35 and we kept 5", so it presents an analysis over a partial history as complete. That is not theoretical — it was measured here before the fix. `cookie` ingested at `--max-versions=5` reported `truncated: false` on every later read and scored **0 of 5 versions affected** for `GHSA-pxg6-pf52-xh8x`; over its full 35 releases that advisory affects **25**. A real finding had become a clean bill of health. The true published total is now stamped on each `:Version` vertex at write time and truncation is re-derived on read, so the warning survives a server restart and an emptied cache. Verified both directions: `webpack` reports 500 of 883 truncated after a cold restart, `qs` (149 of 149) does not false-warn.

**An unparseable version boundary is reported, not absorbed.** If an advisory carries a range boundary this cannot parse, the window it belongs to cannot be evaluated, and an unevaluated window fails *closed* — the version comes back unaffected. That is under-reporting, so the affected count is labelled a lower bound rather than left to look authoritative. This does not fire on real npm data: across 127 advisories and 416 version boundaries sampled from 20 packages, every range was `SEMVER` and every boundary parsed. The signal was already being computed and simply thrown away, which is the part worth fixing — the failure would have been silent, not loud.

**When OSV cannot be reached, this reports that, not "no vulnerabilities."** The distinction is the whole point: a network failure rendered as an empty advisory list tells a reader the package is clean when nothing was checked at all. The CLI exits non-zero and says so, the API returns `osvUnavailable`, and the UI renders it as its own state. This is the one place the codebase deliberately does *not* follow `typosquat.js`'s pattern of defaulting a failed lookup to zero — there the number feeds a ratio, here it *is* the finding.

### Correctness eval

```bash
node src/eval.js koa --depth=3 --max-nodes=200
```

The track brief scores on precision, recall, query latency and cost against OSV / GitHub Advisory ground truth. Since the organizers' held-out harness isn't available to entrants, `src/eval.js` builds the strongest self-check available: it crawls a dependency tree, computes the blast radius **independently** by BFS over the raw edge list in memory (no HydraDB involved), then asks HydraDB's `REQUIRED_BY` traversal the same question and compares the two sets — reporting precision, recall, F1 and per-query latency, with each target cross-referenced against its real OSV advisory count.

The two methods should agree exactly; they currently do, at **1.00 precision and 1.00 recall** on every target, with traversals answering in 25–30ms. Run against an empty graph (`./setup.sh --fresh --no-ingest`) on 2026-08-17:

```
target               truth   hydra   P      R      F1     ms     prior  OSV advisories
fresh                1       1       1.00   1.00   1.00   29     0      1
negotiator           2       2       1.00   1.00   1.00   27     0      1
mime-types           3       3       1.00   1.00   1.00   30     0      0
statuses             3       3       1.00   1.00   1.00   29     0      0
http-errors          2       2       1.00   1.00   1.00   25     0      0
```

`prior` is 0 on every row, which is what makes this a clean baseline rather than a flattering one: it counts packages HydraDB returned that came from some *earlier* ingest, and any non-zero value there would mean the graph held more than this crawl and the precision column was measuring the wrong thing.

Targets are chosen to make the table say something. Ranking purely by in-degree picks the biggest blast radii, but the most-depended-upon packages in a typical npm tree are stable low-level utilities that have never had an advisory — which made the OSV column print all zeros on every run and look like a dead integration. So a wider slice is ranked by in-degree, packages carrying real advisories are preferred, and the rest is backfilled by in-degree.

**What this proves, and what it does not.** It is a correctness gate on the ingest → store → traverse round trip: it answers *"does HydraDB return exactly the set that is actually reachable in the graph we wrote."* It is **not** a measure of vulnerability-detection accuracy against OSV/GHSA. The ground truth is a BFS over the same edge list that was just written, so the score can only drop if ingestion or traversal is broken — which makes it a strong regression test and a deliberately weak accuracy claim. Measuring true detection accuracy needs the organizers' held-out advisory set, which entrants don't have.

Run it against a database holding **nothing but this crawl** — `./setup.sh --fresh --no-ingest`, then the command above. HydraDB accumulates everything previously ingested (correct behavior for a real ecosystem graph — more history means more complete answers), but the in-memory ground truth only knows the current crawl, so correct matches from earlier ingests would read as precision loss.

Note that a plain `./setup.sh --fresh` is *not* enough, which is why `--no-ingest` exists: `--fresh` reloads the 120-package demo graph, and the eval then counts those (correctly) as prior knowledge. Run without it and the table still passes — recall stays 1.00 and nothing inside the crawl is contradicted — but the precision column reads below 1.00 and the run says exactly how many packages came from an earlier ingest.

### Validation against an independent source

```bash
node src/evalExternal.js
```

The eval above has a limit worth naming: its ground truth is a BFS over the same edge list this project just wrote, so it can only catch a broken *round trip*. If the crawler learned the wrong edges, both sides are wrong together and the score is still a confident 1.00.

This script grades the data instead of the plumbing. Ground truth comes from **[deps.dev](https://deps.dev)**, Google's Open Source Insights — a fully resolved transitive dependency graph for npm, produced by Google's own resolver with no connection to this crawler. deps.dev answers the forward question ("what does `P` depend on"), so the closures are inverted to produce the reverse one this project answers:

```
externalDependents(X) = { P in graph : X ∈ depsdev_closure(P) }
```

On the demo graph, against 116 independently resolved closures (run 2026-08-17):

| Target | deps.dev | HydraDB | P | R | OSV advisories |
|---|---|---|---|---|---|
| `ms` | 7 | 7 | 1.00 | **1.00** | 2 |
| `@xtuc/long` | 10 | 11 | 0.91 | **1.00** | 0 |
| `@webassemblyjs/floating-point-hex-parser` | 9 | 10 | 0.90 | **1.00** | 0 |
| `@webassemblyjs/helper-api-error` | 9 | 10 | 0.90 | **1.00** | 0 |
| `@webassemblyjs/helper-numbers` | 8 | 9 | 0.89 | **1.00** | 0 |

**Recall is 1.00 — nothing an independent resolver knows to be exposed is ever missed.** That is the number that matters for a security tool: a missed dependent is an unreported compromise.

> Expect the precision figure to move slightly between runs, and not because anything changed here. Targets are picked at runtime by cross-referencing live OSV advisories, and deps.dev is a live service resolving current versions — so the five packages selected, and their closures, both drift. An earlier run of this same command scored **0.94**, on a target list that included `debug` (1.00) where this one has `@webassemblyjs/helper-numbers` (0.89) — the mean moved because the sample did, not because a traversal changed. Recall has been 1.00 on every run; that is the invariant worth holding this to, not the second decimal of precision.

Precision is 0.92 here, and the script does not wave at the gap — it attributes every case with evidence. All of it is one package, `minimizer-webpack-plugin`, reaching those targets through its `webpack` **peerDependency**. `src/ingest.js` merges `peerDependencies` into the dependency edges on purpose: a plugin that peers on `webpack` runs alongside whatever `webpack` ships, so a compromised peer is exactly as dangerous as a compromised dependency. deps.dev reports an *install* closure, where peers are not pulled in transitively. So this project deliberately reports more, and the script says which package, which peer edge, and why, rather than filing it under "version skew" and hoping.

Two sources of disagreement are separated and labelled rather than folded into the headline number: dependents deps.dev knows that a bounded crawl (`--depth`/`--max-nodes`) never ingested are a **collection** limit, not a traversal miss; dependents this graph has that deps.dev's single resolved version does not are peer edges or version skew, distinguished by checking the manifest.

### Unit tests

```bash
npm test
```

45 tests, `node --test`, no dependency added and no running database or network needed. CI runs them on **Node 18 and 22** — 18 because that is the floor `package.json` claims, and a claimed floor nobody tests is just a comment. The same job fails the build if a third-party dependency or a `node_modules` ever appears, so the zero-dependency claim below cannot quietly go stale — the graph-dependent behaviour is already covered by the two evals above. They are regression tests rather than coverage for its own sake: every case guards a decision made for a stated reason, or a bug that actually happened here and would be silent if it came back.

- **Vertex ids.** A package and a maintainer of the same name must never hash to the same id. HydraDB keys vertices on the integer id alone — labels do not scope identity and they accumulate — so a collision silently fuses two entities into one vertex holding both sets of edges, and npm users routinely publish a package under their own handle. Also asserts ids stay inside the safe-integer range, since they are written into Cypher as integer literals.
- **`cypherString` escaping.** Names come from third-party manifests and are interpolated into query text, so this is the boundary that stops a registry name terminating the literal. Includes an injection payload, and the backslash-before-quote ordering that keeps a trailing backslash from escaping the closing delimiter.
- **`fetchWithTimeout`, both halves of a real bug.** One test for a server that never responds, one for a server that sends headers and then stalls mid-body — the second is the case the first version of the fix missed, because it disarmed its timer as soon as headers arrived.
- **`levenshtein` and the filter thresholds.** Pins the distances the typosquat filter is tuned around, including the short-name pairs (`ms`/`qs`, `acorn`/`cors`) that motivate the ratio rule. Writing these caught a documentation error: `reqeust`/`request` is the distance-2 case the docs meant, while `reqeusts` is distance 3 and is rejected — a typo in the example about typos.
- **A `NaN` typosquat threshold matches nothing.** Every numeric CLI flag is validated, and this one is why it matters rather than being tidiness: `Number("abc")` is `NaN`, every `distance <= NaN` comparison is false, and the scan discards every candidate. Measured before the fix — `node src/typosquat.js --max-distance=abc` printed *"No typosquat candidates found"* on the demo graph, silently suppressing the real `expres`/`express` squat the graph exists to surface. A single mistyped flag turned a security scanner into a clean bill of health, which is the same under-reporting failure the path ceiling is guarded against.
- **`groundTruthBlastRadius`.** The independent BFS the correctness eval is graded against, so a bug here would quietly corrupt the thing doing the grading. Includes a cyclic graph, since merging `peerDependencies` into dependency edges creates cycles routinely.
- **`precisionRecall`.** Perfect agreement, one-sided misses, and the empty-set case that must not produce `NaN`.
- **`compareSemver`.** Ordering, prerelease precedence (`1.0.0-alpha` < `1.0.0`, numeric identifiers compared numerically so `alpha.9` < `alpha.10`, numeric ranking below alphanumeric), build metadata ignored, and unparseable input returning `null` instead of sorting wrongly. This decides which releases sit inside an advisory's affected range; getting it wrong moves a boundary silently rather than failing.
- **`isAffectedByRange`.** Inclusive `introduced` and exclusive `fixed`, the `"0"` sentinel covering a prerelease below `0.0.0`, an open range with no fix still counting as affected, `last_affected` closing inclusively where `fixed` does not, `GIT` ranges skipped and counted, and — the case a naive implementation gets wrong — **multiple windows staying independent, with the gap between them correctly safe**.
- **Version id namespacing.** That a `:Version` cannot collide with its own `:Package` or a `:Maintainer`, and that the length-prefixed encoding cannot be forged from either field. That last test failed when it was written, which is how the separator ambiguity above was found.
- **`deriveTruncation`.** That a stored history smaller than the real published total is flagged partial, that a complete one is not falsely flagged, and that a missing total degrades to "complete" rather than warning on every package. This guards the `cookie` case above, where a capped history silently turned a 25-version advisory into "0 affected".

### On the latency numbers

The UI reports two figures, deliberately kept apart. **`coreQueryMs`** is the single `algo.SSpaths` call that answers "what is exposed" and returns the shape needed to draw it — typically 4–6ms warm on the demo graph, and the only number that should be read as HydraDB's query speed. That figure is scale-dependent, and honestly so: on the 1,024-package graph described under [the path ceiling](#the-path-ceiling-and-why-the-fast-path-is-not-always-the-right-one) the same call runs 400–1300ms, because the work is proportional to the number of *paths* enumerated rather than to the size of the answer. **`totalMs`** additionally covers the existence check and the separate publish-rights traversal, which is a genuinely different question against a different edge type. The UI also names which engine path answered, because that is not cosmetic: on the fallback, `coreQueryMs` covers only the first of several queries and `totalMs` also absorbs hop-distance probes and per-package edge lookups that exist *only to draw the graph*. Those were never folded into a single flattering number, and now that the native procedure removes them entirely, the honest comparison is still on the record above.

### On cost

The brief's fourth eval axis, alongside precision/recall/latency. There's no metered bill to report here — this runs against a self-hosted, single-node alpha image with no usage-based pricing exposed — so the honest proxy is query cost, not dollar cost: **one `algo.SSpaths` call replaces up to 10 fan-out queries** (a 4–10x reduction in round trips, worth a median 9–16x end to end; see the table above), and that reduction is exactly what a metered deployment would bill for, since HydraDB's storage/compute-disaggregated architecture prices on requests against the object store, not on data volume held. The other place cost shows up is ingest: `src/typosquat.js` deliberately uses a static `POPULAR_PACKAGES` reference list rather than a live popularity API call per candidate, and `src/ingest.js` bounds every crawl with `--depth`/`--max-nodes` — both are cost controls as much as they are demo-stability controls.

### Typosquat detection

`node src/typosquat.js` scans every package name currently in the graph, flags anything within edit distance 2 of a popular reference package (`src/typosquat.js`'s `POPULAR_PACKAGES`), and confirms suspicion using live npm weekly download counts — a genuine typosquat has far fewer downloads than the package it resembles. On the demo graph:

```
[HIGH] "expres" (distance 1 from "express") — 2896 weekly downloads vs 109881741
       for "express" (0.003% of "express"'s downloads)
```

The two counts come from npm's live downloads API, so re-running this will print different figures than the sample above (captured 2026-08-18) — that is the integration working, not drifting docs. What does not move is the shape of the finding: a name one edit away, orders of magnitude below the package it imitates.

This is deliberately two-signal, because each signal alone is wrong in a different way:

- **Edit distance alone over-reports.** `isarray` is a real, independently popular package one edit from `is-array` — and has *more* downloads than it. The ratio reclassifies it as "likely coincidence" instead of flagging it.
- **Absolute distance is meaningless on short names.** `ms` is one edit from `qs`, and `acorn` is two from `cors`; neither has anything to do with impersonation. Distance must also be small *relative* to name length (≤ 0.34), which drops both while keeping `expres`/`express` (distance 1, ratio 0.17) and `reqeust`/`request` (distance 2, ratio 0.29).

The panel leads with the verdict rather than the raw candidate list, since the count that matters is how many survived both filters.

**When the download check cannot run, the candidate is unresolved — not cleared.** The confirming lookup used to return `0` on failure, which collapsed both sides of the ratio to zero, produced a null ratio, and scored the candidate *"likely coincidence"* — so an npm downloads outage silently downgraded a real squat to background noise and the panel headlined **"No likely typosquats."** in green. Measured against a stubbed 500 and a refused connection: `expres`/`express` went from `high` to `likely coincidence` in both. A failed lookup now yields its own `unconfirmed` verdict, ranked directly below `high` because that is the honest place for it — it could have been a high and nothing ruled that out. A 404 is deliberately still a real zero, since npm answers that way for a package with no download record, which is the strongest signal a freshly-published squat can give.

## How HydraDB is used

The graph has three vertex types and five edge types:

- `(dependent:Package)-[:DEPENDS_ON]->(dependency:Package)` — the natural direction
- `(dependency)-[:REQUIRED_BY]->(dependent)` — the reverse, written at ingest time
- `(package)-[:MAINTAINED_BY]->(maintainer:Maintainer)` — publish rights
- `(maintainer)-[:MAINTAINS]->(package)` — the reverse, likewise
- `(package)-[:HAS_VERSION]->(version:Version)` — release history with publish dates

`HAS_VERSION` needs no mirrored twin, unlike the two above it. Those are mirrored because they are walked *transitively* from a fixed vertex, and a variable-length `MATCH` here can only expand forward. This one is a single hop, always from a known package to its own releases, so the restriction never applies — the constraint shapes the model exactly where it bites and nowhere else.

The blast-radius question is asked two ways against the same model, and both are forward walks over `REQUIRED_BY` from the compromised package.

The primary path is HydraDB's native single-source path procedure, which returns whole paths and so answers the exposure question and supplies the drawing in one round trip:

```cypher
CALL algo.SSpaths({sourceNode: $sourceNode, relTypes: ["REQUIRED_BY"], maxLen: 6, pathCount: 1024})
YIELD path RETURN path
```

The portable fallback is a variable-length traversal, used when the procedure is unavailable or its path cap is reached:

```cypher
MATCH (target:Package {id: <id>})-[:REQUIRED_BY*1..6]->(dependent:Package)
RETURN DISTINCT dependent.name
```

This is the core "why HydraDB" of the project: computing everything transitively exposed by a compromise is a multi-hop graph traversal, not something a vector index or a flat table can answer — and the engine has a purpose-built procedure for exactly that traversal, which is why the answer costs one query rather than ten.

### Why vertex ids are hashed and namespaced

HydraDB keys vertices on `id` alone — **the label does not scope identity**, and labels accumulate. MERGE-ing a `:Package` onto an id already held by a `:Maintainer` silently overwrites that vertex's properties and leaves a single vertex answering to both labels while carrying both sets of edges (verified against the running node). Since `id` must be an integer, names are hashed — and because npm users routinely publish a package under their own handle, maintainer ids are hashed in a **separate namespace** (`maintainerId()` in `src/hydra.js`). Without that, maintainer `ljharb` and a package named `ljharb` would fuse into one vertex with certainty.

`versionId()` needs one thing more, because it hashes **two** variable-length fields rather than one. Any separator character can be smuggled in from either side: with a space, `("a", "b 1.0")` and `("a b", "1.0")` produce the same string and collapse into one vertex. npm's own rules happen to forbid spaces in both names and versions, so real registry data cannot reach that collision — but "safe because of someone else's validation" is a weaker guarantee than the other two ids rest on, and a fused vertex is silent when it happens. A length prefix (`npm-version 2:qs6.9.0`) removes the ambiguity outright: the boundary is stated, not inferred, so no content in either field can imitate it. There is a unit test that constructs the colliding pair and asserts the two ids differ — it failed, and caught this, before the encoding was changed.

### Why the mirrored edge

HydraDB's current MERGE/traversal implementation only expands **forward** from a vertex with a known, fixed `id` — a variable-length `MATCH` into a fixed target (`(a)<-[:DEPENDS_ON*]-(b)` style reverse queries) errors with `variable-length MATCH requires a fixed source id`. Since blast-radius is inherently "who points at X", the dependency edge is mirrored at write time so the traversal can run forward from the known target along `REQUIRED_BY` instead. See `src/hydra.js` and `src/ingest.js` for the full detail — this constraint (and several other Cypher-subset quirks) was found by direct trial against the local dev node; the vertex `id` must also be an integer, so package names are hashed to stable ids (`packageId()` in `src/hydra.js`).

## Setup, step by step

`./setup.sh` above does all of this for you. This section is the manual equivalent, for anyone who wants to see what it does or run the pieces separately. Requires Docker (or a Docker-compatible daemon like [Colima](https://github.com/abiosoft/colima)) and Node.js 18+.

1. Start HydraDB locally:

   ```bash
   mkdir -p hydradb-data/store hydradb-data/cache
   printf '%s\n' 'local-development-token-32-bytes' > hydradb-data/auth-token
   docker run -d --name hydradb --platform linux/amd64 \
     --user "$(id -u):$(id -g)" \
     -p 7687:7687 -p 8443:8443 -p 9090:9090 \
     -v "$PWD/hydradb-data:/data" \
     -e CLOUD_PROVIDER=local \
     -e LOCAL_PATH=/data/store \
     -e GRAPH_NAMESPACE=default \
     -e GRAPH_ID=default \
     -e GRAPH_CELL_ID=cell-0 \
     -e GRAPH_CELLS=cell-0 \
     -e GRAPH_NODE_ID=node-0 \
     -e GRAPH_DATA_CACHE_DIR=/data/cache \
     -e GRAPH_AUTH_TOKEN_FILE=/data/auth-token \
     -e GRAPH_ALLOW_PLAINTEXT=true \
     -e RUST_MIN_STACK=33554432 \
     ghcr.io/hydra-db/hydradb:latest
   ```

2. Ingest a package's dependency tree:

   ```bash
   node src/ingest.js express --depth=3 --max-nodes=150
   ```

3. Query its blast radius, or any package discovered during ingestion:

   ```bash
   node src/blastRadius.js debug
   ```

## Dependencies / data sources

- Package metadata: the public [npm registry](https://registry.npmjs.org) (no auth, no API key).
- Download counts for typosquat confirmation: the public [npm downloads API](https://api.npmjs.org).
- Vulnerability ground truth in the eval: the public [OSV API](https://api.osv.dev), which serves GitHub Advisory Database records.
- **No third-party libraries at all** — ingestion, querying, the HTTP server and the frontend run on Node's built-in `fetch`/`node:http` and vanilla browser JS. There is no build step, no bundler, and no CDN request, and `npm install` is not required (there are no dependencies to install). The only setup is `./setup.sh`, which also starts HydraDB and loads the demo graph — `node src/server.js` on its own needs a HydraDB instance already running with data in it.

## License

MIT — see [LICENSE](LICENSE).
