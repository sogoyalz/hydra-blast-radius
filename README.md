# Supply Chain Blast Radius

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

**Why a graph database rather than a table or a vector index.** The dependency answer is a transitive closure of unbounded depth — a self-join repeated until fixpoint in SQL, one traversal here. The publish-rights answer is a two-hop walk *across two different edge types* (`MAINTAINED_BY` then `MAINTAINS`). Neither is a similarity question, so an embedding index cannot answer either one: "which packages are semantically similar to `qs`" is not "which packages break when `qs` breaks."

**Engaging with the engine's real limits.** Three constraints were found by direct testing against the running node, and each one visibly shaped the design rather than being worked around silently:

- Variable-length `MATCH` only expands **forward from a fixed source id**, so "who depends on X" is impossible as a reverse query. A mirrored `REQUIRED_BY` edge is written at ingest time so the question becomes a forward traversal. ([why](#why-the-mirrored-edge))
- Vertex identity is the integer `id` **alone — labels do not scope it**, and they accumulate. Hashing maintainer names in the same space as package names would have silently fused maintainer `ljharb` with a package named `ljharb`. Ids are namespaced per type. ([why](#why-vertex-ids-are-hashed-and-namespaced))
- A relationship pattern may name **exactly one type** — `[:REQUIRED_BY|MAINTAINS*1..3]` is rejected outright. So the two channels genuinely cannot be walked in one traversal; they are queried separately and unioned in `src/server.js`. That is a design consequence, not a shortcut.

**Proof it's correct, not just fast.** `src/eval.js` computes the blast radius independently by BFS over the raw edge list in memory, with no HydraDB involved, then asks HydraDB the same question and diffs the two sets: **1.00 precision and 1.00 recall** on every target. ([details](#correctness-eval))

**And the graph shows its work.** Click any node and the exact chain that exposes it lights up — `debug → send → serve-static` — reconstructed from the edges the traversal already returned. For a package reachable only through credentials, it says so explicitly and names the maintainer who connects them. Membership is the weak claim; the path is the evidence.

## Quick start

```bash
./setup.sh
```

That's the whole setup. It starts HydraDB, waits for it to accept queries, ingests a real npm dependency graph from the public registry, and serves the UI at `http://127.0.0.1:8787`. **Cold start to working UI is about 25 seconds**; re-running reuses what's already there and comes up in ~2s. Requires Docker and Node 18+ — the script checks both and tells you exactly what to do if either is missing. `./setup.sh --fresh` wipes the database and starts over.

Once it's up, try **`body-parser`**: one package exposed through dependencies, ~36 through shared publish rights. That gap is the point of the project.

## Status

Working end-to-end, including the demo UI. Of the six questions the track brief asks a submission to answer when a package is compromised, this answers four:

| Brief's question | Status |
|---|---|
| What is the complete blast radius? | ✅ `src/blastRadius.js` |
| Which services are transitively exposed? | ✅ `src/blastRadius.js`, reported with hop distance |
| Which packages share maintainers with it? | ✅ `src/sharedMaintainers.js` |
| Are there likely typosquats nearby? | ✅ `src/typosquat.js` |
| Which version introduced the vulnerability? | ❌ graph is version-less today |
| Which apps resolved the bad version while live? | ❌ needs lockfile ingestion |

Plus a correctness eval (independently-computed ground truth vs. HydraDB's own traversal, cross-referenced against real OSV advisories) and a zero-dependency API + browser visualization (`node src/server.js`, then `http://127.0.0.1:8787`).

### Running the demo UI

```bash
node src/server.js --port=8787
```

Then open `http://127.0.0.1:8787`, type a package name that's already in the graph (the input autocompletes from `/api/packages`), and click "Compute blast radius". Try `body-parser`, `qs`, or `debug`.

**Then click a node.** The graph traces the exact chain that exposes it — for `debug`, clicking `serve-static` lights up `debug → send → serve-static` and spells the path out in the sidebar. Clicking a package that's only reachable through shared credentials says so, and names the maintainer who links them. The path is reconstructed from the edges the blast-radius query already returned, so tracing costs no additional query.

**Demo-ready example:** `./setup.sh` ingests `express --depth=4 --max-nodes=250` and `webpack --depth=3 --max-nodes=150` into one graph — **119 real packages**, including [`qs`](https://github.com/advisories?query=qs), which has 7 real GHSA advisories (prototype pollution, DoS). `node src/blastRadius.js qs` correctly returns `body-parser` and `express` as exposed, via the real `express -> body-parser -> qs` dependency chain — a genuine incident, not a synthetic example.

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

The gap between the two answers is the point. On the `express` graph:

| Package | Exposed via dependencies | Reachable via shared publish rights | **Missed by dependencies alone** |
|---|---|---|---|
| `qs` | 2 | 8 | **8** |
| `debug` | 6 | 1 | **1** |
| `body-parser` | 1 | 36 | **35** |

`body-parser` looks almost harmless through a dependency lens — one exposed package. Widen to publish rights and 35 further packages come into range of the same credentials. The UI reports both side by side for exactly this reason.

> Note: this models *blast radius*, not wrongdoing. These are the legitimate maintainers of widely-used packages; the point is that their credentials are a high-value target, which is what makes the exposure worth measuring.

### Correctness eval

```bash
node src/eval.js koa --depth=3 --max-nodes=200
```

The track brief scores on precision, recall, query latency and cost against OSV / GitHub Advisory ground truth. Since the organizers' held-out harness isn't available to entrants, `src/eval.js` builds the strongest self-check available: it crawls a dependency tree, computes the blast radius **independently** by BFS over the raw edge list in memory (no HydraDB involved), then asks HydraDB's `REQUIRED_BY` traversal the same question and compares the two sets — reporting precision, recall, F1 and per-query latency, with each target cross-referenced against its real OSV advisory count.

The two methods should agree exactly; they currently do, at **1.00 precision and 1.00 recall** on every target, with traversals answering in 12–43ms:

```
target               truth   hydra   P      R      F1     ms     OSV advisories
mime-types           3       3       1.00   1.00   1.00   43     0
statuses             3       3       1.00   1.00   1.00   15     0
http-errors          2       2       1.00   1.00   1.00   12     0
content-type         2       2       1.00   1.00   1.00   13     0
depd                 4       4       1.00   1.00   1.00   14     0
```

Run it against a **freshly reset** database: HydraDB accumulates everything previously ingested (correct behavior for a real ecosystem graph — more history means more complete answers), but the in-memory ground truth only knows the current crawl, so extra correct matches from earlier ingests would read as false precision loss.

### On the latency numbers

The UI reports two figures, deliberately kept apart. **`coreQueryMs`** is the single variable-length traversal that actually answers "what is exposed" — typically 12–60ms, and the only number that should be read as HydraDB's query speed. **`totalMs`** additionally covers the hop-distance probes and per-package edge lookups that exist *only to draw the radial graph*; those are fanned out concurrently and adaptively (probing stops as soon as every exposed package has a hop assigned), but they are presentation cost, not query cost, and are labelled as such rather than folded into a single flattering number.

### Typosquat detection

`node src/typosquat.js` scans every package name currently in the graph, flags anything within edit distance 2 of a popular reference package (`src/typosquat.js`'s `POPULAR_PACKAGES`), and confirms suspicion using live npm weekly download counts — a genuine typosquat has far fewer downloads than the package it resembles. This is deliberately two-signal: edit distance alone produces false positives (e.g. `isarray` is a real, independently popular package one edit from `is-array`, with *more* downloads — the download ratio correctly reclassifies this as "likely coincidence" rather than flagging it).

## How HydraDB is used

The graph has two vertex types and four edge types:

- `(dependent:Package)-[:DEPENDS_ON]->(dependency:Package)` — the natural direction
- `(dependency)-[:REQUIRED_BY]->(dependent)` — the reverse, written at ingest time
- `(package)-[:MAINTAINED_BY]->(maintainer:Maintainer)` — publish rights
- `(maintainer)-[:MAINTAINS]->(package)` — the reverse, likewise

The blast-radius query is a variable-length forward traversal over `REQUIRED_BY` starting from the compromised package:

```cypher
MATCH (target:Package {id: <id>})-[:REQUIRED_BY*1..6]->(dependent:Package)
RETURN DISTINCT dependent.name
```

This is the core "why HydraDB" of the project: computing everything transitively exposed by a compromise is a multi-hop graph traversal, not something a vector index or a flat table can answer.

### Why vertex ids are hashed and namespaced

HydraDB keys vertices on `id` alone — **the label does not scope identity**, and labels accumulate. MERGE-ing a `:Package` onto an id already held by a `:Maintainer` silently overwrites that vertex's properties and leaves a single vertex answering to both labels while carrying both sets of edges (verified against the running node). Since `id` must be an integer, names are hashed — and because npm users routinely publish a package under their own handle, maintainer ids are hashed in a **separate namespace** (`maintainerId()` in `src/hydra.js`). Without that, maintainer `ljharb` and a package named `ljharb` would fuse into one vertex with certainty.

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
