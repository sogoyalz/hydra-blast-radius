# Supply Chain Blast Radius

Hack Hydra 2026 submission — Track 2, Option A ("Repos, Dependencies + Code as Graphs").

**The question:** if an npm package is compromised right now, what's exposed? This project builds the npm dependency graph in [HydraDB](https://github.com/hydra-db/hydradb) and answers that with a graph traversal — not a guess, not a vector search.

## Status

Working end-to-end, including the demo UI. Of the six questions the track brief asks a submission to answer when a package is compromised, this answers four:

| Brief's question | Status |
|---|---|
| What is the complete blast radius? | ✅ `src/blastRadius.js` |
| Which services are transitively exposed? | ✅ same traversal, with hop distance |
| Which packages share maintainers with it? | ✅ `src/sharedMaintainers.js` |
| Are there likely typosquats nearby? | ✅ `src/typosquat.js` |
| Which version introduced the vulnerability? | ❌ graph is version-less today |
| Which apps resolved the bad version while live? | ❌ needs lockfile ingestion |

Plus a correctness eval (independently-computed ground truth vs. HydraDB's own traversal, cross-referenced against real OSV advisories) and a zero-dependency API + browser visualization (`node src/server.js`, then `http://127.0.0.1:8787`).

### Running the demo UI

```bash
node src/server.js --port=8787
```

Then open `http://127.0.0.1:8787`, type a package name that's already in the graph (the input autocompletes from `/api/packages`), and click "Compute blast radius". Try `qs` or `debug` after ingesting `webpack` and `express` as below.

**Demo-ready example:** ingesting `webpack` and `express` (`node src/ingest.js webpack --depth=4 --max-nodes=400` then `node src/ingest.js express --depth=5 --max-nodes=300` into the same graph) produces 135 real packages that include [`qs`](https://github.com/advisories?query=qs), which has 7 real GHSA advisories (prototype pollution, DoS). `node src/blastRadius.js qs` correctly returns `body-parser` and `express` as exposed via the real `express -> body-parser -> qs` dependency chain — a genuine incident, not a synthetic example.

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
| `qs` | 2 | 3 | **3** |
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

## Setup

Requires Docker (or a Docker-compatible daemon like [Colima](https://github.com/abiosoft/colima)) and Node.js 18+.

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
- **No third-party libraries at all** — ingestion, querying, the HTTP server and the frontend run on Node's built-in `fetch`/`node:http` and vanilla browser JS. There is no build step, no bundler, and no CDN request, so `git clone` + `node src/server.js` is the whole setup. `npm install` is not required (there are no dependencies to install).

## License

MIT — see [LICENSE](LICENSE).
