# Supply Chain Blast Radius

Hack Hydra 2026 submission — Track 2, Option A ("Repos, Dependencies + Code as Graphs").

**The question:** if an npm package is compromised right now, what's exposed? This project builds the npm dependency graph in [HydraDB](https://github.com/hydra-db/hydradb) and answers that with a graph traversal — not a guess, not a vector search.

## Status

Working end-to-end: npm registry ingestion into HydraDB, blast-radius queries, a correctness eval (independently-computed ground truth vs. HydraDB's own traversal, cross-referenced against real OSV advisories), and typosquat detection (edit distance + live npm download-count confirmation, validated against real near-miss packages on the registry). Still to come: the API/frontend layer and scaling ingestion to a larger real-world graph.

### Typosquat detection

`node src/typosquat.js` scans every package name currently in the graph, flags anything within edit distance 2 of a popular reference package (`src/typosquat.js`'s `POPULAR_PACKAGES`), and confirms suspicion using live npm weekly download counts — a genuine typosquat has far fewer downloads than the package it resembles. This is deliberately two-signal: edit distance alone produces false positives (e.g. `isarray` is a real, independently popular package one edit from `is-array`, with *more* downloads — the download ratio correctly reclassifies this as "likely coincidence" rather than flagging it).

## How HydraDB is used

Every package is a `Package` vertex; every dependency relationship is written as **two** mirrored edges:

- `(dependent)-[:DEPENDS_ON]->(dependency)` — the natural direction
- `(dependency)-[:REQUIRED_BY]->(dependent)` — the reverse, written at ingest time

The blast-radius query is a variable-length forward traversal over `REQUIRED_BY` starting from the compromised package:

```cypher
MATCH (target:Package {id: <id>})-[:REQUIRED_BY*1..6]->(dependent:Package)
RETURN DISTINCT dependent.name
```

This is the core "why HydraDB" of the project: computing everything transitively exposed by a compromise is a multi-hop graph traversal, not something a vector index or a flat table can answer.

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
- No third-party libraries are used yet — ingestion and querying run on Node's built-in `fetch`.

## License

MIT — see [LICENSE](LICENSE).
