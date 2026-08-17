// Zero-dependency HTTP API + static file server for the demo frontend.
// No Express/etc. on purpose: the whole point of this project is showing
// what HydraDB does, so the app layer stays as thin as possible.
//
// Usage: node src/server.js [--port=8787]

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { blastRadiusWithHops } from "./blastRadius.js";
import { findTyposquats } from "./typosquat.js";
import { sharedMaintainerReach } from "./sharedMaintainers.js";
import { analyzeVersions } from "./versions.js";
import { runQuery, runQueryPagedKeyset, packageId, DEFAULT_TIMEOUT_MS } from "./hydra.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const FRONTEND_DIR = join(__dirname, "..", "frontend");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

// Invalidated whenever the ingested package set changes.
let typosquatCache = null; // { key, packageCount, suspects }

// The scan in flight, shared by every request that arrives while it runs.
// Without this the cache only helps AFTER the first scan finishes, so N
// requests landing on a cold cache all start their own scan — and each one
// costs two npm download lookups per candidate. The frontend requests this on
// every page load, so a reload or a couple of open tabs is enough to multiply
// the outbound calls and invite rate limiting for answers that are all
// identical anyway.
let typosquatInFlight = null; // { key, promise }

// Version analysis, cached per package rather than under one global key the
// way the typosquat scan is: that scan is a property of the whole graph, this
// is a property of one package, and two different packages must not evict each
// other. Same in-flight sharing for the same reason — a cold analysis fetches
// a packument (qs's is ~360KB) and writes a MERGE per version, so concurrent
// requests for the same never-analyzed package would otherwise each run the
// whole thing.
const versionCache = new Map(); // package name -> result
const versionInFlight = new Map(); // package name -> promise

function parsePort(argv) {
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "port") {
      const port = Number(value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        console.error(`Invalid --port=${value}; must be an integer 1-65535.`);
        process.exit(1);
      }
      return port;
    }
  }
  return 8787;
}

// Depth reaches HydraDB as the literal N in `REQUIRED_BY*1..N`, so it must be
// a small positive integer: NaN/negative would produce a malformed query, and
// a large value would run an expensive traversal plus that many hop probes.
// Clamp to the same 1..10 range the UI offers.
function parseDepth(raw) {
  const depth = Number(raw);
  if (!Number.isInteger(depth)) return { ok: false };
  return { ok: true, depth: Math.max(1, Math.min(10, depth)) };
}

async function allIngestedPackageNames() {
  // Paged: past 1024 packages an unpaged query silently returns 1024, which
  // would quietly shrink the autocomplete list and, worse, hand the typosquat
  // scan a partial view of the graph it reports as fully scanned. Seek-paged so
  // an ingest running alongside the server cannot shift rows out of the result.
  // Each page is a flat label scan rather than a traversal, so it keeps the
  // short per-query budget. That matters beyond speed: this endpoint has no
  // cheap existence check in front of it the way /api/blast-radius does, so its
  // first page IS the liveness probe — on the traversal budget a wedged
  // container took 60s to produce a 503 instead of 10.
  const rows = await runQueryPagedKeyset(
    "MATCH (p:Package) {{SEEK}} RETURN DISTINCT p.name AS name ORDER BY name",
    "p.name",
    "name",
    undefined,
    500,
    DEFAULT_TIMEOUT_MS
  );
  return rows.map((r) => r.name).filter(Boolean);
}

function sendJson(res, status, body) {
  if (res.headersSent) return; // a partial response already went out; don't double-send
  // No wildcard CORS: this is a localhost demo the co-located UI drives
  // same-origin, so there is no reason to let arbitrary sites a viewer
  // visits reach into their local instance.
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

// Takes the parsed pathname, not the raw req.url: the raw form still
// carries any query string ("/?x=1"), which turns into a bogus filename
// and 404s the index page.
async function serveStatic(pathname, res) {
  let path;
  if (pathname === "/") {
    path = "/index.html";
  } else {
    try {
      path = decodeURIComponent(pathname);
    } catch {
      // decodeURIComponent throws URIError on a malformed escape ("/%",
      // "/%zz"). Letting that reach the generic handler reported a client's
      // bad URL as a 500 *server* error and logged a stack trace for it. A
      // path that cannot be decoded names no file, which is a 404.
      res.writeHead(404);
      res.end("Not found");
      return;
    }
  }
  const filePath = join(FRONTEND_DIR, path);
  // Boundary compare, not a bare prefix: `startsWith(FRONTEND_DIR)` alone would
  // also match a sibling directory like `<repo>/frontend-notes`. Require the
  // resolved path to be FRONTEND_DIR itself or sit under it + a separator.
  if (filePath !== FRONTEND_DIR && !filePath.startsWith(FRONTEND_DIR + sep)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  try {
    const content = await readFile(filePath);
    res.writeHead(200, { "Content-Type": MIME_TYPES[extname(filePath)] ?? "application/octet-stream" });
    res.end(content);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
}

async function handleApi(req, res, url) {
  if (url.pathname === "/api/blast-radius") {
    const name = url.searchParams.get("name");
    if (!name) return sendJson(res, 400, { error: "missing ?name=" });

    const parsed = parseDepth(url.searchParams.get("depth") ?? 6);
    if (!parsed.ok) return sendJson(res, 400, { error: "depth must be an integer 1-10" });
    const depth = parsed.depth;

    const exists = await runQuery(`MATCH (p:Package {id: ${packageId(name)}}) RETURN p.name AS name`);
    if (exists.length === 0) {
      return sendJson(res, 404, { error: `"${name}" is not in the ingested graph` });
    }

    const start = Date.now();
    const result = await blastRadiusWithHops(name, depth);

    // The second attack path: packages reachable through shared publish
    // rights rather than through a dependency edge. Reported alongside the
    // dependency blast radius because the two answers can differ wildly —
    // and the gap is the whole point.
    const { groups, reach } = await sharedMaintainerReach(name);
    const exposedByDeps = new Set(result.nodes.filter((n) => n.hop > 0).map((n) => n.name));
    const reachSet = new Set(reach);
    reachSet.delete(name); // a package is not its own blast radius
    const missedByDeps = [...reachSet].filter((p) => !exposedByDeps.has(p));

    // The two channels are traversed separately because HydraDB's query
    // engine rejects mixing relationship types in one variable-length
    // pattern ("relationship pattern must have exactly one type"). Combining
    // them here is the point: a compromise spreads through code you pull in
    // AND through credentials that can push code to you, and only the union
    // is the honest answer. Set arithmetic over results already fetched — no
    // extra queries, so this costs nothing against the latency figures.
    const viaBoth = [...exposedByDeps].filter((p) => reachSet.has(p));
    const viaDependencyOnly = [...exposedByDeps].filter((p) => !reachSet.has(p));
    const unified = new Set([...exposedByDeps, ...reachSet]);

    // coreQueryMs (the traversal that answers the question) is reported
    // separately from totalMs (which also covers laying out the picture).
    return sendJson(res, 200, {
      ...result,
      maintainers: { groups, reach, missedByDeps },
      unifiedExposure: {
        total: unified.size,
        viaDependencyOnly: viaDependencyOnly.length,
        viaMaintainerOnly: missedByDeps.length,
        viaBoth: viaBoth.length,
      },
      totalMs: Date.now() - start,
    });
  }

  if (url.pathname === "/api/shared-maintainers") {
    const name = url.searchParams.get("name");
    if (!name) return sendJson(res, 400, { error: "missing ?name=" });
    // Same 404-on-unknown behavior as /api/blast-radius, so an empty result
    // means "no shared maintainers", not "package isn't in the graph".
    const exists = await runQuery(`MATCH (p:Package {id: ${packageId(name)}}) RETURN p.name AS name`);
    if (exists.length === 0) {
      return sendJson(res, 404, { error: `"${name}" is not in the ingested graph` });
    }
    return sendJson(res, 200, await sharedMaintainerReach(name));
  }

  if (url.pathname === "/api/typosquat") {
    // The scan hits the npm downloads API once per candidate, so its result
    // is cached. The key is the actual sorted name set, not the count — an
    // ingest that swaps some packages for others (same total) must still
    // invalidate. The frontend requests this on every page load.
    const names = await allIngestedPackageNames();
    const key = names.slice().sort().join("\n");
    if (typosquatCache?.key === key) {
      return sendJson(res, 200, {
        packageCount: typosquatCache.packageCount,
        suspects: typosquatCache.suspects,
      });
    }
    // Start a scan only if one for this exact package set is not already
    // running; otherwise join it. Cleared on settle either way, so a scan that
    // failed (npm unreachable, say) is retried by the next request rather than
    // leaving a rejected promise cached forever.
    if (typosquatInFlight?.key !== key) {
      typosquatInFlight = {
        key,
        promise: findTyposquats(names)
          .then((suspects) => {
            typosquatCache = { key, packageCount: names.length, suspects };
            return typosquatCache;
          })
          .finally(() => {
            if (typosquatInFlight?.key === key) typosquatInFlight = null;
          }),
      };
    }
    const scan = await typosquatInFlight.promise;
    return sendJson(res, 200, { packageCount: scan.packageCount, suspects: scan.suspects });
  }

  if (url.pathname === "/api/versions") {
    const name = url.searchParams.get("name");
    if (!name) return sendJson(res, 400, { error: "missing ?name=" });
    // Gated on the package being in the graph, like every other endpoint. That
    // is also what stops this being used as an open proxy to fetch an
    // arbitrary npm packument through this server.
    const exists = await runQuery(`MATCH (p:Package {id: ${packageId(name)}}) RETURN p.name AS name`);
    if (exists.length === 0) {
      return sendJson(res, 404, { error: `"${name}" is not in the ingested graph` });
    }

    if (versionCache.has(name)) {
      return sendJson(res, 200, versionCache.get(name));
    }
    if (!versionInFlight.has(name)) {
      versionInFlight.set(
        name,
        analyzeVersions(name)
          .then((result) => {
            // Only cache a complete answer. An analysis that could not reach
            // OSV has to be retried on the next request rather than pinning
            // "we don't know" in place for the life of the process — the whole
            // point of distinguishing it from "no advisories" is that it is a
            // transient failure, not a finding.
            if (!result.osvUnavailable) versionCache.set(name, result);
            return result;
          })
          .finally(() => versionInFlight.delete(name))
      );
    }
    return sendJson(res, 200, await versionInFlight.get(name));
  }

  if (url.pathname === "/api/packages") {
    const names = await allIngestedPackageNames();
    return sendJson(res, 200, { names: names.sort() });
  }

  sendJson(res, 404, { error: "unknown endpoint" });
}

const port = parsePort(process.argv.slice(2));
const server = createServer(async (req, res) => {
  try {
    // Inside the try: a malformed Host header makes `new URL` throw, and an
    // uncaught throw in an async request handler takes the whole process down.
    const url = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);

    // Everything here reads; nothing this server exposes creates, changes or
    // deletes anything. The method was simply never inspected, so DELETE and
    // PUT against /api/packages answered 200 as cheerfully as GET — which
    // misrepresents the endpoint as accepting a write it silently ignored, and
    // left TRACE answering too. HEAD is allowed alongside GET because Node
    // suppresses the body for it on its own.
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { "Content-Type": "application/json", Allow: "GET, HEAD" });
      res.end(JSON.stringify({ error: `${req.method} is not supported; this API is read-only` }));
      return;
    }

    if (url.pathname.startsWith("/api/")) {
      await handleApi(req, res, url);
    } else {
      await serveStatic(url.pathname, res);
    }
  } catch (err) {
    // Log the detail server-side; return a generic message so internal errors
    // (including raw HydraDB responses) are never echoed to the client.
    console.error(err);
    // A timed-out HydraDB call (see fetchWithTimeout in hydra.js) is the one
    // case worth naming specifically: it's actionable by the person running
    // the demo ("go check the container"), unlike an arbitrary internal
    // error, and it used to surface as an infinite "Loading..." with no
    // signal at all rather than any response, timed out or otherwise.
    // An error tagged with `upstream` came from a third-party service (the npm
    // registry, OSV), not from the database. This check has to come FIRST:
    // those calls go through the same fetchWithTimeout, so their failures also
    // say "timed out", and the HydraDB branch below would confidently tell
    // someone to go restart a container that is working perfectly. Naming the
    // service that actually failed is the difference between a useful error
    // and a wild goose chase mid-demo.
    if (err.upstream) {
      sendJson(res, 503, {
        error: `${err.upstream} isn't responding, so this couldn't be checked. HydraDB itself is fine.`,
        upstream: err.upstream,
      });
    } else if (err.message?.includes("timed out")) {
      sendJson(res, 503, { error: "HydraDB isn't responding — check that the container is running and healthy." });
    } else {
      sendJson(res, 500, { error: "internal server error" });
    }
  }
});

// The same entry-point guard every other CLI file here carries. Without it,
// importing this module to reach a helper binds the port as a side effect —
// which happened while testing, producing an EADDRINUSE from an import that
// was never meant to start anything. Running it directly is unaffected:
// setup.sh's `exec node src/server.js` still matches.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  server.listen(port, () => {
    console.log(`Blast radius demo running at http://127.0.0.1:${port}`);
  });
}
