// Zero-dependency HTTP API + static file server for the demo frontend.
// No Express/etc. on purpose: the whole point of this project is showing
// what HydraDB does, so the app layer stays as thin as possible.
//
// Usage: node src/server.js [--port=8787]

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { blastRadiusWithHops } from "./blastRadius.js";
import { findTyposquats } from "./typosquat.js";
import { runQuery, packageId } from "./hydra.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const FRONTEND_DIR = join(__dirname, "..", "frontend");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

// Invalidated whenever the ingested package count changes.
let typosquatCache = null;

function parsePort(argv) {
  for (const arg of argv) {
    const [key, value] = arg.replace(/^--/, "").split("=");
    if (key === "port") return Number(value);
  }
  return 8787;
}

async function allIngestedPackageNames() {
  const rows = await runQuery("MATCH (p:Package) RETURN DISTINCT p.name AS name");
  return rows.map((r) => r.name).filter(Boolean);
}

function sendJson(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
  res.end(JSON.stringify(body));
}

// Takes the parsed pathname, not the raw req.url: the raw form still
// carries any query string ("/?x=1"), which turns into a bogus filename
// and 404s the index page.
async function serveStatic(pathname, res) {
  const path = pathname === "/" ? "/index.html" : decodeURIComponent(pathname);
  const filePath = join(FRONTEND_DIR, path);
  if (!filePath.startsWith(FRONTEND_DIR)) {
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
    const depth = Number(url.searchParams.get("depth") ?? 6);
    if (!name) return sendJson(res, 400, { error: "missing ?name=" });

    const exists = await runQuery(`MATCH (p:Package {id: ${packageId(name)}}) RETURN p.name AS name`);
    if (exists.length === 0) {
      return sendJson(res, 404, { error: `"${name}" is not in the ingested graph` });
    }

    const start = Date.now();
    const result = await blastRadiusWithHops(name, depth);
    // coreQueryMs (the traversal that answers the question) is reported
    // separately from totalMs (which also covers laying out the picture).
    return sendJson(res, 200, { ...result, totalMs: Date.now() - start });
  }

  if (url.pathname === "/api/typosquat") {
    // The scan hits the npm downloads API once per candidate, so its result
    // is cached: it only changes when the ingested package set changes, and
    // the frontend requests it on every page load.
    const names = await allIngestedPackageNames();
    if (!typosquatCache || typosquatCache.packageCount !== names.length) {
      typosquatCache = { packageCount: names.length, suspects: await findTyposquats(names) };
    }
    return sendJson(res, 200, typosquatCache);
  }

  if (url.pathname === "/api/packages") {
    const names = await allIngestedPackageNames();
    return sendJson(res, 200, { names: names.sort() });
  }

  sendJson(res, 404, { error: "unknown endpoint" });
}

const port = parsePort(process.argv.slice(2));
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (url.pathname.startsWith("/api/")) {
      await handleApi(req, res, url);
    } else {
      await serveStatic(url.pathname, res);
    }
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { error: err.message });
  }
});

server.listen(port, () => {
  console.log(`Blast radius demo running at http://127.0.0.1:${port}`);
});
