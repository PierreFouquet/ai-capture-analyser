// Minimal static file server for Playwright E2E runs.
//
// Serves the real frontend in ./public so the browser exercises the actual
// modules (file <input> upload, in-browser PCAP parsing, Chart.js, jsPDF). The
// backend /api/* calls are mocked per-test via Playwright route interception, so
// no Worker/Workers AI is needed. Deliberately dependency-free (node:http only).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { extname, normalize, join } from 'node:path';

const PUBLIC_DIR = fileURLToPath(new URL('../../public/', import.meta.url));
const PORT = Number(process.env.E2E_PORT) || 4321;

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.ico': 'image/x-icon',
    '.pcap': 'application/octet-stream',
};

const server = createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://localhost:${PORT}`);
        let pathname = decodeURIComponent(url.pathname);
        if (pathname === '/') pathname = '/index.html';
        // Resolve within PUBLIC_DIR and reject path traversal.
        const filePath = normalize(join(PUBLIC_DIR, pathname));
        if (!filePath.startsWith(PUBLIC_DIR)) {
            res.writeHead(403).end('Forbidden');
            return;
        }
        const body = await readFile(filePath);
        res.writeHead(200, { 'Content-Type': MIME[extname(filePath)] || 'application/octet-stream' });
        res.end(body);
    } catch {
        res.writeHead(404).end('Not Found');
    }
});

server.listen(PORT, () => {
    console.log(`E2E static server listening on http://localhost:${PORT}`);
});
