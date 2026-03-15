"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const db_1 = require("./db");
const auth_1 = __importDefault(require("./routes/auth"));
const projects_1 = __importDefault(require("./routes/projects"));
const ingest_1 = __importDefault(require("./routes/ingest"));
const admin_1 = __importDefault(require("./routes/admin"));
// ── Startup guards ────────────────────────────────────────────────────────────
// Fail immediately if required secrets are absent — better to crash at boot
// than to serve requests with broken auth or licensing.
if (!process.env['JWT_SECRET']) {
    throw new Error('JWT_SECRET environment variable is required');
}
if (!process.env['MASTER_KEY']) {
    throw new Error('MASTER_KEY environment variable is required');
}
const app = (0, express_1.default)();
const PORT = Number(process.env['PORT']) || 8080;
// ── Middleware ────────────────────────────────────────────────────────────────
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: '1mb' }));
// ── Routes ───────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
});
app.use('/api/auth', auth_1.default);
app.use('/api/projects', projects_1.default);
app.use('/api/admin', admin_1.default);
app.use('/api', ingest_1.default);
// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err, _req, res, _next) => {
    console.error('[error]', err);
    res.status(500).json({ error: 'Internal server error.' });
});
// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function start() {
    await (0, db_1.initDb)();
    const server = app.listen(PORT, () => {
        console.log(`[server] Listening on port ${PORT}`);
    });
    process.on('SIGTERM', () => {
        console.log('[server] SIGTERM received — draining connections');
        server.close(async () => {
            await db_1.pool.end();
            console.log('[server] Shutdown complete');
            process.exit(0);
        });
    });
}
start().catch((err) => {
    console.error('[server] Failed to start:', err);
    process.exit(1);
});
//# sourceMappingURL=index.js.map