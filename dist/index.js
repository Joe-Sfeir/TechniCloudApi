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
const machine_1 = __importDefault(require("./routes/machine"));
const export_1 = __importDefault(require("./routes/export"));
// ── Startup guards ────────────────────────────────────────────────────────────
if (!process.env['JWT_SECRET']) {
    throw new Error('JWT_SECRET environment variable is required');
}
if (!process.env['MASTER_KEY']) {
    throw new Error('MASTER_KEY environment variable is required');
}
const app = (0, express_1.default)();
const PORT = Number(process.env['PORT']) || 8080;
// ── Middleware ────────────────────────────────────────────────────────────────
const ALLOWED_ORIGIN_PATTERNS = [
    /^http:\/\/localhost:5173$/,
    /\.vercel\.app$/,
    /technicatgroup\.com$/,
];
app.use((0, cors_1.default)({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGIN_PATTERNS.some((pattern) => pattern.test(origin))) {
            callback(null, true);
        }
        else {
            callback(new Error(`CORS: origin ${origin} not allowed`));
        }
    },
    credentials: true,
    allowedHeaders: ['Authorization', 'Content-Type', 'x-api-key'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}));
app.use(express_1.default.json({ limit: '1mb' }));
// ── Routes ───────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
});
app.use('/api/auth', auth_1.default);
app.use('/api/projects', projects_1.default);
app.use('/api/admin', admin_1.default);
app.use('/api/export', export_1.default);
// machine router carries its own express.json({ limit: '5mb' }) for batch ingest
app.use('/api/machine', machine_1.default);
app.use('/api', ingest_1.default);
// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err, _req, res, _next) => {
    console.error('[error]', err);
    res.status(500).json({ error: 'Internal server error.' });
});
// ── Tier-1 pruning ────────────────────────────────────────────────────────────
async function pruneTier1() {
    try {
        const result = await db_1.pool.query(`
      DELETE FROM telemetry
      WHERE project_id IN (SELECT id FROM projects WHERE tier = 1)
        AND timestamp < NOW() - INTERVAL '2 days'
    `);
        console.log(`[prune] Tier-1 rows deleted: ${result.rowCount ?? 0}`);
    }
    catch (err) {
        console.error('[prune] Error during tier-1 pruning:', err);
    }
}
// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function start() {
    await (0, db_1.initDb)();
    // Run immediately on boot to clear backlog, then every hour
    await pruneTier1();
    setInterval(() => { void pruneTier1(); }, 60 * 60 * 1000);
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`[server] Listening on 0.0.0.0:${PORT}`);
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