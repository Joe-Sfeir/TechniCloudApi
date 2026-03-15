import 'dotenv/config';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { initDb, pool } from './db';
import authRouter    from './routes/auth';
import projectsRouter from './routes/projects';
import ingestRouter  from './routes/ingest';
import adminRouter   from './routes/admin';
import machineRouter from './routes/machine';
import exportRouter  from './routes/export';

// ── Startup guards ────────────────────────────────────────────────────────────

if (!process.env['JWT_SECRET']) {
  throw new Error('JWT_SECRET environment variable is required');
}
if (!process.env['MASTER_KEY']) {
  throw new Error('MASTER_KEY environment variable is required');
}

const app = express();
const PORT = Number(process.env['PORT']) || 8080;

// ── Middleware ────────────────────────────────────────────────────────────────

const ALLOWED_ORIGIN_PATTERNS = [
  /^http:\/\/localhost:5173$/,
  /\.vercel\.app$/,
  /technicatgroup\.com$/,
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGIN_PATTERNS.some((pattern) => pattern.test(origin))) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: origin ${origin} not allowed`));
    }
  },
  credentials: true,
  allowedHeaders: ['Authorization', 'Content-Type', 'x-api-key'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}));

app.use(express.json({ limit: '1mb' }));

// ── Routes ───────────────────────────────────────────────────────────────────

app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok' });
});

app.use('/api/auth',     authRouter);
app.use('/api/projects', projectsRouter);
app.use('/api/admin',    adminRouter);
app.use('/api/export',   exportRouter);
// machine router carries its own express.json({ limit: '5mb' }) for batch ingest
app.use('/api/machine',  machineRouter);
app.use('/api',          ingestRouter);

// ── Global error handler ──────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[error]', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Tier-1 pruning ────────────────────────────────────────────────────────────

async function pruneTier1(): Promise<void> {
  try {
    const result = await pool.query(`
      DELETE FROM telemetry
      WHERE project_id IN (SELECT id FROM projects WHERE tier = 1)
        AND timestamp < NOW() - INTERVAL '2 days'
    `);
    console.log(`[prune] Tier-1 rows deleted: ${result.rowCount ?? 0}`);
  } catch (err) {
    console.error('[prune] Error during tier-1 pruning:', err);
  }
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function start(): Promise<void> {
  await initDb();

  // Run immediately on boot to clear backlog, then every hour
  await pruneTier1();
  setInterval(() => { void pruneTier1(); }, 60 * 60 * 1000);

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] Listening on 0.0.0.0:${PORT}`);
  });

  process.on('SIGTERM', () => {
    console.log('[server] SIGTERM received — draining connections');
    server.close(async () => {
      await pool.end();
      console.log('[server] Shutdown complete');
      process.exit(0);
    });
  });
}

start().catch((err: unknown) => {
  console.error('[server] Failed to start:', err);
  process.exit(1);
});
