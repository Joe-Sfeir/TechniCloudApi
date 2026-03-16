import { Router } from 'express';
import type { Request, Response } from 'express';
import type { QueryResult } from 'pg';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';

const router = Router();

// ── Payload shape ─────────────────────────────────────────────────────────────

interface IngestPayload {
  api_key: string;
  device_name: string;
  timestamp: string;
  data: Record<string, unknown>;
}

function validatePayload(body: unknown): body is IngestPayload {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;

  const b = body as Record<string, unknown>;

  if (
    typeof b['api_key'] !== 'string' ||
    b['api_key'].trim().length === 0
  ) return false;

  if (
    typeof b['device_name'] !== 'string' ||
    b['device_name'].trim().length === 0 ||
    b['device_name'].length > 255
  ) return false;

  if (typeof b['timestamp'] !== 'string') return false;

  if (
    !b['data'] ||
    typeof b['data'] !== 'object' ||
    Array.isArray(b['data'])
  ) return false;

  return true;
}

// ── POST /api/ingest ──────────────────────────────────────────────────────────
//
// Machine-facing route — NOT protected by JWT.
// Authentication is performed via the project api_key embedded in the body
// (or optionally the x-api-key header, for devices that can't set a body field).

router.post('/ingest', async (req: Request, res: Response): Promise<void> => {
  // Allow api_key from header as a fallback for constrained devices (e.g. ESP32
  // that can't easily set a JSON body field alongside sensor data)
  const headerKey = req.headers['x-api-key'];
  const bodyWithKey = { ...req.body as Record<string, unknown> };
  if (typeof headerKey === 'string' && !bodyWithKey['api_key']) {
    bodyWithKey['api_key'] = headerKey;
  }

  if (!validatePayload(bodyWithKey)) {
    res.status(400).json({
      error:
        'Invalid payload. Required: api_key (string), device_name (string ≤255), ' +
        'timestamp (ISO 8601), data (object).',
    });
    return;
  }

  const { api_key, device_name, timestamp, data } = bodyWithKey;

  const parsedTimestamp = new Date(timestamp);
  if (isNaN(parsedTimestamp.getTime())) {
    res.status(400).json({ error: 'Invalid timestamp: must be a valid ISO 8601 date string.' });
    return;
  }

  // Resolve api_key → project_id
  const project = await pool.query<{ id: number }>(
    'SELECT id FROM projects WHERE api_key = $1',
    [api_key],
  );

  if ((project.rowCount ?? 0) === 0) {
    res.status(401).json({ error: 'Unauthorized.' });
    return;
  }

  const projectId = project.rows[0]?.id;

  await pool.query(
    `INSERT INTO telemetry (project_id, device_name, timestamp, data)
     VALUES ($1, $2, $3, $4)`,
    [projectId, device_name.trim(), parsedTimestamp, data],
  );

  res.status(200).json({ success: true, message: 'Telemetry ingested.' });
});

// ── GET /api/telemetry/:projectId ─────────────────────────────────────────────
//
// Website-facing route — requires JWT.
// Returns the last 120 rows on initial load, or rows after `?since=<ISO>` for
// incremental polling. Each row flattens the JSONB `data` field so the frontend
// receives { timestamp, device_name, "Voltage L1": 230.5, ... } directly.

router.get('/telemetry/:projectId', requireAuth, async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const userId = res.locals['userId'] as number;
  const role   = res.locals['role']   as string;

  // Access control — MASTER/SUB_MASTER see all; CLIENT only their own projects
  const projectResult = await pool.query<{ id: number; name: string; user_id: number | null }>(
    'SELECT id, name, user_id FROM projects WHERE id = $1',
    [projectId],
  );
  const project = projectResult.rows[0];
  if (!project) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }
  if (role === 'CLIENT' && project.user_id !== userId) {
    res.status(403).json({ error: 'Forbidden.' });
    return;
  }

  const since = req.query['since'] as string | undefined;

  let result: QueryResult<{ device_name: string; timestamp: Date; data: Record<string, unknown> }>;

  if (since) {
    const parsedSince = new Date(since);
    if (isNaN(parsedSince.getTime())) {
      res.status(400).json({ error: 'Invalid since parameter — must be an ISO 8601 date string.' });
      return;
    }
    result = await pool.query(
      `SELECT device_name, timestamp, data
       FROM telemetry
       WHERE project_id = $1 AND timestamp > $2
       ORDER BY timestamp ASC
       LIMIT 500`,
      [projectId, parsedSince],
    );
  } else {
    // Initial load — fetch the most recent 120 rows then re-sort ascending
    // so the chart renders left-to-right chronologically.
    result = await pool.query(
      `SELECT device_name, timestamp, data
       FROM (
         SELECT device_name, timestamp, data
         FROM telemetry
         WHERE project_id = $1
         ORDER BY timestamp DESC
         LIMIT 120
       ) sub
       ORDER BY timestamp ASC`,
      [projectId],
    );
  }

  // Flatten JSONB data fields into each row so the frontend receives
  // { timestamp, device_name, "Voltage L1": 230.5, ... }
  const rows = result.rows.map((r) => ({
    timestamp:   new Date(r.timestamp).toISOString(),
    device_name: r.device_name,
    ...(r.data as Record<string, unknown>),
  }));

  res.status(200).json({ project_name: project.name, rows });
});

export default router;
