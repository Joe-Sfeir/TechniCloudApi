import { Router } from 'express';
import type { Request, Response } from 'express';
import { randomBytes } from 'crypto';
import { pool } from '../db';
import { requireAuth, requireRole } from '../middleware/auth';

const router = Router();

router.use(requireAuth, requireRole('MASTER', 'SUB_MASTER'));

const ONLINE_WINDOW_MS = 5 * 60 * 1000;

// ── POST /api/admin/online-projects ──────────────────────────────────────────

router.post('/online-projects', async (req: Request, res: Response): Promise<void> => {
  const { name, tier, max_activations, duration_days, allowed_meters, protocols, notes } =
    req.body as Record<string, unknown>;

  if (typeof name !== 'string' || name.trim().length === 0 || name.length > 255) {
    res.status(400).json({ error: 'name is required and must be ≤255 characters.' });
    return;
  }

  if (tier !== 1 && tier !== 2 && tier !== 3) {
    res.status(400).json({ error: 'tier must be 1, 2, or 3.' });
    return;
  }

  if (!Number.isInteger(max_activations) || (max_activations as number) < 1) {
    res.status(400).json({ error: 'max_activations must be a positive integer.' });
    return;
  }

  if (!Number.isInteger(duration_days) || (duration_days as number) <= 0) {
    res.status(400).json({ error: 'duration_days must be a positive integer.' });
    return;
  }

  if (!Array.isArray(allowed_meters)) {
    res.status(400).json({ error: 'allowed_meters must be an array.' });
    return;
  }

  if (protocols !== 'RTU' && protocols !== 'TCP' && protocols !== 'All') {
    res.status(400).json({ error: 'protocols must be "RTU", "TCP", or "All".' });
    return;
  }

  if (notes !== undefined && typeof notes !== 'string') {
    res.status(400).json({ error: 'notes must be a string.' });
    return;
  }

  const project_key = `TDAQ-PRJ-${randomBytes(20).toString('hex')}`;
  const api_key     = `TDAQ-${randomBytes(20).toString('hex')}`;

  const result = await pool.query<{
    id: number;
    name: string;
    project_key: string;
    tier: number;
    max_activations: number;
    duration_days: number;
    expires_at: Date;
    allowed_meters: unknown[];
    protocols: string;
    is_active: boolean;
  }>(
    `INSERT INTO projects
       (name, tier, api_key, project_key, max_activations, duration_days, expires_at,
        allowed_meters, protocols, notes)
     VALUES ($1, $2, $3, $4, $5, $6, NOW() + $7 * INTERVAL '1 day',
             $8, $9, $10)
     RETURNING id, name, project_key, tier, max_activations, duration_days,
               expires_at, allowed_meters, protocols, is_active`,
    [
      name.trim(), tier, api_key, project_key, max_activations, duration_days, duration_days,
      JSON.stringify(allowed_meters), protocols, notes ?? '',
    ],
  );

  res.status(201).json(result.rows[0]);
});

// ── GET /api/admin/online-projects ───────────────────────────────────────────

router.get('/online-projects', async (_req: Request, res: Response): Promise<void> => {
  const result = await pool.query<{
    id: number;
    name: string;
    project_key: string;
    tier: number;
    max_activations: number;
    duration_days: number | null;
    expires_at: Date | null;
    is_active: boolean;
    allowed_meters: unknown[];
    protocols: string;
    notes: string;
    created_at: Date;
    activation_count: number;
    nodes: { machine_id: string; node_name: string; last_seen: Date | null; is_active: boolean; polling_state: string }[];
    clients: { id: number; email: string }[];
    last_seen: Date | null;
  }>(
    `SELECT p.id, p.name, p.project_key, p.tier, p.max_activations, p.duration_days,
            p.expires_at, p.is_active, p.allowed_meters, p.protocols, p.notes, p.created_at,
            COUNT(pa.id)::int AS activation_count,
            COALESCE(
              json_agg(
                json_build_object(
                  'machine_id',    pa.machine_id,
                  'node_name',     pa.node_name,
                  'last_seen',     pa.last_seen,
                  'is_active',     pa.is_active,
                  'polling_state', pa.polling_state
                ) ORDER BY pa.activated_at
              ) FILTER (WHERE pa.id IS NOT NULL),
              '[]'::json
            ) AS nodes,
            COALESCE(
              (SELECT json_agg(json_build_object('id', u.id, 'email', u.email) ORDER BY pas.assigned_at)
               FROM project_assignments pas
               JOIN users u ON u.id = pas.user_id
               WHERE pas.project_id = p.id),
              '[]'::json
            ) AS clients,
            MAX(pa.last_seen) AS last_seen
     FROM projects p
     LEFT JOIN project_activations pa ON pa.project_id = p.id
     WHERE p.project_key IS NOT NULL
     GROUP BY p.id
     ORDER BY p.created_at DESC`,
  );

  const now = Date.now();
  const projects = result.rows.map((row) => {
    let status: 'ONLINE' | 'OFFLINE' | 'NEVER';
    if (!row.last_seen) {
      status = 'NEVER';
    } else if (now - new Date(row.last_seen).getTime() <= ONLINE_WINDOW_MS) {
      status = 'ONLINE';
    } else {
      status = 'OFFLINE';
    }
    return { ...row, status };
  });

  res.status(200).json(projects);
});

// ── GET /api/admin/online-projects/:projectId ─────────────────────────────────

router.get('/online-projects/:projectId', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const projectResult = await pool.query<{
    id: number; name: string; project_key: string; tier: number;
    max_activations: number; duration_days: number | null; expires_at: Date | null;
    is_active: boolean; allowed_meters: unknown[]; protocols: string; notes: string; created_at: Date;
  }>(
    `SELECT id, name, project_key, tier, max_activations, duration_days, expires_at,
            is_active, allowed_meters, protocols, notes, created_at
     FROM projects WHERE id = $1 AND project_key IS NOT NULL`,
    [projectId],
  );

  if ((projectResult.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const [activationsResult, clientsResult, configsResult] = await Promise.all([
    pool.query<{ id: number; machine_id: string; node_name: string; activated_at: Date; last_seen: Date | null; is_active: boolean }>(
      `SELECT id, machine_id, node_name, activated_at, last_seen, is_active
       FROM project_activations WHERE project_id = $1 ORDER BY activated_at`,
      [projectId],
    ),
    pool.query<{ id: number; email: string }>(
      `SELECT u.id, u.email FROM project_assignments pa
       JOIN users u ON u.id = pa.user_id WHERE pa.project_id = $1 ORDER BY pa.assigned_at`,
      [projectId],
    ),
    pool.query<{ id: number; machine_id: string; config_version: number; desired_config: unknown; current_config: unknown; status: string; updated_at: Date }>(
      `SELECT id, machine_id, config_version, desired_config, current_config, status, updated_at
       FROM project_configs WHERE project_id = $1 ORDER BY updated_at DESC`,
      [projectId],
    ),
  ]);

  res.status(200).json({
    ...projectResult.rows[0],
    activations: activationsResult.rows,
    clients:     clientsResult.rows,
    configs:     configsResult.rows,
  });
});

// ── PATCH /api/admin/online-projects/:projectId ───────────────────────────────

router.patch('/online-projects/:projectId', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const body = req.body as Record<string, unknown>;
  const allowed = ['name', 'tier', 'max_activations', 'duration_days', 'allowed_meters', 'protocols', 'notes', 'is_active'];
  const setClauses: string[] = [];
  const params: unknown[] = [];

  for (const field of allowed) {
    if (!(field in body)) continue;
    const val = body[field];

    if (field === 'name') {
      if (typeof val !== 'string' || val.trim().length === 0 || val.length > 255) {
        res.status(400).json({ error: 'name must be a non-empty string ≤255 characters.' });
        return;
      }
      params.push((val as string).trim());
      setClauses.push(`name = $${params.length}`);
    } else if (field === 'tier') {
      if (val !== 1 && val !== 2 && val !== 3) {
        res.status(400).json({ error: 'tier must be 1, 2, or 3.' });
        return;
      }
      params.push(val);
      setClauses.push(`tier = $${params.length}`);
    } else if (field === 'max_activations') {
      if (!Number.isInteger(val) || (val as number) < 1) {
        res.status(400).json({ error: 'max_activations must be a positive integer.' });
        return;
      }
      params.push(val);
      setClauses.push(`max_activations = $${params.length}`);
    } else if (field === 'duration_days') {
      if (!Number.isInteger(val) || (val as number) <= 0) {
        res.status(400).json({ error: 'duration_days must be a positive integer.' });
        return;
      }
      params.push(val);
      setClauses.push(`duration_days = $${params.length}`);
      params.push(val);
      setClauses.push(`expires_at = NOW() + $${params.length} * INTERVAL '1 day'`);
    } else if (field === 'allowed_meters') {
      if (!Array.isArray(val)) {
        res.status(400).json({ error: 'allowed_meters must be an array.' });
        return;
      }
      params.push(JSON.stringify(val));
      setClauses.push(`allowed_meters = $${params.length}`);
    } else if (field === 'protocols') {
      if (val !== 'RTU' && val !== 'TCP' && val !== 'All') {
        res.status(400).json({ error: 'protocols must be "RTU", "TCP", or "All".' });
        return;
      }
      params.push(val);
      setClauses.push(`protocols = $${params.length}`);
    } else if (field === 'notes') {
      if (typeof val !== 'string') {
        res.status(400).json({ error: 'notes must be a string.' });
        return;
      }
      params.push(val);
      setClauses.push(`notes = $${params.length}`);
    } else if (field === 'is_active') {
      if (typeof val !== 'boolean') {
        res.status(400).json({ error: 'is_active must be a boolean.' });
        return;
      }
      params.push(val);
      setClauses.push(`is_active = $${params.length}`);
    }
  }

  if (setClauses.length === 0) {
    res.status(400).json({ error: 'No valid fields provided to update.' });
    return;
  }

  params.push(projectId);
  const result = await pool.query<{
    id: number; name: string; project_key: string; tier: number; max_activations: number;
    duration_days: number | null; expires_at: Date | null; is_active: boolean;
    allowed_meters: unknown[]; protocols: string; notes: string;
  }>(
    `UPDATE projects SET ${setClauses.join(', ')}
     WHERE id = $${params.length} AND project_key IS NOT NULL
     RETURNING id, name, project_key, tier, max_activations, duration_days,
               expires_at, is_active, allowed_meters, protocols, notes`,
    params,
  );

  if ((result.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  // Deactivate all activations if project is being deactivated
  if (body['is_active'] === false) {
    await pool.query(
      `UPDATE project_activations SET is_active = false WHERE project_id = $1`,
      [projectId],
    );
  }

  // Notify live nodes when settings that affect desktop behaviour change
  const settingsChanged = ['allowed_meters', 'protocols', 'tier'].some((f) => f in body);
  if (settingsChanged) {
    await pool.query(
      `UPDATE project_activations SET config_pending = true WHERE project_id = $1 AND is_active = true`,
      [projectId],
    );
  }

  res.status(200).json(result.rows[0]);
});

// ── POST /api/admin/online-projects/:projectId/renew ─────────────────────────

router.post('/online-projects/:projectId/renew', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const { duration_days } = req.body as Record<string, unknown>;

  if (!Number.isInteger(duration_days) || (duration_days as number) <= 0) {
    res.status(400).json({ error: 'duration_days must be a positive integer.' });
    return;
  }

  const result = await pool.query<{
    id: number; name: string; project_key: string; tier: number; max_activations: number;
    duration_days: number | null; expires_at: Date; is_active: boolean;
    allowed_meters: unknown[]; protocols: string; notes: string;
  }>(
    `UPDATE projects
     SET expires_at = NOW() + $2 * INTERVAL '1 day', duration_days = $2, is_active = true
     WHERE id = $1 AND project_key IS NOT NULL
     RETURNING id, name, project_key, tier, max_activations, duration_days,
               expires_at, is_active, allowed_meters, protocols, notes`,
    [projectId, duration_days],
  );

  if ((result.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  res.status(200).json(result.rows[0]);
});

// ── POST /api/admin/online-projects/:projectId/push-config ───────────────────

router.post('/online-projects/:projectId/push-config', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const body = req.body as Record<string, unknown>;
  const { machine_id, config } = body;

  if (typeof machine_id !== 'string' || machine_id.trim().length === 0) {
    res.status(400).json({ error: 'machine_id is required.' });
    return;
  }

  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    res.status(400).json({ error: 'config must be an object.' });
    return;
  }

  const trimmedMachineId = machine_id.trim();

  // Verify the activation exists
  const activationCheck = await pool.query<{ id: number }>(
    `SELECT id FROM project_activations WHERE project_id = $1 AND machine_id = $2`,
    [projectId, trimmedMachineId],
  );

  if ((activationCheck.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Activation not found.' });
    return;
  }

  // Determine next config version
  const versionResult = await pool.query<{ max_version: number | null }>(
    `SELECT MAX(config_version) AS max_version FROM project_configs WHERE project_id = $1 AND machine_id = $2`,
    [projectId, trimmedMachineId],
  );
  const nextVersion = (versionResult.rows[0]?.max_version ?? 0) + 1;

  await pool.query(
    `INSERT INTO project_configs (project_id, machine_id, config_version, desired_config, status)
     VALUES ($1, $2, $3, $4, 'pending')`,
    [projectId, trimmedMachineId, nextVersion, JSON.stringify(config)],
  );

  await pool.query(
    `UPDATE project_activations SET config_pending = true WHERE project_id = $1 AND machine_id = $2`,
    [projectId, trimmedMachineId],
  );

  res.status(200).json({ message: 'Config queued for delivery.', config_version: nextVersion });
});

// ── DELETE /api/admin/online-projects/:projectId ──────────────────────────────

router.delete('/online-projects/:projectId', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const { confirm } = req.body as Record<string, unknown>;
  if (confirm !== true) {
    res.status(400).json({ error: 'Confirmation required.' });
    return;
  }

  const result = await pool.query(
    `DELETE FROM projects WHERE id = $1 AND project_key IS NOT NULL`,
    [projectId],
  );

  if ((result.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  res.status(200).json({ message: 'Project deleted.' });
});

// ── DELETE /api/admin/online-projects/:projectId/telemetry ────────────────────

router.delete('/online-projects/:projectId/telemetry', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const check = await pool.query<{ id: number }>(
    'SELECT id FROM projects WHERE id = $1 AND project_key IS NOT NULL',
    [projectId],
  );
  if ((check.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const result = await pool.query(
    'DELETE FROM telemetry WHERE project_id = $1',
    [projectId],
  );

  res.status(200).json({ message: 'Telemetry cleared.', deleted: result.rowCount ?? 0 });
});

// ── GET /api/admin/online-projects/:projectId/activations ─────────────────────

router.get('/online-projects/:projectId/activations', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const projectCheck = await pool.query<{ id: number }>(
    'SELECT id FROM projects WHERE id = $1 AND project_key IS NOT NULL',
    [projectId],
  );
  if ((projectCheck.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const result = await pool.query<{
    machine_id: string; node_name: string; activated_at: Date; last_seen: Date | null; is_active: boolean;
  }>(
    `SELECT machine_id, node_name, activated_at, last_seen, is_active
     FROM project_activations WHERE project_id = $1 ORDER BY activated_at`,
    [projectId],
  );

  res.status(200).json(result.rows);
});

// ── PATCH /api/admin/online-projects/:projectId/activations/:machineId ────────

router.patch('/online-projects/:projectId/activations/:machineId', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const machineId = req.params['machineId'];
  if (!machineId) {
    res.status(400).json({ error: 'machineId is required.' });
    return;
  }

  const { is_active } = req.body as Record<string, unknown>;
  if (typeof is_active !== 'boolean') {
    res.status(400).json({ error: 'is_active must be a boolean.' });
    return;
  }

  const result = await pool.query<{
    machine_id: string; node_name: string; activated_at: Date; last_seen: Date | null; is_active: boolean; polling_state: string;
  }>(
    `UPDATE project_activations SET is_active = $1
     WHERE project_id = $2 AND machine_id = $3
     RETURNING machine_id, node_name, activated_at, last_seen, is_active, polling_state`,
    [is_active, projectId, machineId],
  );

  if ((result.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Activation not found.' });
    return;
  }

  res.status(200).json(result.rows[0]);
});

export default router;
