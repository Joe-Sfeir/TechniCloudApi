import { Router } from 'express';
import type { Request, Response } from 'express';
import { randomBytes } from 'crypto';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';

const router = Router();

// All project routes require a valid JWT
router.use(requireAuth);

// ── GET /api/projects ─────────────────────────────────────────────────────────

router.get('/', async (_req: Request, res: Response): Promise<void> => {
  const userId = res.locals['userId'] as number;

  const result = await pool.query<{
    id: number;
    name: string;
    tier: number;
    api_key_prefix: string;
    created_at: Date;
  }>(
    `SELECT p.id, p.name, p.tier,
            CONCAT(SUBSTRING(p.api_key, 1, 10), '...') AS api_key_prefix,
            p.created_at
     FROM projects p
     JOIN project_assignments pa ON pa.project_id = p.id
     WHERE pa.user_id = $1
     ORDER BY p.created_at DESC`,
    [userId],
  );

  res.status(200).json(result.rows);
});

// ── POST /api/projects ────────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response): Promise<void> => {
  const userId = res.locals['userId'] as number;
  const { name, tier } = req.body as Record<string, unknown>;

  if (typeof name !== 'string' || name.trim().length === 0 || name.length > 255) {
    res.status(400).json({ error: 'name is required and must be ≤255 characters.' });
    return;
  }

  const resolvedTier = tier === undefined ? 1 : tier;
  if (resolvedTier !== 1 && resolvedTier !== 2 && resolvedTier !== 3) {
    res.status(400).json({ error: 'tier must be 1, 2, or 3.' });
    return;
  }

  // 160 bits of entropy — brute-force infeasible
  const apiKey = `TDAQ-${randomBytes(20).toString('hex')}`;

  const result = await pool.query<{
    id: number;
    user_id: number;
    name: string;
    tier: number;
    api_key: string;
    created_at: Date;
  }>(
    `INSERT INTO projects (user_id, name, tier, api_key)
     VALUES ($1, $2, $3, $4)
     RETURNING id, user_id, name, tier, api_key, created_at`,
    [userId, name.trim(), resolvedTier, apiKey],
  );

  const project = result.rows[0];

  // api_key is returned in full here — this is the only time it is shown.
  res.status(201).json(project);
});

// ── Helpers ───────────────────────────────────────────────────────────────────

async function checkProjectAccess(projectId: number, userId: number, role: string): Promise<boolean> {
  if (role === 'MASTER' || role === 'SUB_MASTER') return true;
  const r = await pool.query(
    'SELECT 1 FROM project_assignments WHERE project_id = $1 AND user_id = $2',
    [projectId, userId],
  );
  return (r.rowCount ?? 0) > 0;
}

// ── GET /api/projects/:projectId/config/:machineId ────────────────────────────

router.get('/:projectId/config/:machineId', async (req: Request, res: Response): Promise<void> => {
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

  const userId = res.locals['userId'] as number;
  const role   = res.locals['role'] as string;

  if (!(await checkProjectAccess(projectId, userId, role))) {
    res.status(403).json({ error: 'Forbidden.' });
    return;
  }

  const activationResult = await pool.query<{
    active_devices: unknown;
    thresholds: unknown;
    polling_state: string;
    last_seen: Date | null;
    config_pending: boolean;
    current_config: unknown;
  }>(
    `SELECT active_devices, thresholds, polling_state, last_seen, config_pending, current_config
     FROM project_activations WHERE project_id = $1 AND machine_id = $2`,
    [projectId, machineId],
  );

  if ((activationResult.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Machine not found.' });
    return;
  }

  const configResult = await pool.query<{
    config_version: number;
    desired_config: unknown;
    current_config: unknown;
    status: string;
    updated_at: Date;
  }>(
    `SELECT config_version, desired_config, current_config, status, updated_at
     FROM project_configs WHERE project_id = $1 AND machine_id = $2
     ORDER BY config_version DESC LIMIT 1`,
    [projectId, machineId],
  );

  const cfg = configResult.rows[0];
  const act = activationResult.rows[0]!;

  res.status(200).json({
    config_version: cfg?.config_version ?? null,
    desired_config: cfg?.desired_config ?? null,
    current_config: act.current_config ?? cfg?.current_config ?? null,
    status:         cfg?.status ?? null,
    updated_at:     cfg?.updated_at ?? null,
    active_devices: act.active_devices,
    thresholds:     act.thresholds,
    polling_state:  act.polling_state,
    last_seen:      act.last_seen,
    config_pending: act.config_pending,
  });
});

// ── POST /api/projects/:projectId/config ──────────────────────────────────────

router.post('/:projectId/config', async (req: Request, res: Response): Promise<void> => {
  console.log('[config-push-debug] received:', { projectId: req.params['projectId'], machine_id: (req.body as Record<string, unknown>)['machine_id'] });
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const userId = res.locals['userId'] as number;
  const role   = res.locals['role'] as string;

  if (!(await checkProjectAccess(projectId, userId, role))) {
    res.status(403).json({ error: 'Forbidden.' });
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

  const activationCheck = await pool.query<{ id: number }>(
    `SELECT id FROM project_activations WHERE project_id = $1 AND machine_id = $2`,
    [projectId, trimmedMachineId],
  );

  if ((activationCheck.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Machine not found.' });
    return;
  }

  const versionResult = await pool.query<{ next_version: number }>(
    `SELECT COALESCE(MAX(config_version), 0) + 1 AS next_version
     FROM project_configs WHERE project_id = $1 AND machine_id = $2`,
    [projectId, trimmedMachineId],
  );
  const nextVersion = versionResult.rows[0]!.next_version;

  await pool.query(
    `INSERT INTO project_configs (project_id, machine_id, config_version, desired_config, status)
     VALUES ($1, $2, $3, $4, 'pending')`,
    [projectId, trimmedMachineId, nextVersion, JSON.stringify(config)],
  );

  console.log('[config-push-debug] setting config_pending=true for project_id=' + projectId + ' machine_id=' + machine_id);
  const updateResult = await pool.query(
    `UPDATE project_activations SET config_pending = true WHERE project_id = $1 AND machine_id = $2`,
    [projectId, trimmedMachineId],
  );
  console.log('[config-push-debug] UPDATE rowCount:', updateResult.rowCount);

  res.status(200).json({ config_version: nextVersion, message: 'Configuration queued for delivery.' });
});

// ── GET /api/projects/:projectId/nodes ────────────────────────────────────────

router.get('/:projectId/nodes', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const userId = res.locals['userId'] as number;
  const role   = res.locals['role'] as string;

  if (!(await checkProjectAccess(projectId, userId, role))) {
    res.status(403).json({ error: 'Forbidden.' });
    return;
  }

  const projectResult = await pool.query<{ protocols: string }>(
    `SELECT protocols FROM projects WHERE id = $1`,
    [projectId],
  );

  if ((projectResult.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const nodesResult = await pool.query<{
    machine_id: string;
    node_name: string;
    polling_state: string;
    last_seen: Date | null;
  }>(
    `SELECT machine_id, node_name, polling_state, last_seen
     FROM project_activations
     WHERE project_id = $1 AND is_active = true
     ORDER BY activated_at`,
    [projectId],
  );

  res.status(200).json({
    protocols: projectResult.rows[0]!.protocols,
    nodes:     nodesResult.rows,
  });
});

export default router;
