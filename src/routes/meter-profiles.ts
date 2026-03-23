import { Router } from 'express';
import type { Request, Response } from 'express';
import { pool } from '../db.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

const router = Router();

router.use(requireAuth, requireRole('MASTER', 'SUB_MASTER'));

// ── GET /api/admin/meter-profiles ─────────────────────────────────────────────

router.get('/meter-profiles', async (_req: Request, res: Response): Promise<void> => {
  const result = await pool.query<{
    id: number; model: string; display_name: string; endianness: string;
    baud_rate: number | null; parity: string | null; registers: unknown;
    created_by: number | null; updated_at: Date;
  }>(
    `SELECT id, model, display_name, endianness, baud_rate, parity, registers, created_by, updated_at
     FROM meter_profiles ORDER BY model`,
  );

  res.status(200).json(result.rows);
});

// ── POST /api/admin/meter-profiles/publish ────────────────────────────────────
// Registered before /:id so Express doesn't treat "publish" as an id param.

router.post('/meter-profiles/publish', async (_req: Request, res: Response): Promise<void> => {
  const result = await pool.query(
    `UPDATE project_activations SET profiles_pending = true WHERE is_active = true`,
  );

  const nodeCount = result.rowCount ?? 0;
  res.status(200).json({ message: `Profiles queued for delivery to ${nodeCount} nodes.`, node_count: nodeCount });
});

// ── POST /api/admin/meter-profiles ────────────────────────────────────────────

router.post('/meter-profiles', async (req: Request, res: Response): Promise<void> => {
  const body = req.body as Record<string, unknown>;
  const { model, display_name, endianness, baud_rate, parity, registers } = body;

  if (typeof model !== 'string' || model.trim().length === 0 || model.length > 255) {
    res.status(400).json({ error: 'model is required and must be ≤255 characters.' });
    return;
  }

  if (typeof display_name !== 'string' || display_name.trim().length === 0 || display_name.length > 255) {
    res.status(400).json({ error: 'display_name is required and must be ≤255 characters.' });
    return;
  }

  if (endianness !== undefined && (typeof endianness !== 'string' || endianness.length > 10)) {
    res.status(400).json({ error: 'endianness must be a string ≤10 characters.' });
    return;
  }

  if (baud_rate !== undefined && (!Number.isInteger(baud_rate) || (baud_rate as number) <= 0)) {
    res.status(400).json({ error: 'baud_rate must be a positive integer.' });
    return;
  }

  if (parity !== undefined && typeof parity !== 'string') {
    res.status(400).json({ error: 'parity must be a string.' });
    return;
  }

  if (registers !== undefined && !Array.isArray(registers)) {
    res.status(400).json({ error: 'registers must be an array.' });
    return;
  }

  const userId = res.locals['userId'] as number;

  try {
    const result = await pool.query<{
      id: number; model: string; display_name: string; endianness: string;
      baud_rate: number | null; parity: string | null; registers: unknown;
      created_by: number | null; updated_at: Date;
    }>(
      `INSERT INTO meter_profiles (model, display_name, endianness, baud_rate, parity, registers, created_by, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING id, model, display_name, endianness, baud_rate, parity, registers, created_by, updated_at`,
      [
        model.trim(),
        display_name.trim(),
        endianness ?? 'ABCD',
        baud_rate ?? 19200,
        parity ?? 'None',
        JSON.stringify(registers ?? []),
        userId,
      ],
    );

    res.status(201).json(result.rows[0]);
  } catch (err: unknown) {
    if (
      typeof err === 'object' && err !== null &&
      'code' in err && (err as Record<string, unknown>)['code'] === '23505'
    ) {
      res.status(409).json({ error: 'A profile with this model name already exists.' });
      return;
    }
    throw err;
  }
});

// ── PATCH /api/admin/meter-profiles/:id ───────────────────────────────────────

router.patch('/meter-profiles/:id', async (req: Request, res: Response): Promise<void> => {
  const id = Number(req.params['id']);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'id must be a positive integer.' });
    return;
  }

  const body = req.body as Record<string, unknown>;
  const allowed = ['model', 'display_name', 'endianness', 'baud_rate', 'parity', 'registers'];
  const setClauses: string[] = [];
  const params: unknown[] = [];

  for (const field of allowed) {
    if (!(field in body)) continue;
    const val = body[field];

    if (field === 'model') {
      if (typeof val !== 'string' || val.trim().length === 0 || val.length > 255) {
        res.status(400).json({ error: 'model must be a non-empty string ≤255 characters.' });
        return;
      }
      params.push((val as string).trim());
      setClauses.push(`model = $${params.length}`);
    } else if (field === 'display_name') {
      if (typeof val !== 'string' || val.trim().length === 0 || val.length > 255) {
        res.status(400).json({ error: 'display_name must be a non-empty string ≤255 characters.' });
        return;
      }
      params.push((val as string).trim());
      setClauses.push(`display_name = $${params.length}`);
    } else if (field === 'endianness') {
      if (typeof val !== 'string' || val.length > 10) {
        res.status(400).json({ error: 'endianness must be a string ≤10 characters.' });
        return;
      }
      params.push(val);
      setClauses.push(`endianness = $${params.length}`);
    } else if (field === 'baud_rate') {
      if (!Number.isInteger(val) || (val as number) <= 0) {
        res.status(400).json({ error: 'baud_rate must be a positive integer.' });
        return;
      }
      params.push(val);
      setClauses.push(`baud_rate = $${params.length}`);
    } else if (field === 'parity') {
      if (typeof val !== 'string') {
        res.status(400).json({ error: 'parity must be a string.' });
        return;
      }
      params.push(val);
      setClauses.push(`parity = $${params.length}`);
    } else if (field === 'registers') {
      if (!Array.isArray(val)) {
        res.status(400).json({ error: 'registers must be an array.' });
        return;
      }
      params.push(JSON.stringify(val));
      setClauses.push(`registers = $${params.length}`);
    }
  }

  if (setClauses.length === 0) {
    res.status(400).json({ error: 'No valid fields provided to update.' });
    return;
  }

  setClauses.push(`updated_at = NOW()`);
  params.push(id);

  try {
    const result = await pool.query<{
      id: number; model: string; display_name: string; endianness: string;
      baud_rate: number | null; parity: string | null; registers: unknown;
      created_by: number | null; updated_at: Date;
    }>(
      `UPDATE meter_profiles SET ${setClauses.join(', ')}
       WHERE id = $${params.length}
       RETURNING id, model, display_name, endianness, baud_rate, parity, registers, created_by, updated_at`,
      params,
    );

    if ((result.rowCount ?? 0) === 0) {
      res.status(404).json({ error: 'Profile not found.' });
      return;
    }

    res.status(200).json(result.rows[0]);
  } catch (err: unknown) {
    if (
      typeof err === 'object' && err !== null &&
      'code' in err && (err as Record<string, unknown>)['code'] === '23505'
    ) {
      res.status(409).json({ error: 'A profile with this model name already exists.' });
      return;
    }
    throw err;
  }
});

// ── DELETE /api/admin/meter-profiles/:id ──────────────────────────────────────

router.delete('/meter-profiles/:id', async (req: Request, res: Response): Promise<void> => {
  const id = Number(req.params['id']);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'id must be a positive integer.' });
    return;
  }

  const result = await pool.query(
    `DELETE FROM meter_profiles WHERE id = $1`,
    [id],
  );

  if ((result.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Profile not found.' });
    return;
  }

  res.status(200).json({ message: 'Profile deleted.' });
});

export default router;
