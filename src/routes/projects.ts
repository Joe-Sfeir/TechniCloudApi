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
    `SELECT id, name, tier,
            -- Only expose a masked prefix; the full key was shown once at creation
            CONCAT(SUBSTRING(api_key, 1, 10), '...') AS api_key_prefix,
            created_at
     FROM projects
     WHERE user_id = $1
     ORDER BY created_at DESC`,
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

export default router;
