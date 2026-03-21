import { Router } from 'express';
import type { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { randomBytes, createCipheriv } from 'crypto';
import { pool } from '../db';
import { requireAuth, requireRole } from '../middleware/auth';

const router = Router();

// All admin routes require a valid JWT and at least SUB_MASTER role.
router.use(requireAuth, requireRole('MASTER', 'SUB_MASTER'));

// ── Helpers ───────────────────────────────────────────────────────────────────

const ONLINE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

function getMasterKey(): string {
  const key = process.env['MASTER_KEY'];
  if (!key) throw new Error('MASTER_KEY environment variable is required');
  return key;
}

// ── GET /api/admin/projects ───────────────────────────────────────────────────

router.get('/projects', async (_req: Request, res: Response): Promise<void> => {
  const result = await pool.query<{
    id: number;
    user_id: number | null;
    name: string;
    tier: number;
    created_at: Date;
    clients: { id: number; email: string }[];
    last_seen: Date | null;
  }>(
    `SELECT p.id, p.user_id, p.name, p.tier, p.created_at,
            COALESCE(
              json_agg(json_build_object('id', u.id, 'email', u.email) ORDER BY pa.assigned_at)
              FILTER (WHERE pa.id IS NOT NULL),
              '[]'::json
            ) AS clients,
            (SELECT MAX(t.timestamp) FROM telemetry t WHERE t.project_id = p.id) AS last_seen
     FROM projects p
     LEFT JOIN project_assignments pa ON pa.project_id = p.id
     LEFT JOIN users u ON u.id = pa.user_id
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

// ── GET /api/admin/users ──────────────────────────────────────────────────────

router.get('/users', async (_req: Request, res: Response): Promise<void> => {
  const result = await pool.query<{
    id: number;
    email: string;
    role: string;
    full_name: string | null;
    company: string | null;
    reset_requested: boolean;
    created_at: Date;
    project_count: number;
  }>(
    `SELECT id, email, role, full_name, company, reset_requested, created_at,
            (SELECT COUNT(*) FROM project_assignments pa WHERE pa.user_id = u.id)::int AS project_count
     FROM users u
     ORDER BY created_at DESC`,
  );

  res.status(200).json(result.rows);
});

// ── DELETE /api/admin/users/:userId ──────────────────────────────────────────

router.delete('/users/:userId', async (req: Request, res: Response): Promise<void> => {
  const userId = Number(req.params['userId']);
  if (!Number.isInteger(userId) || userId <= 0) {
    res.status(400).json({ error: 'userId must be a positive integer.' });
    return;
  }

  const check = await pool.query<{ id: number; role: string }>(
    'SELECT id, role FROM users WHERE id = $1',
    [userId],
  );

  if ((check.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'User not found.' });
    return;
  }

  if (check.rows[0]?.role === 'MASTER') {
    res.status(403).json({ error: 'Cannot delete master account.' });
    return;
  }

  await pool.query('DELETE FROM users WHERE id = $1', [userId]);

  res.status(200).json({ message: 'User deleted.' });
});

// ── POST /api/admin/users ─────────────────────────────────────────────────────

router.post('/users', async (req: Request, res: Response): Promise<void> => {
  const { full_name, email, company, password, role } = req.body as Record<string, unknown>;

  if (typeof full_name !== 'string' || full_name.trim().length === 0 || full_name.length > 255) {
    res.status(400).json({ error: 'full_name is required and must be ≤255 characters.' });
    return;
  }

  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ error: 'A valid email address is required.' });
    return;
  }

  if (company !== undefined && (typeof company !== 'string' || company.length > 255)) {
    res.status(400).json({ error: 'company must be a string ≤255 characters.' });
    return;
  }

  if (typeof password !== 'string' || password.length < 8) {
    res.status(400).json({ error: 'password must be at least 8 characters.' });
    return;
  }

  const VALID_ROLES = ['CLIENT', 'SUB_MASTER', 'MASTER'];
  if (typeof role !== 'string' || !VALID_ROLES.includes(role)) {
    res.status(400).json({ error: 'role must be "CLIENT", "SUB_MASTER", or "MASTER".' });
    return;
  }

  const normalizedEmail = email.toLowerCase();

  const existing = await pool.query<{ id: number }>(
    'SELECT id FROM users WHERE email = $1',
    [normalizedEmail],
  );
  if ((existing.rowCount ?? 0) > 0) {
    res.status(400).json({ error: 'Email already exists in the system.' });
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const result = await pool.query<{
    id: number;
    email: string;
    role: string;
    full_name: string;
    company: string | null;
    created_at: Date;
  }>(
    `INSERT INTO users (email, password_hash, role, full_name, company)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, email, role, full_name, company, created_at`,
    [normalizedEmail, passwordHash, role, full_name.trim(), company ?? null],
  );

  res.status(201).json(result.rows[0]);
});

// ── PATCH /api/admin/projects/:projectId/assign ───────────────────────────────

router.patch('/projects/:projectId/assign', async (req: Request, res: Response): Promise<void> => {
  try {
    const projectId = Number(req.params['projectId']);
    if (!Number.isInteger(projectId) || projectId <= 0) {
      res.status(400).json({ error: 'projectId must be a positive integer.' });
      return;
    }

    const { user_id } = req.body as Record<string, unknown>;

    if (typeof user_id !== 'number' && typeof user_id !== 'string') {
      res.status(400).json({ error: 'user_id is required.' });
      return;
    }

    const targetUserId = Number(user_id);
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      res.status(400).json({ error: 'user_id must be a positive integer.' });
      return;
    }

    const projectCheck = await pool.query<{ id: number }>(
      'SELECT id FROM projects WHERE id = $1',
      [projectId],
    );
    if ((projectCheck.rowCount ?? 0) === 0) {
      res.status(404).json({ error: 'Project not found.' });
      return;
    }

    const userCheck = await pool.query<{ id: number }>(
      'SELECT id FROM users WHERE id = $1',
      [targetUserId],
    );
    if ((userCheck.rowCount ?? 0) === 0) {
      res.status(400).json({ error: 'User not found.' });
      return;
    }

    try {
      await pool.query(
        `INSERT INTO project_assignments (project_id, user_id) VALUES ($1, $2)`,
        [projectId, targetUserId],
      );
    } catch (insertErr: unknown) {
      if (
        typeof insertErr === 'object' && insertErr !== null &&
        'code' in insertErr && (insertErr as Record<string, unknown>)['code'] === '23505'
      ) {
        res.status(400).json({ error: 'Client already assigned to this project.' });
        return;
      }
      throw insertErr;
    }

    const result = await pool.query<{
      id: number;
      user_id: number | null;
      name: string;
      tier: number;
      created_at: Date;
      clients: { id: number; email: string }[];
      last_seen: Date | null;
    }>(
      `SELECT p.id, p.user_id, p.name, p.tier, p.created_at,
              COALESCE(
                json_agg(json_build_object('id', u.id, 'email', u.email) ORDER BY pa.assigned_at)
                FILTER (WHERE pa.id IS NOT NULL),
                '[]'::json
              ) AS clients,
              (SELECT MAX(t.timestamp) FROM telemetry t WHERE t.project_id = p.id) AS last_seen
       FROM projects p
       LEFT JOIN project_assignments pa ON pa.project_id = p.id
       LEFT JOIN users u ON u.id = pa.user_id
       WHERE p.id = $1
       GROUP BY p.id`,
      [projectId],
    );

    const row = result.rows[0];
    let status: 'ONLINE' | 'OFFLINE' | 'NEVER';
    if (!row?.last_seen) {
      status = 'NEVER';
    } else if (Date.now() - new Date(row.last_seen).getTime() <= ONLINE_WINDOW_MS) {
      status = 'ONLINE';
    } else {
      status = 'OFFLINE';
    }

    res.status(200).json({ message: 'Project assigned successfully.', project: { ...row, status } });
  } catch (err) {
    console.error('[admin] PATCH /projects/:projectId/assign error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ── DELETE /api/admin/projects/:projectId/unassign ────────────────────────────

router.delete('/projects/:projectId/unassign', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const { user_id } = req.body as Record<string, unknown>;

  if (typeof user_id !== 'number' && typeof user_id !== 'string') {
    res.status(400).json({ error: 'user_id is required.' });
    return;
  }

  const targetUserId = Number(user_id);
  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    res.status(400).json({ error: 'user_id must be a positive integer.' });
    return;
  }

  const result = await pool.query(
    `DELETE FROM project_assignments WHERE project_id = $1 AND user_id = $2`,
    [projectId, targetUserId],
  );

  if ((result.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'Assignment not found.' });
    return;
  }

  res.status(200).json({ message: 'Client unassigned.' });
});

// ── POST /api/admin/reset-password ───────────────────────────────────────────

router.post('/reset-password', async (req: Request, res: Response): Promise<void> => {
  const { user_id } = req.body as Record<string, unknown>;

  if (typeof user_id !== 'number' && typeof user_id !== 'string') {
    res.status(400).json({ error: 'user_id is required.' });
    return;
  }

  const targetId = Number(user_id);
  if (!Number.isInteger(targetId) || targetId <= 0) {
    res.status(400).json({ error: 'user_id must be a positive integer.' });
    return;
  }

  // Verify target user exists
  const check = await pool.query<{ id: number }>(
    'SELECT id FROM users WHERE id = $1',
    [targetId],
  );
  if ((check.rowCount ?? 0) === 0) {
    res.status(404).json({ error: 'User not found.' });
    return;
  }

  // 8 URL-safe characters (~48 bits of entropy) — sufficient for a phone-read temp credential
  const tempPassword = randomBytes(6).toString('base64url');
  const passwordHash = await bcrypt.hash(tempPassword, 12);

  await pool.query(
    `UPDATE users SET password_hash = $1, reset_requested = false WHERE id = $2`,
    [passwordHash, targetId],
  );

  // Returned in plaintext once — admin reads this to the client over the phone.
  res.status(200).json({ user_id: targetId, temp_password: tempPassword });
});

// ── POST /api/admin/generate-license ─────────────────────────────────────────
// Restricted to MASTER only — SUB_MASTERs cannot mint licenses.
//
// Output format: base64( IV[12] | Ciphertext[n] | AuthTag[16] )
// The Rust desktop app derives the same 32-byte key via SHA-256(MASTER_KEY),
// then splits the decoded blob as: iv=[:12], tag=[-16:], ciphertext=[12..-16].

router.post(
  '/generate-license',
  requireRole('MASTER'),
  async (req: Request, res: Response): Promise<void> => {
    const { user_name, project_name, allowed_meters, tier, protocols, mode, ttl_hours } =
      req.body as Record<string, unknown>;

    // ── Validate required string fields ───────────────────────────────────────
    if (typeof user_name !== 'string' || user_name.trim().length === 0) {
      res.status(400).json({ error: 'user_name is required.' });
      return;
    }
    if (typeof project_name !== 'string' || project_name.trim().length === 0) {
      res.status(400).json({ error: 'project_name is required.' });
      return;
    }
    if (!Array.isArray(allowed_meters) || allowed_meters.length === 0) {
      res.status(400).json({ error: 'allowed_meters must be a non-empty array.' });
      return;
    }

    // ── Validate mode first — tier rules depend on it ─────────────────────────
    if (mode !== 'online' && mode !== 'offline') {
      res.status(400).json({ error: 'mode must be "online" or "offline".' });
      return;
    }

    // ── Validate tier (online only; offline forces null) ──────────────────────
    let resolvedTier: number | null = null;
    if (mode === 'online') {
      if (tier !== 1 && tier !== 2) {
        res.status(400).json({ error: 'tier must be 1 or 2 for online mode.' });
        return;
      }
      resolvedTier = tier;
    }
    // mode === 'offline': tier input is ignored, payload carries null

    // ── Validate protocols ────────────────────────────────────────────────────
    if (protocols !== 'RTU' && protocols !== 'TCP' && protocols !== 'All') {
      res.status(400).json({ error: 'protocols must be "RTU", "TCP", or "All".' });
      return;
    }

    if (typeof ttl_hours !== 'number' || ttl_hours <= 0 || !Number.isFinite(ttl_hours)) {
      res.status(400).json({ error: 'ttl_hours must be a positive number.' });
      return;
    }

    // ── Build plaintext payload ───────────────────────────────────────────────
    const nowSec = Math.floor(Date.now() / 1000);
    const plaintext = JSON.stringify({
      created_at:     nowSec,
      duration_days:  ttl_hours / 24,
      ttl_hours,
      username:       user_name.trim(),
      project_name:   project_name.trim(),
      allowed_meters,
      mode,
      tier:           resolvedTier ?? 0,
      protocols,
    });

    // ── Decode 32-byte AES key from MASTER_KEY hex string ────────────────────
    // The Rust app does: hex_decode(MASTER_KEY_HEX) — no hashing, direct decode.
    // MASTER_KEY must be exactly 64 hex chars (= 32 bytes for AES-256).
    const masterKey = getMasterKey();
    if (masterKey.length !== 64) {
      throw new Error('CRITICAL: MASTER_KEY is missing or invalid length');
    }
    const aesKey = Buffer.from(masterKey, 'hex');

    // ── Encrypt with AES-256-GCM ──────────────────────────────────────────────
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag(); // always 16 bytes

    // ── Encode as base64( IV[12] | Ciphertext[n] | AuthTag[16] ) ─────────────
    const licenseKey = Buffer.concat([iv, ciphertext, authTag]).toString('base64');

    // ── Record to license history ─────────────────────────────────────────────
    const generatedBy = res.locals['userId'] as number;
    await pool.query(
      `INSERT INTO license_history
         (generated_by, username, project_name, mode, tier, protocols, allowed_meters, ttl_hours)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        generatedBy,
        user_name.trim(),
        project_name.trim(),
        mode,
        resolvedTier,
        protocols,
        JSON.stringify(allowed_meters),
        ttl_hours,
      ],
    );

    res.status(201).json({ license_key: licenseKey });
  },
);

// ── GET /api/admin/licenses ───────────────────────────────────────────────────

router.get('/licenses', async (_req: Request, res: Response): Promise<void> => {
  const result = await pool.query<{
    id: number;
    generated_by: number | null;
    username: string;
    project_name: string;
    mode: string;
    tier: number | null;
    protocols: string | null;
    allowed_meters: unknown[];
    ttl_hours: number | null;
    created_at: Date;
  }>(
    `SELECT id, generated_by, username, project_name, mode, tier,
            protocols, allowed_meters, ttl_hours, created_at
     FROM license_history
     ORDER BY created_at DESC`,
  );

  res.status(200).json(result.rows);
});

export default router;
