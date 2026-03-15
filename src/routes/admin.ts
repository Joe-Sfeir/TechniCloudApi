import { Router } from 'express';
import type { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { randomBytes, createCipheriv, createHash } from 'crypto';
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
    name: string;
    tier: number;
    created_at: Date;
    owner_email: string;
    last_seen: Date | null;
  }>(
    `SELECT p.id, p.name, p.tier, p.created_at,
            u.email AS owner_email,
            MAX(t.timestamp) AS last_seen
     FROM projects p
     JOIN users u ON u.id = p.user_id
     LEFT JOIN telemetry t ON t.project_id = p.id
     GROUP BY p.id, u.email
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
  }>(
    `SELECT id, email, role, full_name, company, reset_requested, created_at
     FROM users
     ORDER BY created_at DESC`,
  );

  res.status(200).json(result.rows);
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
      user_name:      user_name.trim(),
      project_name:   project_name.trim(),
      allowed_meters,
      tier:           resolvedTier,
      protocols,
      mode,
      issued_at:      nowSec,
      expires_at:     nowSec + Math.floor(ttl_hours * 3600),
    });

    // ── Derive 32-byte AES key via SHA-256(MASTER_KEY) ────────────────────────
    // The Rust app must apply the same derivation:
    //   let key = Sha256::digest(master_key_bytes);
    const aesKey = createHash('sha256').update(getMasterKey(), 'utf8').digest();

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

    res.status(201).json({ license_key: licenseKey });
  },
);

export default router;
