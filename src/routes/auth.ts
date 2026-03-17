import { Router } from 'express';
import type { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomInt } from 'crypto';
import { pool } from '../db';

const router = Router();

// ── Helpers ───────────────────────────────────────────────────────────────────

function getJwtSecret(): string {
  const secret = process.env['JWT_SECRET'];
  if (!secret) throw new Error('JWT_SECRET environment variable is required');
  return secret;
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

/**
 * Sends the 2FA code by email via Resend when RESEND_API_KEY is configured.
 * Falls back to console logging in development.
 */
function sendTwoFactorEmail(to: string, code: string): void {
  const apiKey = process.env['RESEND_API_KEY'];

  if (apiKey) {
    fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'TechniDAQ <onboarding@resend.dev>',
        to: [to],
        subject: 'Your TechniDAQ login code',
        html: `<p>Your verification code is: <strong>${code}</strong></p><p>This code expires in 10 minutes.</p>`,
      }),
    }).then(() => {
      console.log(`[2FA] Code emailed to ${to}`);
    }).catch((err: unknown) => {
      console.error('[2FA] Resend background error:', err);
      console.log(`[2FA] Code for ${to}: ${code}`);
    });
  } else {
    console.log(`[2FA] Code for ${to}: ${code}`);
  }
}

// ── POST /api/auth/register ───────────────────────────────────────────────────

router.post('/register', async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body as Record<string, unknown>;

  if (typeof email !== 'string' || !isValidEmail(email)) {
    res.status(400).json({ error: 'A valid email address is required.' });
    return;
  }

  if (typeof password !== 'string' || password.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters.' });
    return;
  }

  const normalizedEmail = email.toLowerCase();

  const existing = await pool.query<{ id: number }>(
    'SELECT id FROM users WHERE email = $1',
    [normalizedEmail],
  );
  if ((existing.rowCount ?? 0) > 0) {
    res.status(409).json({ error: 'An account with that email already exists.' });
    return;
  }

  // Assign MASTER role if this email matches the designated master account.
  const masterEmail = process.env['MASTER_EMAIL']?.toLowerCase();
  const role = masterEmail && normalizedEmail === masterEmail ? 'MASTER' : 'CLIENT';

  const passwordHash = await bcrypt.hash(password, 12);

  const result = await pool.query<{ id: number; email: string; role: string; created_at: Date }>(
    `INSERT INTO users (email, password_hash, role)
     VALUES ($1, $2, $3)
     RETURNING id, email, role, created_at`,
    [normalizedEmail, passwordHash, role],
  );

  const user = result.rows[0];
  res.status(201).json({ id: user?.id, email: user?.email, role: user?.role, created_at: user?.created_at });
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────

router.post('/login', async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body as Record<string, unknown>;

  if (typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({ error: 'email and password are required.' });
    return;
  }

  const result = await pool.query<{
    id: number;
    email: string;
    password_hash: string;
    role: string;
  }>(
    'SELECT id, email, password_hash, role FROM users WHERE email = $1',
    [email.toLowerCase()],
  );

  const user = result.rows[0];

  // Always run bcrypt.compare to prevent timing-based email enumeration.
  const dummyHash = '$2a$12$invalidhashfortimingnormalization000000000000000000000';
  const hashToCompare = user?.password_hash ?? dummyHash;
  const match = await bcrypt.compare(password, hashToCompare);

  if (!user || !match) {
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }

  // ── CLIENT / SUB_MASTER: return JWT immediately ─────────────────────────────
  if (user.role === 'CLIENT' || user.role === 'SUB_MASTER') {
    const token = jwt.sign(
      { sub: user.id, email: user.email, role: user.role },
      getJwtSecret(),
      { expiresIn: '24h' },
    );
    res.status(200).json({ token, user: { id: user.id, email: user.email, role: user.role } });
    return;
  }

  // ── MASTER: trigger 2FA challenge ────────────────────────────────────────────
  // crypto.randomInt is cryptographically secure; range [100000, 1000000) gives
  // exactly 6 digits with uniform distribution.
  const code = randomInt(100_000, 1_000_000).toString();

  await pool.query(
    `UPDATE users
     SET two_factor_code = $1, two_factor_expires = NOW() + INTERVAL '10 minutes'
     WHERE id = $2`,
    [code, user.id],
  );

  // Respond instantly — email is dispatched in the background inside sendTwoFactorEmail
  sendTwoFactorEmail(user.email, code);
  res.status(200).json({ requires_2fa: true, email: user.email });
});

// ── POST /api/auth/verify-2fa ─────────────────────────────────────────────────

router.post('/verify-2fa', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, code } = req.body as Record<string, unknown>;

    console.log('Verify 2FA hit for:', email, code);

    if (typeof email !== 'string' || typeof code !== 'string') {
      res.status(400).json({ error: 'email and code are required.' });
      return;
    }

    // Step 1: look up user by email
    const result = await pool.query<{
      id: number;
      email: string;
      role: string;
      two_factor_code: string | null;
      two_factor_expires: Date | null;
    }>(
      `SELECT id, email, role, two_factor_code, two_factor_expires
       FROM users WHERE email = $1`,
      [email.toLowerCase()],
    );

    const user = result.rows[0];

    if (!user) {
      res.status(400).json({ error: 'User not found.' });
      return;
    }

    // Step 2: check expiry
    if (!user.two_factor_expires || new Date() > new Date(user.two_factor_expires)) {
      res.status(400).json({ error: 'Code expired.' });
      return;
    }

    // Step 3: check code matches
    if (user.two_factor_code !== code) {
      res.status(400).json({ error: 'Invalid code.' });
      return;
    }

    // Step 4: consume the code so it cannot be reused
    await pool.query(
      `UPDATE users SET two_factor_code = NULL, two_factor_expires = NULL WHERE id = $1`,
      [user.id],
    );

    // Step 5: issue JWT
    const token = jwt.sign(
      { sub: user.id, email: user.email, role: user.role },
      getJwtSecret(),
      { expiresIn: '24h' },
    );

    res.status(200).json({ token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('[verify-2fa] Unexpected error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

export default router;
