"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = require("crypto");
const nodemailer_1 = __importDefault(require("nodemailer"));
const db_1 = require("../db");
const router = (0, express_1.Router)();
// ── Helpers ───────────────────────────────────────────────────────────────────
function getJwtSecret() {
    const secret = process.env['JWT_SECRET'];
    if (!secret)
        throw new Error('JWT_SECRET environment variable is required');
    return secret;
}
function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
/**
 * Sends the 2FA code by email when SMTP env vars are configured.
 * Falls back to console logging in development.
 */
function sendTwoFactorEmail(to, code) {
    const { SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
    if (SMTP_USER && SMTP_PASS) {
        // family:4 forces IPv4 — prevents ENETUNREACH on Render's IPv6 nodes.
        // connectionTimeout/greetingTimeout cap any SMTP hang to 5 s max so the
        // background task never saturates the event loop.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const transporter = nodemailer_1.default.createTransport({
            host: 'smtp.gmail.com',
            port: Number(SMTP_PORT ?? 587),
            secure: Number(SMTP_PORT ?? 587) === 465,
            family: 4,
            connectionTimeout: 5_000,
            greetingTimeout: 5_000,
            auth: { user: SMTP_USER, pass: SMTP_PASS },
        });
        transporter.sendMail({
            from: `"TechniDAQ Security" <${SMTP_USER}>`,
            to,
            subject: 'Your TechniDAQ login code',
            text: `Your verification code is: ${code}\n\nThis code expires in 10 minutes.`,
        }).then(() => {
            console.log(`[2FA] Code emailed to ${to}`);
        }).catch((err) => {
            console.error('[2FA] SMTP background error:', err);
            console.log(`[2FA] Code for ${to}: ${code}`);
        });
    }
    else {
        console.log(`[2FA] Code for ${to}: ${code}`);
    }
}
// ── POST /api/auth/register ───────────────────────────────────────────────────
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (typeof email !== 'string' || !isValidEmail(email)) {
        res.status(400).json({ error: 'A valid email address is required.' });
        return;
    }
    if (typeof password !== 'string' || password.length < 8) {
        res.status(400).json({ error: 'Password must be at least 8 characters.' });
        return;
    }
    const normalizedEmail = email.toLowerCase();
    const existing = await db_1.pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if ((existing.rowCount ?? 0) > 0) {
        res.status(409).json({ error: 'An account with that email already exists.' });
        return;
    }
    // Assign MASTER role if this email matches the designated master account.
    const masterEmail = process.env['MASTER_EMAIL']?.toLowerCase();
    const role = masterEmail && normalizedEmail === masterEmail ? 'MASTER' : 'CLIENT';
    const passwordHash = await bcryptjs_1.default.hash(password, 12);
    const result = await db_1.pool.query(`INSERT INTO users (email, password_hash, role)
     VALUES ($1, $2, $3)
     RETURNING id, email, role, created_at`, [normalizedEmail, passwordHash, role]);
    const user = result.rows[0];
    res.status(201).json({ id: user?.id, email: user?.email, role: user?.role, created_at: user?.created_at });
});
// ── POST /api/auth/login ──────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (typeof email !== 'string' || typeof password !== 'string') {
        res.status(400).json({ error: 'email and password are required.' });
        return;
    }
    const result = await db_1.pool.query('SELECT id, email, password_hash, role FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];
    // Always run bcrypt.compare to prevent timing-based email enumeration.
    const dummyHash = '$2a$12$invalidhashfortimingnormalization000000000000000000000';
    const hashToCompare = user?.password_hash ?? dummyHash;
    const match = await bcryptjs_1.default.compare(password, hashToCompare);
    if (!user || !match) {
        res.status(401).json({ error: 'Invalid email or password.' });
        return;
    }
    // ── CLIENT: return JWT immediately ──────────────────────────────────────────
    if (user.role === 'CLIENT') {
        const token = jsonwebtoken_1.default.sign({ sub: user.id, email: user.email, role: user.role }, getJwtSecret(), { expiresIn: '24h' });
        res.status(200).json({ token, user: { id: user.id, email: user.email, role: user.role } });
        return;
    }
    // ── MASTER / SUB_MASTER: trigger 2FA challenge ───────────────────────────────
    // crypto.randomInt is cryptographically secure; range [100000, 1000000) gives
    // exactly 6 digits with uniform distribution.
    const code = (0, crypto_1.randomInt)(100_000, 1_000_000).toString();
    await db_1.pool.query(`UPDATE users
     SET two_factor_code = $1, two_factor_expires = NOW() + INTERVAL '10 minutes'
     WHERE id = $2`, [code, user.id]);
    // Respond instantly — email is dispatched in the background inside sendTwoFactorEmail
    sendTwoFactorEmail(user.email, code);
    res.status(200).json({ requires_2fa: true, email: user.email });
});
// ── POST /api/auth/verify-2fa ─────────────────────────────────────────────────
router.post('/verify-2fa', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (typeof email !== 'string' || typeof code !== 'string') {
            res.status(400).json({ error: 'email and code are required.' });
            return;
        }
        const result = await db_1.pool.query(`SELECT id, email, role FROM users
       WHERE email = $1
         AND two_factor_code = $2
         AND two_factor_expires > NOW()`, [email.toLowerCase(), code]);
        const user = result.rows[0];
        if (!user) {
            res.status(400).json({ error: 'Invalid or expired code.' });
            return;
        }
        // Consume the code so it cannot be reused.
        await db_1.pool.query(`UPDATE users SET two_factor_code = NULL, two_factor_expires = NULL WHERE id = $1`, [user.id]);
        const token = jsonwebtoken_1.default.sign({ sub: user.id, email: user.email, role: user.role }, getJwtSecret(), { expiresIn: '24h' });
        res.status(200).json({ token, user: { id: user.id, email: user.email, role: user.role } });
    }
    catch (err) {
        console.error('[verify-2fa] Unexpected error:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
exports.default = router;
//# sourceMappingURL=auth.js.map