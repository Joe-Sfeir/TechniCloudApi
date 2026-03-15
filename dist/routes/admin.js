"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const crypto_1 = require("crypto");
const db_1 = require("../db");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
// All admin routes require a valid JWT and at least SUB_MASTER role.
router.use(auth_1.requireAuth, (0, auth_1.requireRole)('MASTER', 'SUB_MASTER'));
// ── Helpers ───────────────────────────────────────────────────────────────────
const ONLINE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
function getMasterKey() {
    const key = process.env['MASTER_KEY'];
    if (!key)
        throw new Error('MASTER_KEY environment variable is required');
    return key;
}
// ── GET /api/admin/projects ───────────────────────────────────────────────────
router.get('/projects', async (_req, res) => {
    const result = await db_1.pool.query(`SELECT p.id, p.name, p.tier, p.created_at,
            u.email AS owner_email,
            MAX(t.timestamp) AS last_seen
     FROM projects p
     JOIN users u ON u.id = p.user_id
     LEFT JOIN telemetry t ON t.project_id = p.id
     GROUP BY p.id, u.email
     ORDER BY p.created_at DESC`);
    const now = Date.now();
    const projects = result.rows.map((row) => {
        let status;
        if (!row.last_seen) {
            status = 'NEVER';
        }
        else if (now - new Date(row.last_seen).getTime() <= ONLINE_WINDOW_MS) {
            status = 'ONLINE';
        }
        else {
            status = 'OFFLINE';
        }
        return { ...row, status };
    });
    res.status(200).json(projects);
});
// ── GET /api/admin/users ──────────────────────────────────────────────────────
router.get('/users', async (_req, res) => {
    const result = await db_1.pool.query(`SELECT id, email, role, reset_requested, created_at
     FROM users
     ORDER BY created_at DESC`);
    res.status(200).json(result.rows);
});
// ── POST /api/admin/reset-password ───────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
    const { user_id } = req.body;
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
    const check = await db_1.pool.query('SELECT id FROM users WHERE id = $1', [targetId]);
    if ((check.rowCount ?? 0) === 0) {
        res.status(404).json({ error: 'User not found.' });
        return;
    }
    // 8 URL-safe characters (~48 bits of entropy) — sufficient for a phone-read temp credential
    const tempPassword = (0, crypto_1.randomBytes)(6).toString('base64url');
    const passwordHash = await bcryptjs_1.default.hash(tempPassword, 12);
    await db_1.pool.query(`UPDATE users SET password_hash = $1, reset_requested = false WHERE id = $2`, [passwordHash, targetId]);
    // Returned in plaintext once — admin reads this to the client over the phone.
    res.status(200).json({ user_id: targetId, temp_password: tempPassword });
});
// ── POST /api/admin/generate-license ─────────────────────────────────────────
// Restricted to MASTER only — SUB_MASTERs cannot mint licenses.
//
// Output format: base64( IV[12] | Ciphertext[n] | AuthTag[16] )
// The Rust desktop app derives the same 32-byte key via SHA-256(MASTER_KEY),
// then splits the decoded blob as: iv=[:12], tag=[-16:], ciphertext=[12..-16].
router.post('/generate-license', (0, auth_1.requireRole)('MASTER'), async (req, res) => {
    const { user_name, project_name, allowed_meters, tier, protocols, mode, ttl_hours } = req.body;
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
    let resolvedTier = null;
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
        user_name: user_name.trim(),
        project_name: project_name.trim(),
        allowed_meters,
        tier: resolvedTier,
        protocols,
        mode,
        issued_at: nowSec,
        expires_at: nowSec + Math.floor(ttl_hours * 3600),
    });
    // ── Derive 32-byte AES key via SHA-256(MASTER_KEY) ────────────────────────
    // The Rust app must apply the same derivation:
    //   let key = Sha256::digest(master_key_bytes);
    const aesKey = (0, crypto_1.createHash)('sha256').update(getMasterKey(), 'utf8').digest();
    // ── Encrypt with AES-256-GCM ──────────────────────────────────────────────
    const iv = (0, crypto_1.randomBytes)(12);
    const cipher = (0, crypto_1.createCipheriv)('aes-256-gcm', aesKey, iv);
    const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag(); // always 16 bytes
    // ── Encode as base64( IV[12] | Ciphertext[n] | AuthTag[16] ) ─────────────
    const licenseKey = Buffer.concat([iv, ciphertext, authTag]).toString('base64');
    res.status(201).json({ license_key: licenseKey });
});
exports.default = router;
//# sourceMappingURL=admin.js.map