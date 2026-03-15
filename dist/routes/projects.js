"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const crypto_1 = require("crypto");
const db_1 = require("../db");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
// All project routes require a valid JWT
router.use(auth_1.requireAuth);
// ── GET /api/projects ─────────────────────────────────────────────────────────
router.get('/', async (_req, res) => {
    const userId = res.locals['userId'];
    const result = await db_1.pool.query(`SELECT id, name, tier,
            -- Only expose a masked prefix; the full key was shown once at creation
            CONCAT(SUBSTRING(api_key, 1, 10), '...') AS api_key_prefix,
            created_at
     FROM projects
     WHERE user_id = $1
     ORDER BY created_at DESC`, [userId]);
    res.status(200).json(result.rows);
});
// ── POST /api/projects ────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
    const userId = res.locals['userId'];
    const { name, tier } = req.body;
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
    const apiKey = `TDAQ-${(0, crypto_1.randomBytes)(20).toString('hex')}`;
    const result = await db_1.pool.query(`INSERT INTO projects (user_id, name, tier, api_key)
     VALUES ($1, $2, $3, $4)
     RETURNING id, user_id, name, tier, api_key, created_at`, [userId, name.trim(), resolvedTier, apiKey]);
    const project = result.rows[0];
    // api_key is returned in full here — this is the only time it is shown.
    res.status(201).json(project);
});
exports.default = router;
//# sourceMappingURL=projects.js.map