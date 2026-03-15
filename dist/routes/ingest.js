"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const db_1 = require("../db");
const router = (0, express_1.Router)();
function validatePayload(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body))
        return false;
    const b = body;
    if (typeof b['api_key'] !== 'string' ||
        b['api_key'].trim().length === 0)
        return false;
    if (typeof b['device_name'] !== 'string' ||
        b['device_name'].trim().length === 0 ||
        b['device_name'].length > 255)
        return false;
    if (typeof b['timestamp'] !== 'string')
        return false;
    if (!b['data'] ||
        typeof b['data'] !== 'object' ||
        Array.isArray(b['data']))
        return false;
    return true;
}
// ── POST /api/ingest ──────────────────────────────────────────────────────────
//
// Machine-facing route — NOT protected by JWT.
// Authentication is performed via the project api_key embedded in the body
// (or optionally the x-api-key header, for devices that can't set a body field).
router.post('/ingest', async (req, res) => {
    // Allow api_key from header as a fallback for constrained devices (e.g. ESP32
    // that can't easily set a JSON body field alongside sensor data)
    const headerKey = req.headers['x-api-key'];
    const bodyWithKey = { ...req.body };
    if (typeof headerKey === 'string' && !bodyWithKey['api_key']) {
        bodyWithKey['api_key'] = headerKey;
    }
    if (!validatePayload(bodyWithKey)) {
        res.status(400).json({
            error: 'Invalid payload. Required: api_key (string), device_name (string ≤255), ' +
                'timestamp (ISO 8601), data (object).',
        });
        return;
    }
    const { api_key, device_name, timestamp, data } = bodyWithKey;
    const parsedTimestamp = new Date(timestamp);
    if (isNaN(parsedTimestamp.getTime())) {
        res.status(400).json({ error: 'Invalid timestamp: must be a valid ISO 8601 date string.' });
        return;
    }
    // Resolve api_key → project_id
    const project = await db_1.pool.query('SELECT id FROM projects WHERE api_key = $1', [api_key]);
    if ((project.rowCount ?? 0) === 0) {
        res.status(401).json({ error: 'Unauthorized.' });
        return;
    }
    const projectId = project.rows[0]?.id;
    await db_1.pool.query(`INSERT INTO telemetry (project_id, device_name, timestamp, data)
     VALUES ($1, $2, $3, $4)`, [projectId, device_name.trim(), parsedTimestamp, data]);
    res.status(200).json({ success: true, message: 'Telemetry ingested.' });
});
exports.default = router;
//# sourceMappingURL=ingest.js.map