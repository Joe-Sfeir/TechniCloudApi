import { Router } from 'express';
import express from 'express';
import type { Request, Response } from 'express';
import { createDecipheriv, createHash, randomBytes } from 'crypto';
import { pool } from '../db';

const router = Router();

// Machine ingest payloads can be large batches — override the global 1 mb limit.
router.use(express.json({ limit: '5mb' }));

// ── Helpers ───────────────────────────────────────────────────────────────────

function getMasterKey(): string {
  const key = process.env['MASTER_KEY'];
  if (!key || key.length !== 64) throw new Error('CRITICAL: MASTER_KEY is missing or invalid length');
  return key;
}

interface LicensePayload {
  username: string;
  project_name: string;
  allowed_meters: string[];
  tier: number;
  protocols: string;
  mode: string;
  created_at: number;
  duration_days: number;
  ttl_hours: number;
}

/**
 * Decrypts an AES-256-GCM license blob produced by POST /api/admin/generate-license.
 * Format: base64( IV[12] | Ciphertext[n] | AuthTag[16] )
 * Key: Buffer.from(MASTER_KEY, 'hex') — 64 hex chars = 32 bytes, no hashing.
 */
function decryptLicense(licenseKey: string): LicensePayload {
  const aesKey = Buffer.from(getMasterKey(), 'hex');

  const blob = Buffer.from(licenseKey, 'base64');
  if (blob.length < 29) throw new Error('License blob too short to be valid.');

  const iv         = blob.subarray(0, 12);
  const authTag    = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(12, blob.length - 16);

  const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8')) as LicensePayload;
}

// ── POST /api/machine/activate ────────────────────────────────────────────────

router.post('/activate', async (req: Request, res: Response): Promise<void> => {
  console.log('[activate] Activation attempt body:', req.body);

  const { license_key } = req.body as Record<string, unknown>;

  if (typeof license_key !== 'string' || license_key.trim().length === 0) {
    res.status(400).json({ error: 'license_key is required.' });
    return;
  }

  // Decrypt and verify the license server-side — the desktop cannot forge this
  // without MASTER_KEY.
  let payload: LicensePayload;
  try {
    payload = decryptLicense(license_key.trim());
  } catch (err) {
    console.error('[activate] Decryption failed:', err);
    res.status(401).json({ error: 'AES decryption failed on cloud.' });
    return;
  }

  // Check expiry — derived from created_at + ttl_hours (no expires_at field in payload)
  const expiresAt = payload.created_at + Math.floor(payload.ttl_hours * 3600);
  if (Math.floor(Date.now() / 1000) > expiresAt) {
    res.status(403).json({ error: 'License has expired.' });
    return;
  }

  // Validate required fields
  if (!payload.project_name || !payload.username || !payload.mode) {
    res.status(400).json({ error: 'License payload is missing required fields.' });
    return;
  }

  const tier = payload.tier ?? 1;

  // Fingerprint prevents replay: same license blob cannot activate twice
  const fingerprint = createHash('sha256').update(license_key.trim()).digest('hex');

  const machineApiKey = `TDAQ-MAC-${randomBytes(20).toString('hex')}`;

  try {
    const result = await pool.query<{
      id: number;
      name: string;
      tier: number;
      api_key: string;
      created_at: Date;
    }>(
      `INSERT INTO projects (user_id, name, tier, api_key, license_fingerprint)
       VALUES (NULL, $1, $2, $3, $4)
       RETURNING id, name, tier, api_key, created_at`,
      [payload.project_name.trim(), tier, machineApiKey, fingerprint],
    );

    const project = result.rows[0];
    res.status(201).json({
      machine_api_key: project?.api_key,
      project_id:      project?.id,
      project_name:    project?.name,
      tier:            project?.tier,
      expires_at:      expiresAt,
    });
  } catch (err: unknown) {
    // Unique violation on license_fingerprint — this license was already activated
    if (
      typeof err === 'object' && err !== null &&
      'code' in err && (err as Record<string, unknown>)['code'] === '23505'
    ) {
      res.status(409).json({ error: 'This license has already been activated on another machine.' });
      return;
    }
    throw err; // let Express global handler catch anything else
  }
});

// ── POST /api/machine/ingest ──────────────────────────────────────────────────

interface TelemetryRow {
  device_name: string;
  timestamp: string;
  data: Record<string, unknown>;
}

function validateRow(row: unknown, index: number): row is TelemetryRow {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
  const r = row as Record<string, unknown>;

  if (typeof r['device_name'] !== 'string' || r['device_name'].trim().length === 0 || r['device_name'].length > 255)
    throw new Error(`Row ${index}: device_name must be a non-empty string ≤255 chars.`);

  if (typeof r['timestamp'] !== 'string')
    throw new Error(`Row ${index}: timestamp must be a string.`);

  // Require an explicit UTC offset so PostgreSQL never interprets the value as
  // session-local time. The desktop app must send UTC (e.g. "2024-03-21T09:00:00Z").
  if (!/[Zz]|[+-]\d{2}:?\d{2}$/.test(r['timestamp'] as string))
    throw new Error(`Row ${index}: timestamp must include a UTC offset (e.g. Z or +00:00).`);

  if (isNaN(new Date(r['timestamp']).getTime()))
    throw new Error(`Row ${index}: timestamp is not a valid ISO 8601 date.`);

  if (!r['data'] || typeof r['data'] !== 'object' || Array.isArray(r['data']))
    throw new Error(`Row ${index}: data must be an object.`);

  return true;
}

router.post('/ingest', async (req: Request, res: Response): Promise<void> => {
  const apiKey = req.headers['x-api-key'];

  if (typeof apiKey !== 'string' || apiKey.trim().length === 0) {
    res.status(401).json({ error: 'Missing x-api-key header.' });
    return;
  }

  // Resolve api_key → project_id
  const projectResult = await pool.query<{ id: number }>(
    'SELECT id FROM projects WHERE api_key = $1',
    [apiKey.trim()],
  );

  if ((projectResult.rowCount ?? 0) === 0) {
    res.status(401).json({ error: 'Unauthorized.' });
    return;
  }

  const projectId = projectResult.rows[0]?.id;

  const { telemetry_array } = req.body as Record<string, unknown>;

  if (!Array.isArray(telemetry_array) || telemetry_array.length === 0) {
    res.status(400).json({ error: 'telemetry_array must be a non-empty array.' });
    return;
  }

  if (telemetry_array.length > 500) {
    res.status(400).json({ error: 'telemetry_array exceeds maximum batch size of 500 rows.' });
    return;
  }

  // Validate every row before touching the DB — fail the whole batch or nothing
  try {
    telemetry_array.forEach((row, i) => validateRow(row, i));
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid row.' });
    return;
  }

  // Single bulk INSERT via jsonb_array_elements — one round-trip regardless of batch size
  const result = await pool.query(
    `INSERT INTO telemetry (project_id, device_name, timestamp, data)
     SELECT $1,
            elem->>'device_name',
            (elem->>'timestamp')::timestamptz,
            elem->'data'
     FROM jsonb_array_elements($2::jsonb) AS elem`,
    [projectId, JSON.stringify(telemetry_array)],
  );

  res.status(200).json({ success: true, inserted: result.rowCount ?? 0 });
});

export default router;
