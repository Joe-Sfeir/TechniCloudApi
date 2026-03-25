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

  const body = req.body as Record<string, unknown>;
  const { license_key, project_key, project_name, node_name, machine_id: provided_machine_id } = body;

  // ── Online project activation path ────────────────────────────────────────
  if (typeof project_key === 'string' && project_key.trim().length > 0) {
    if (typeof project_name !== 'string' || project_name.trim().length === 0) {
      res.status(400).json({ error: 'project_name is required.' });
      return;
    }

    const projectResult = await pool.query<{
      id: number;
      name: string;
      tier: number;
      max_activations: number;
      expires_at: Date | null;
      is_active: boolean;
      allowed_meters: unknown[];
      protocols: string;
    }>(
      `SELECT id, name, tier, max_activations, expires_at, is_active, allowed_meters, protocols
       FROM projects WHERE project_key = $1`,
      [project_key.trim()],
    );

    if ((projectResult.rowCount ?? 0) === 0) {
      res.status(404).json({ error: 'Project not found.' });
      return;
    }

    const project = projectResult.rows[0]!;

    if (!project.is_active) {
      res.status(403).json({ error: 'Project is deactivated.' });
      return;
    }

    if (project.expires_at && new Date(project.expires_at) <= new Date()) {
      res.status(403).json({ error: 'Project has expired.' });
      return;
    }

    if (project.name.trim().toLowerCase() !== (project_name as string).trim().toLowerCase()) {
      res.status(400).json({ error: 'project_name does not match.' });
      return;
    }

    const resolvedNodeName = typeof node_name === 'string' ? node_name.trim() : '';

    // ── If client sent a stable machine_id, check for existing activation ────
    if (typeof provided_machine_id === 'string' && provided_machine_id.trim().length > 0) {
      const trimmedMachineId = provided_machine_id.trim();

      const existingResult = await pool.query<{
        id: number;
        project_id: number;
        machine_id: string;
        machine_api_key: string;
        is_active: boolean;
      }>(
        `SELECT id, project_id, machine_id, machine_api_key, is_active
         FROM project_activations WHERE machine_id = $1`,
        [trimmedMachineId],
      );

      if ((existingResult.rowCount ?? 0) > 0) {
        const existing = existingResult.rows[0]!;

        if (existing.project_id === project.id) {
          // Same project — reuse the existing activation
          if (!existing.is_active) {
            await pool.query(
              `UPDATE project_activations SET is_active = true, last_seen = NOW() WHERE id = $1`,
              [existing.id],
            );
          }

          res.status(200).json({
            machine_id:      existing.machine_id,
            machine_api_key: existing.machine_api_key,
            project_id:      project.id,
            project_name:    project.name,
            tier:            project.tier,
            allowed_meters:  project.allowed_meters,
            protocols:       project.protocols,
            expires_at:      project.expires_at,
            config:          null,
          });
          return;
        }

        // Different project — deactivate the old activation before creating a new one
        await pool.query(
          `UPDATE project_activations SET is_active = false WHERE id = $1`,
          [existing.id],
        );
      }
    }

    // ── New activation — check slot availability ──────────────────────────────
    const countResult = await pool.query<{ count: string }>(
      `SELECT COUNT(*) AS count FROM project_activations WHERE project_id = $1 AND is_active = true`,
      [project.id],
    );
    const activeCount = parseInt(countResult.rows[0]?.count ?? '0', 10);

    if (activeCount >= project.max_activations) {
      res.status(403).json({ error: 'Maximum activations reached for this project.' });
      return;
    }

    const machine_id = typeof provided_machine_id === 'string' && provided_machine_id.trim().length > 0
      ? provided_machine_id.trim()
      : `TDAQ-NODE-${randomBytes(16).toString('hex')}`;
    const machine_api_key = `TDAQ-MAC-${randomBytes(20).toString('hex')}`;

    try {
      await pool.query(
        `INSERT INTO project_activations (project_id, machine_id, machine_api_key, node_name)
         VALUES ($1, $2, $3, $4)`,
        [project.id, machine_id, machine_api_key, resolvedNodeName],
      );
    } catch (err: unknown) {
      if (
        typeof err === 'object' && err !== null &&
        'code' in err && (err as Record<string, unknown>)['code'] === '23505'
      ) {
        res.status(409).json({ error: 'This machine ID is already active on another project.' });
        return;
      }
      throw err;
    }

    res.status(201).json({
      machine_id,
      machine_api_key,
      project_id:     project.id,
      project_name:   project.name,
      tier:           project.tier,
      allowed_meters: project.allowed_meters,
      protocols:      project.protocols,
      expires_at:     project.expires_at,
      config:         null,
    });
    return;
  }

  // ── Legacy offline license path ───────────────────────────────────────────
  if (typeof license_key !== 'string' || license_key.trim().length === 0) {
    res.status(400).json({ error: 'license_key or project_key is required.' });
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

// ── GET /api/machine/config ───────────────────────────────────────────────────

router.get('/config', async (req: Request, res: Response): Promise<void> => {
  const apiKey = req.headers['x-api-key'];

  if (typeof apiKey !== 'string' || apiKey.trim().length === 0) {
    res.status(401).json({ error: 'Missing x-api-key header.' });
    return;
  }

  const activationResult = await pool.query<{
    id: number;
    project_id: number;
    machine_id: string;
    is_active: boolean;
    project_name: string;
    tier: number;
    allowed_meters: unknown[];
    protocols: string;
    expires_at: Date | null;
    project_active: boolean;
  }>(
    `SELECT pa.id, pa.project_id, pa.machine_id, pa.is_active,
            p.name AS project_name, p.tier, p.allowed_meters, p.protocols,
            p.expires_at, p.is_active AS project_active
     FROM project_activations pa
     JOIN projects p ON p.id = pa.project_id
     WHERE pa.machine_api_key = $1`,
    [apiKey.trim()],
  );

  if ((activationResult.rowCount ?? 0) === 0) {
    res.status(401).json({ error: 'Unauthorized.' });
    return;
  }

  const act = activationResult.rows[0]!;

  if (!act.is_active || !act.project_active || (act.expires_at && new Date(act.expires_at) <= new Date())) {
    res.status(401).json({ error: 'Project deactivated.' });
    return;
  }

  await pool.query(
    `UPDATE project_activations SET last_seen = NOW() WHERE id = $1`,
    [act.id],
  );

  const configResult = await pool.query<{ config_version: number; desired_config: unknown }>(
    `SELECT config_version, desired_config
     FROM project_configs WHERE project_id = $1 AND machine_id = $2
     ORDER BY config_version DESC LIMIT 1`,
    [act.project_id, act.machine_id],
  );

  const cfg = configResult.rows[0];

  res.status(200).json({
    project_name:   act.project_name,
    tier:           act.tier,
    allowed_meters: act.allowed_meters,
    protocols:      act.protocols,
    expires_at:     act.expires_at,
    is_active:      true,
    config_version: cfg?.config_version ?? 0,
    desired_config: cfg?.desired_config ?? null,
  });
});

// ── POST /api/machine/status ──────────────────────────────────────────────────

router.post('/status', async (req: Request, res: Response): Promise<void> => {
  const apiKey = req.headers['x-api-key'];

  if (typeof apiKey !== 'string' || apiKey.trim().length === 0) {
    res.status(401).json({ error: 'Missing x-api-key header.' });
    return;
  }

  const { polling_state } = req.body as Record<string, unknown>;

  if (polling_state !== 'running' && polling_state !== 'stopped' && polling_state !== 'fault') {
    res.status(400).json({ error: 'polling_state must be "running", "stopped", or "fault".' });
    return;
  }

  const result = await pool.query(
    `UPDATE project_activations
     SET polling_state = $1, last_seen = NOW()
     WHERE machine_api_key = $2
     RETURNING id`,
    [polling_state, apiKey.trim()],
  );

  if ((result.rowCount ?? 0) === 0) {
    res.status(401).json({ error: 'Unauthorized.' });
    return;
  }

  res.status(200).json({ success: true });
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

  const trimmedKey = apiKey.trim();

  // Try online path: machine_api_key in project_activations
  let projectId: number | undefined;
  let activationId: number | undefined;

  const onlineResult = await pool.query<{
    project_id: number;
    activation_id: number;
    config_pending: boolean;
    profiles_pending: boolean;
    allowed_meters: unknown[];
    protocols: string;
    tier: number;
  }>(
    `SELECT pa.project_id, pa.id AS activation_id,
            pa.config_pending, pa.profiles_pending,
            p.allowed_meters, p.protocols, p.tier
     FROM project_activations pa
     JOIN projects p ON p.id = pa.project_id
     WHERE pa.machine_api_key = $1
       AND pa.is_active = true
       AND p.is_active = true
       AND (p.expires_at IS NULL OR p.expires_at > NOW())`,
    [trimmedKey],
  );

  if ((onlineResult.rowCount ?? 0) > 0) {
    projectId    = onlineResult.rows[0]!.project_id;
    activationId = onlineResult.rows[0]!.activation_id;
  } else {
    // Fall back to legacy api_key on projects table
    const legacyResult = await pool.query<{ id: number }>(
      'SELECT id FROM projects WHERE api_key = $1',
      [trimmedKey],
    );

    if ((legacyResult.rowCount ?? 0) === 0) {
      res.status(401).json({ error: 'Unauthorized.' });
      return;
    }

    projectId = legacyResult.rows[0]?.id;
  }

  const { telemetry_array, active_devices, thresholds, polling_state } = req.body as Record<string, unknown>;

  const resolvedPollingState =
    polling_state === 'running' || polling_state === 'stopped' ? polling_state : 'running';

  if (active_devices !== undefined) {
    if (!Array.isArray(active_devices) || !active_devices.every((d) => typeof d === 'string')) {
      res.status(400).json({ error: 'active_devices must be an array of strings.' });
      return;
    }
  }

  if (thresholds !== undefined) {
    if (typeof thresholds !== 'object' || thresholds === null || Array.isArray(thresholds)) {
      res.status(400).json({ error: 'thresholds must be an object.' });
      return;
    }
  }

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

  // Online path: update last_seen, store polling state, clear pending flags, then deliver queued data
  if (activationId !== undefined) {
    const { project_id, config_pending, profiles_pending } = onlineResult.rows[0]!;

    // Clear flags atomically — values were already captured above before this UPDATE
    await pool.query(
      `UPDATE project_activations
       SET last_seen        = NOW(),
           active_devices   = $2,
           thresholds       = $3,
           polling_state    = $4,
           config_pending   = false,
           profiles_pending = false
       WHERE id = $1`,
      [activationId, JSON.stringify(active_devices ?? []), JSON.stringify(thresholds ?? {}), resolvedPollingState],
    );

    // Always fetch the latest config for version tracking
    const configResult = await pool.query<{ config_version: number; desired_config: unknown }>(
      `SELECT config_version, desired_config
       FROM project_configs
       WHERE project_id = $1 AND machine_id = (
         SELECT machine_id FROM project_activations WHERE id = $2
       )
       ORDER BY config_version DESC LIMIT 1`,
      [project_id, activationId],
    );

    const cfg = configResult.rows[0];

    const responseBody: Record<string, unknown> = {
      success:        true,
      inserted:       result.rowCount ?? 0,
      config_version: cfg?.config_version ?? 0,
      desired_config: cfg?.desired_config ?? null,
    };

    if (config_pending) {
      responseBody['config_update'] = true;
      responseBody['allowed_meters'] = onlineResult.rows[0]!.allowed_meters;
      responseBody['protocols']      = onlineResult.rows[0]!.protocols;
      responseBody['tier']           = onlineResult.rows[0]!.tier;
    }

    if (profiles_pending) {
      const profilesResult = await pool.query<{
        id: number; model: string; display_name: string; endianness: string;
        baud_rate: number | null; parity: string | null; registers: unknown;
      }>(
        `SELECT id, model, display_name, endianness, baud_rate, parity, registers
         FROM meter_profiles ORDER BY model`,
      );
      responseBody['profiles_update'] = true;
      responseBody['meter_profiles']  = profilesResult.rows;
    }

    res.status(200).json(responseBody);
    return;
  }

  res.status(200).json({ success: true, inserted: result.rowCount ?? 0 });
});

export default router;
