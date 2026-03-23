import pg from 'pg';

const { Pool } = pg;

if (!process.env['DATABASE_URL']) {
  throw new Error('DATABASE_URL environment variable is required');
}

const poolConfig: pg.PoolConfig = {
  connectionString: process.env['DATABASE_URL'],
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
};

// Cloud SQL (and most managed Postgres on GCP) requires SSL in production.
// rejectUnauthorized is false because Cloud Run connects via the Cloud SQL
// Auth Proxy — override by setting PGSSLMODE=require where you provide your
// own CA bundle.
if (process.env['NODE_ENV'] === 'production') {
  poolConfig.ssl = { rejectUnauthorized: false };
}

export const pool = new Pool(poolConfig);

pool.on('error', (err: Error) => {
  console.error('[db] Unexpected pool client error:', err);
});

export async function initDb(): Promise<void> {
  await pool.query(`
    -- ── Users ──────────────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS users (
      id            BIGSERIAL    PRIMARY KEY,
      email         VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT         NOT NULL,
      created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    -- Idempotent column additions — safe to run on an already-populated table
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role               VARCHAR(20)  NOT NULL DEFAULT 'CLIENT';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_requested    BOOLEAN      NOT NULL DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_code    VARCHAR(6);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_expires TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name          VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS company            VARCHAR(255);

    -- ── Projects ────────────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS projects (
      id         BIGSERIAL    PRIMARY KEY,
      user_id    BIGINT       REFERENCES users(id) ON DELETE CASCADE,
      name       VARCHAR(255) NOT NULL,
      tier       INT          NOT NULL DEFAULT 1,
      api_key    VARCHAR(255) UNIQUE NOT NULL,
      created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    -- Machine-activated projects: user_id is assigned later by an admin.
    ALTER TABLE projects ALTER COLUMN user_id DROP NOT NULL;

    -- Prevents the same license blob from activating more than one machine.
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS license_fingerprint VARCHAR(64) UNIQUE;

    CREATE INDEX IF NOT EXISTS idx_projects_user_id
      ON projects (user_id);

    CREATE INDEX IF NOT EXISTS idx_projects_api_key
      ON projects (api_key);

    -- ── Telemetry ───────────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS telemetry (
      id          BIGSERIAL    PRIMARY KEY,
      project_id  BIGINT       NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      device_name VARCHAR(255) NOT NULL,
      timestamp   TIMESTAMPTZ  NOT NULL,
      data        JSONB        NOT NULL,
      created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_telemetry_project_timestamp
      ON telemetry (project_id, timestamp DESC);

    -- ── Project Assignments ──────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS project_assignments (
      id          BIGSERIAL   PRIMARY KEY,
      project_id  BIGINT      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      user_id     BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(project_id, user_id)
    );

    CREATE INDEX IF NOT EXISTS idx_project_assignments_project_id
      ON project_assignments (project_id);

    CREATE INDEX IF NOT EXISTS idx_project_assignments_user_id
      ON project_assignments (user_id);

    -- ── License History ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS license_history (
      id             BIGSERIAL    PRIMARY KEY,
      generated_by   BIGINT       REFERENCES users(id),
      username       VARCHAR(255) NOT NULL,
      project_name   VARCHAR(255) NOT NULL,
      mode           VARCHAR(20)  NOT NULL,
      tier           INT,
      protocols      VARCHAR(20),
      allowed_meters JSONB,
      ttl_hours      INT,
      created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    -- ── Online project columns (idempotent) ──────────────────────────────────────
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS project_key     VARCHAR(255) UNIQUE;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS max_activations INT         NOT NULL DEFAULT 1;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS duration_days   INT;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS expires_at      TIMESTAMPTZ;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS is_active       BOOLEAN     NOT NULL DEFAULT true;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS allowed_meters  JSONB       DEFAULT '[]';
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS protocols       VARCHAR(20) DEFAULT 'All';
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS notes           TEXT        DEFAULT '';

    -- ── Project activations ──────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS project_activations (
      id              BIGSERIAL    PRIMARY KEY,
      project_id      BIGINT       NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      machine_id      VARCHAR(255) UNIQUE NOT NULL,
      machine_api_key VARCHAR(255) UNIQUE NOT NULL,
      node_name       VARCHAR(255) DEFAULT '',
      activated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      last_seen       TIMESTAMPTZ,
      is_active       BOOLEAN      NOT NULL DEFAULT true,
      UNIQUE(project_id, machine_id)
    );

    CREATE INDEX IF NOT EXISTS idx_project_activations_project_id
      ON project_activations (project_id);

    CREATE INDEX IF NOT EXISTS idx_project_activations_machine_api_key
      ON project_activations (machine_api_key);

    -- Allow the same machine to activate on different projects (one active at a time).
    -- The composite UNIQUE(project_id, machine_id) remains; the global UNIQUE is dropped.
    ALTER TABLE project_activations DROP CONSTRAINT IF EXISTS project_activations_machine_id_key;

    ALTER TABLE project_activations ADD COLUMN IF NOT EXISTS active_devices    JSONB       NOT NULL DEFAULT '[]';
    ALTER TABLE project_activations ADD COLUMN IF NOT EXISTS thresholds        JSONB       NOT NULL DEFAULT '{}';
    ALTER TABLE project_activations ADD COLUMN IF NOT EXISTS polling_state     VARCHAR(20) NOT NULL DEFAULT 'stopped';
    ALTER TABLE project_activations ADD COLUMN IF NOT EXISTS config_pending    BOOLEAN     NOT NULL DEFAULT false;
    ALTER TABLE project_activations ADD COLUMN IF NOT EXISTS profiles_pending  BOOLEAN     NOT NULL DEFAULT false;

    -- ── Project configs ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS project_configs (
      id             BIGSERIAL    PRIMARY KEY,
      project_id     BIGINT       NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      machine_id     VARCHAR(255) NOT NULL,
      config_version INT          NOT NULL DEFAULT 1,
      desired_config JSONB        NOT NULL DEFAULT '{}',
      current_config JSONB,
      status         VARCHAR(20)  DEFAULT 'pending',
      updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_project_configs_project_machine
      ON project_configs (project_id, machine_id);

    -- ── Meter profiles ───────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS meter_profiles (
      id           BIGSERIAL    PRIMARY KEY,
      model        VARCHAR(255) UNIQUE NOT NULL,
      display_name VARCHAR(255) NOT NULL,
      endianness   VARCHAR(10)  NOT NULL DEFAULT 'ABCD',
      baud_rate    INT          DEFAULT 19200,
      parity       VARCHAR(10)  DEFAULT 'None',
      registers    JSONB        NOT NULL DEFAULT '[]',
      created_by   BIGINT       REFERENCES users(id),
      updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    -- ── KV store ─────────────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS kv (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    INSERT INTO kv (key, value) VALUES ('max_client_sessions', '10') ON CONFLICT (key) DO NOTHING;
  `);

  // Promote the master account if it exists and hasn't been promoted yet.
  // MASTER_EMAIL is read from env so it's never hard-coded in source.
  const masterEmail = process.env['MASTER_EMAIL'];
  if (masterEmail) {
    await pool.query(
      `UPDATE users SET role = 'MASTER' WHERE email = $1 AND role != 'MASTER'`,
      [masterEmail.toLowerCase()],
    );
  }

  console.log('[db] Schema ready');
}
