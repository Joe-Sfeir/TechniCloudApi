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
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role             VARCHAR(20)  NOT NULL DEFAULT 'CLIENT';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_requested  BOOLEAN      NOT NULL DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_code  VARCHAR(6);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_expires TIMESTAMPTZ;

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
