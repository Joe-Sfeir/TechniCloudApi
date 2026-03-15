# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`technidaq-cloud-api` is a REST API for the TechniDAQ industrial SCADA SaaS platform. It receives telemetry data (and eventually SQLite backups) from edge Windows desktop apps and persists them to PostgreSQL. Deployment target: Google Cloud Run.

Stack: **Express 5 + TypeScript (strict, ESM) + PostgreSQL (`pg` driver, no ORM)**.

## Commands

```bash
npm start          # Run with ts-node (development)
npm run build      # Compile TypeScript → dist/
```

Copy `.env.example` to `.env` and fill in `DATABASE_URL` before running.

## TypeScript Configuration

The project uses **ESM** (`"type": "module"` in `package.json`) with `"module": "nodenext"` in `tsconfig.json`. Key implications:

- All relative imports **must** use `.js` extensions (e.g. `import { pool } from './db.js'`), even though source files are `.ts`
- `verbatimModuleSyntax` is on — type-only imports **must** use `import type`
- `noUncheckedIndexedAccess` + `exactOptionalPropertyTypes` are enabled — index access returns `T | undefined`, and optional properties cannot be assigned `undefined` explicitly
- ts-node ESM mode is enabled via `"ts-node": { "esm": true }` in `package.json`

## Architecture

```
src/
  index.ts          Express app, middleware, global error handler, SIGTERM shutdown
  db.ts             pg Pool, startup SSL config, initDb() creates schema + indices
  routes/
    ingest.ts       POST /api/v1/telemetry — validates, parses, INSERTs telemetry
```

**Request lifecycle:** `cors` → `express.json({ limit: '1mb' })` → route → global error handler (4-arg signature; Express 5 auto-propagates async errors).

**Database:** Raw SQL via `pg.Pool`. `initDb()` is idempotent (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`). The `telemetry` table has a composite index on `(license_key, timestamp DESC)` for the expected per-tenant time-range query pattern.

**Cloud Run specifics:**
- `GET /health` — liveness/readiness probe
- `SIGTERM` handler drains the HTTP server then calls `pool.end()` before exiting
- SSL is enabled automatically when `NODE_ENV=production`; `rejectUnauthorized: false` is intentional for Cloud SQL Auth Proxy setups
