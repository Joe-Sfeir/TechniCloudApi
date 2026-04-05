import { Router } from 'express';
import type { Request, Response } from 'express';
import { pool } from '../db.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

const router = Router();

router.use(requireAuth, requireRole('MASTER'));

// ── Types ─────────────────────────────────────────────────────────────────────

interface BranchInfo {
  sha: string;
  message: string;
  author: string;
  date: string;
}

interface RepoStatus {
  name: string;
  label: string;
  url: string;
  main: BranchInfo;
  dev: BranchInfo;
  devAhead: number;
  devBehind: number;
}

// ── In-memory cache ───────────────────────────────────────────────────────────

let cachedRepos: RepoStatus[] | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60_000;

// ── GitHub fetch helpers ──────────────────────────────────────────────────────

interface GithubBranchResponse {
  commit: {
    sha: string;
    commit: {
      message: string;
      author: { name: string; date: string };
    };
  };
}

interface GithubCompareResponse {
  ahead_by: number;
  behind_by: number;
}

async function fetchGitHub<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!res.ok) {
    throw new Error(`GitHub API ${res.status} for ${path}`);
  }
  return res.json() as Promise<T>;
}

function extractBranch(b: GithubBranchResponse): BranchInfo {
  return {
    sha:     b.commit.sha.slice(0, 7),
    message: b.commit.commit.message.split('\n')[0] ?? '',
    author:  b.commit.commit.author.name,
    date:    b.commit.commit.author.date,
  };
}

async function getRepoStatus(
  owner: string,
  repo: string,
  label: string,
  token: string,
): Promise<RepoStatus> {
  const [mainBranch, devBranch, compare] = await Promise.all([
    fetchGitHub<GithubBranchResponse>(`/repos/${owner}/${repo}/branches/main`, token),
    fetchGitHub<GithubBranchResponse>(`/repos/${owner}/${repo}/branches/dev`, token),
    fetchGitHub<GithubCompareResponse>(`/repos/${owner}/${repo}/compare/main...dev`, token),
  ]);

  return {
    name:      repo,
    label,
    url:       `https://github.com/${owner}/${repo}`,
    main:      extractBranch(mainBranch),
    dev:       extractBranch(devBranch),
    devAhead:  compare.ahead_by,
    devBehind: compare.behind_by,
  };
}

// ── GET /api/admin/devops/repo-status ─────────────────────────────────────────

router.get('/repo-status', async (_req: Request, res: Response): Promise<void> => {
  const token = process.env['GITHUB_TOKEN'];
  if (!token) {
    res.status(503).json({ error: 'GitHub token not configured.' });
    return;
  }

  const kvQuery = pool.query<{ key: string; value: string }>(
    `SELECT key, value FROM kv WHERE key IN ('latest_app_version', 'update_notes', 'update_url')`,
  );

  // Serve repos from cache if still fresh
  if (cachedRepos && Date.now() - cacheTimestamp < CACHE_TTL_MS) {
    const kvResult = await kvQuery;
    const map = Object.fromEntries(kvResult.rows.map((r) => [r.key, r.value]));
    res.status(200).json({
      repos: cachedRepos,
      appVersion: {
        version: map['latest_app_version'] ?? '0.1.0',
        notes:   map['update_notes']       ?? '',
        url:     map['update_url']         ?? '',
      },
    });
    return;
  }

  const repoConfigs = [
    { owner: 'Joe-Sfeir', repo: 'TechniCloudApi', label: 'Cloud API' },
    { owner: 'Joe-Sfeir', repo: 'TechniWeb',      label: 'Web' },
    { owner: 'Joe-Sfeir', repo: 'TechniDAQ',      label: 'Desktop App' },
  ];

  const [repoStatuses, kvResult] = await Promise.all([
    Promise.all(repoConfigs.map((r) => getRepoStatus(r.owner, r.repo, r.label, token))),
    kvQuery,
  ]);

  cachedRepos    = repoStatuses;
  cacheTimestamp = Date.now();

  const map = Object.fromEntries(kvResult.rows.map((r) => [r.key, r.value]));

  res.status(200).json({
    repos: repoStatuses,
    appVersion: {
      version: map['latest_app_version'] ?? '0.1.0',
      notes:   map['update_notes']       ?? '',
      url:     map['update_url']         ?? '',
    },
  });
});

// ── POST /api/admin/devops/publish-update ─────────────────────────────────────

router.post('/publish-update', async (req: Request, res: Response): Promise<void> => {
  const { version, notes, url } = req.body as { version?: string; notes?: string; url?: string };

  if (!version || typeof version !== 'string' || !version.trim()) {
    res.status(400).json({ error: 'version is required.' });
    return;
  }
  if (!url || typeof url !== 'string' || !url.trim()) {
    res.status(400).json({ error: 'url is required.' });
    return;
  }

  await pool.query(
    `INSERT INTO kv (key, value) VALUES
       ('latest_app_version', $1),
       ('update_notes',       $2),
       ('update_url',         $3)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [version.trim(), (notes ?? '').trim(), url.trim()],
  );

  // Invalidate the in-memory repo cache so the next GET returns fresh KV data.
  cachedRepos    = null;
  cacheTimestamp = 0;

  res.status(200).json({ ok: true });
});

export default router;
