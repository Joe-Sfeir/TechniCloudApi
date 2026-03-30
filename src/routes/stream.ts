import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { pool } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { addClient, removeClient, getClientCount } from '../sse.js';

const router = Router();

// EventSource can't set custom headers, so accept JWT as ?token= query param
// and inject it as Authorization header before requireAuth runs.
function tokenFromQuery(req: Request, _res: Response, next: NextFunction): void {
  const token = req.query['token'];
  if (typeof token === 'string' && !req.headers['authorization']) {
    req.headers['authorization'] = `Bearer ${token}`;
  }
  next();
}

router.get('/telemetry/stream/:projectId', tokenFromQuery, requireAuth, async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const userId = res.locals['userId'] as number;
  const role   = res.locals['role']   as string;

  // Project existence check
  const projectResult = await pool.query<{ id: number }>(
    'SELECT id FROM projects WHERE id = $1',
    [projectId],
  );
  if (!projectResult.rows[0]) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  // Access control — MASTER/SUB_MASTER see all; CLIENT only assigned projects
  if (role === 'CLIENT') {
    const assignment = await pool.query(
      'SELECT 1 FROM project_assignments WHERE project_id = $1 AND user_id = $2',
      [projectId, userId],
    );
    if ((assignment.rowCount ?? 0) === 0) {
      res.status(403).json({ error: 'Forbidden.' });
      return;
    }
  }

  // SSE headers — X-Accel-Buffering: no is required for Railway/nginx proxies
  res.writeHead(200, {
    'Content-Type':      'text/event-stream',
    'Cache-Control':     'no-cache',
    'Connection':        'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  addClient(projectId, res);
  console.log(`[sse] client connected project=${projectId} total=${getClientCount(projectId)}`);
  res.write(': connected\n\n');

  // Keep-alive comment every 25s to prevent Railway proxy from killing the connection
  const keepalive = setInterval(() => {
    res.write(': keepalive\n\n');
  }, 25_000);

  req.on('close', () => {
    clearInterval(keepalive);
    removeClient(projectId, res);
    console.log(`[sse] client disconnected project=${projectId}`);
  });
});

export default router;
