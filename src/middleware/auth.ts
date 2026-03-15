import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface JwtPayload {
  sub: number;
  email: string;
  role: string;
}

function getJwtSecret(): string {
  const secret = process.env['JWT_SECRET'];
  if (!secret) throw new Error('JWT_SECRET environment variable is required');
  return secret;
}

/**
 * Verifies the Bearer JWT and attaches `userId` and `role` to res.locals.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized.' });
    return;
  }

  const token = header.slice(7);

  let payload: JwtPayload;
  try {
    payload = jwt.verify(token, getJwtSecret()) as unknown as JwtPayload;
  } catch {
    res.status(401).json({ error: 'Unauthorized.' });
    return;
  }

  res.locals['userId'] = payload.sub;
  res.locals['role'] = payload.role;
  next();
}

/**
 * Middleware factory that restricts access to the given roles.
 * Must be used after requireAuth.
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const role = res.locals['role'] as string | undefined;
    if (!role || !roles.includes(role)) {
      res.status(403).json({ error: 'Forbidden.' });
      return;
    }
    next();
  };
}
