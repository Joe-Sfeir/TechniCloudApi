import type { Request, Response, NextFunction } from 'express';
export interface JwtPayload {
    sub: number;
    email: string;
    role: string;
}
/**
 * Verifies the Bearer JWT and attaches `userId` and `role` to res.locals.
 */
export declare function requireAuth(req: Request, res: Response, next: NextFunction): void;
/**
 * Middleware factory that restricts access to the given roles.
 * Must be used after requireAuth.
 */
export declare function requireRole(...roles: string[]): (req: Request, res: Response, next: NextFunction) => void;
//# sourceMappingURL=auth.d.ts.map