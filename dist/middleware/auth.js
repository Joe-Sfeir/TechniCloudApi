"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAuth = requireAuth;
exports.requireRole = requireRole;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function getJwtSecret() {
    const secret = process.env['JWT_SECRET'];
    if (!secret)
        throw new Error('JWT_SECRET environment variable is required');
    return secret;
}
/**
 * Verifies the Bearer JWT and attaches `userId` and `role` to res.locals.
 */
function requireAuth(req, res, next) {
    const header = req.headers['authorization'];
    if (!header || !header.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Unauthorized.' });
        return;
    }
    const token = header.slice(7);
    let payload;
    try {
        payload = jsonwebtoken_1.default.verify(token, getJwtSecret());
    }
    catch {
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
function requireRole(...roles) {
    return (req, res, next) => {
        const role = res.locals['role'];
        if (!role || !roles.includes(role)) {
            res.status(403).json({ error: 'Forbidden.' });
            return;
        }
        next();
    };
}
//# sourceMappingURL=auth.js.map