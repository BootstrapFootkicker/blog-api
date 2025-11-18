const jwt = require('jsonwebtoken');

function authRequired(req, res, next) {
    const authHeader = req.headers.authorization || '';

    const [scheme, token] = authHeader.split(' ');

    if (scheme !== 'Bearer' || !token) {
        return res.status(401).json({ message: 'Authorization header missing or malformed' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload; // { id, role, username, email }
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
}

function adminOnly(req, res, next) {
    if (!req.user || req.user.role !== 'ADMIN') {
        return res.status(403).json({ message: 'Admin only' });
    }
    next();
}

module.exports = { authRequired, adminOnly };
