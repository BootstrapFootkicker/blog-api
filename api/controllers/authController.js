const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const prisma = require('../prismaClient');

const SALT_ROUNDS = 10;

async function register(req, res) {
    try {
        const { email, username, password } = req.body;

        if (!email || !username || !password) {
            return res.status(400).json({ message: 'email, username, and password are required' });
        }

        const existing = await prisma.user.findFirst({
            where: { OR: [{ email }, { username }] }
        });

        if (existing) {
            return res.status(409).json({ message: 'email or username already in use' });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        const user = await prisma.user.create({
            data: {
                email,
                username,
                passwordHash
            }
        });

        res.status(201).json({ id: user.id, email: user.email, username: user.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'server error' });
    }
}

async function login(req, res) {
    try {
        const { emailOrUsername, password } = req.body;

        const user = await prisma.user.findFirst({
            where: {
                OR: [
                    { email: emailOrUsername },
                    { username: emailOrUsername }
                ]
            }
        });

        if (!user) {
            return res.status(401).json({ message: 'invalid credentials' });
        }

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) {
            return res.status(401).json({ message: 'invalid credentials' });
        }

        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                username: user.username,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'server error' });
    }
}

module.exports = { register, login };
