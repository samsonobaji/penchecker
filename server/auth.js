'use strict';
require('dotenv').config();
const jwt = require('jsonwebtoken');
const { DB } = require('./db');
const SECRET = process.env.JWT_SECRET || 'penchecker_dev_secret';

async function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, SECRET);
    const user = await DB.get('SELECT id FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(401).json({ error: 'User does not exist' });
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function signToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

module.exports = { auth, signToken };
