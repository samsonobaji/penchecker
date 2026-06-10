'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { DB } = require('../db');
const { signToken } = require('../auth');
const { sendWelcomeEmail, sendPasswordResetEmail } = require('../mailer');

const router = express.Router();

router.post('/signup', async (req, res) => {
  try {
    const { email, password, full_name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await DB.get('SELECT id FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

    const id = uuidv4();
    const hash = await bcrypt.hash(password, 12);
    const referralCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    const verifyToken = uuidv4();

    await DB.run(
      `INSERT INTO users (id, email, password_hash, full_name, referral_code, email_verify_token) VALUES (?, ?, ?, ?, ?, ?)`,
      [id, email.toLowerCase().trim(), hash, full_name || '', referralCode, verifyToken]
    );

    const token = signToken({ id, email: email.toLowerCase().trim(), role: 'user', plan: 'free' });
    const user = await DB.get('SELECT id, email, full_name, role, plan, onboarding_completed FROM users WHERE id = ?', [id]);

    // Send welcome email (non-blocking)
    const firstName = (full_name || email.split('@')[0]).split(' ')[0];
    sendWelcomeEmail(email.toLowerCase().trim(), firstName).catch(() => {});

    res.status(201).json({ token, user });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Could not create account' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await DB.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.is_suspended) return res.status(403).json({ error: 'Your account has been suspended' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signToken({ id: user.id, email: user.email, role: user.role, plan: user.plan });
    res.json({ token, user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role, plan: user.plan, onboarding_completed: user.onboarding_completed } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  const user = await DB.get('SELECT id FROM users WHERE email = ?', [email.toLowerCase().trim()]);
  if (user) {
    const token = uuidv4();
    const expires = new Date(Date.now() + 3600000).toISOString();
    await DB.run('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?', [token, expires, user.id]);
    // Send real password reset email (non-blocking)
    sendPasswordResetEmail(email.toLowerCase().trim(), token).catch(() => {
      console.log(`[Auth] Email failed — reset link: ${process.env.APP_URL || 'http://localhost:3000'}/reset-password.html?token=${token}`);
    });
  }
  res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
});

router.post('/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const user = await DB.get('SELECT * FROM users WHERE reset_token = ?', [token]);
    if (!user || new Date(user.reset_token_expires) < new Date()) return res.status(400).json({ error: 'Invalid or expired token' });
    const hash = await bcrypt.hash(password, 12);
    await DB.run('UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', [hash, user.id]);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Reset failed' });
  }
});

router.post('/social', async (req, res) => {
  try {
    const { email, full_name, provider } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    let user = await DB.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    
    if (!user) {
      const id = uuidv4();
      const randomPassword = uuidv4();
      const hash = await bcrypt.hash(randomPassword, 12);
      const referralCode = Math.random().toString(36).substring(2, 10).toUpperCase();

      await DB.run(
        `INSERT INTO users (id, email, password_hash, full_name, referral_code, email_verified) VALUES (?, ?, ?, ?, ?, 1)`,
        [id, email.toLowerCase().trim(), hash, full_name || '', referralCode]
      );
      
      user = await DB.get('SELECT * FROM users WHERE id = ?', [id]);
    }

    if (user.is_suspended) return res.status(403).json({ error: 'Your account has been suspended' });

    const token = signToken({ id: user.id, email: user.email, role: user.role, plan: user.plan });
    res.json({ token, user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role, plan: user.plan, onboarding_completed: user.onboarding_completed } });
  } catch (err) {
    console.error('Social auth error:', err);
    res.status(500).json({ error: 'Social authentication failed' });
  }
});

module.exports = router;
