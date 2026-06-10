'use strict';
require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { startScheduler } = require('./scheduler');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Trust proxy (for correct IP behind Nginx/load balancer) ─────────────────
app.set('trust proxy', 1);

// ─── Security headers via Helmet ──────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // We manage CSP per-page
  crossOriginEmbedderPolicy: false,
}));

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));

// ─── Body parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
// Global: 300 requests per minute per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
  skip: (req) => req.path === '/api/health',
});
app.use(globalLimiter);

// Auth routes: 15 requests per minute per IP (prevent brute force)
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please wait a minute.' },
});

// Scan creation: 10 scans per minute per IP (prevent scan abuse)
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Scan rate limit exceeded. Please wait before starting another scan.' },
});

// ─── Request logger ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/scans/') || !req.path.endsWith('/progress')) {
    console.log(`[${new Date().toISOString().substring(11, 19)}] ${req.method} ${req.path}`);
  }
  next();
});

// ─── Static files (frontend) ──────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public')));

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth',    authLimiter, require('./routes/auth'));
app.use('/api/scans',   scanLimiter, require('./routes/scans'));
app.use('/api/domains', require('./routes/domains'));
app.use('/api/users',   require('./routes/users'));

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({
  status: 'ok',
  version: '2.0.0',
  timestamp: new Date().toISOString(),
  environment: process.env.NODE_ENV || 'development',
}));

// ─── SPA fallback — serve HTML for non-API routes ────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  const fs = require('fs');
  const filePath = path.join(__dirname, '..', 'public',
    req.path.endsWith('.html') ? req.path : req.path + (req.path.includes('.') ? '' : '/index.html'));
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
  }
});

// ─── Error handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ██████╗ ███████╗███╗   ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ ');
  console.log('  ██╔══██╗██╔════╝████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗');
  console.log('  ██████╔╝█████╗  ██╔██╗ ██║██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝');
  console.log('  ██╔═══╝ ██╔══╝  ██║╚██╗██║██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗');
  console.log('  ██║     ███████╗██║ ╚████║╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║');
  console.log('  ╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝');
  console.log('');
  console.log(`  Version             v2.0.0`);
  console.log(`  Server              http://localhost:${PORT}`);
  const dbInfo = process.env.DB_TYPE === 'postgres'
    ? `PostgreSQL (${process.env.PGHOST || 'localhost'}:${process.env.PGPORT || '5000'})`
    : (process.env.DB_PATH || './data/penchecker.db');
  console.log(`  Database            ${dbInfo}`);
  console.log(`  Scanner             Real HTTP-based (7 check modules)`);
  console.log(`  Rate limiting       ✓ Enabled`);
  console.log(`  Security headers    ✓ Helmet active`);
  console.log(`  Email notifications ✓ ${process.env.SMTP_USER ? 'SMTP configured' : 'Add SMTP_USER/SMTP_PASS to .env'}`);
  console.log('');

  // Start monitoring scheduler
  startScheduler();
});
