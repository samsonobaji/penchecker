'use strict';
/**
 * mailer.js — Shared email sending module for PenChecker
 * Uses nodemailer with SMTP credentials from environment variables.
 * Gracefully degrades (logs to console) when SMTP is not configured.
 */
require('dotenv').config();
const nodemailer = require('nodemailer');

// Build transport — only if SMTP credentials are present
let transport = null;

function getTransport() {
  if (transport) return transport;
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return null; // SMTP not configured
  }
  transport = nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp.gmail.com',
    port:   parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_PORT === '465', // true for 465, false for 587
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: { rejectUnauthorized: false }, // Allow self-signed certs in dev
  });
  return transport;
}

/**
 * sendMail — Send a single email.
 * @param {string} to       - Recipient email address
 * @param {string} subject  - Email subject
 * @param {string} html     - HTML body
 * @returns {Promise<boolean>} - true if sent, false if skipped
 */
async function sendMail(to, subject, html) {
  const t = getTransport();
  if (!t) {
    console.log(`[Mailer] SMTP not configured — would have sent "${subject}" to ${to}`);
    return false;
  }
  try {
    const info = await t.sendMail({
      from: `"PenChecker" <${process.env.FROM_EMAIL || 'noreply@penchecker.io'}>`,
      to,
      subject,
      html,
    });
    console.log(`[Mailer] Sent "${subject}" to ${to} (${info.messageId})`);
    return true;
  } catch (err) {
    console.error(`[Mailer] Failed to send to ${to}:`, err.message);
    return false;
  }
}

// ─── Email Templates ──────────────────────────────────────────────────────────

const BASE_URL = process.env.APP_URL || 'http://localhost:3000';

function baseTemplate(content) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <style>
    body { margin:0; padding:0; background:#060608; color:#f0f0f8; font-family:'Segoe UI',Arial,sans-serif; font-size:15px; line-height:1.6; }
    .wrap { max-width:560px; margin:40px auto; padding:0 20px; }
    .card { background:#13131a; border:1px solid rgba(255,255,255,0.07); border-radius:16px; overflow:hidden; }
    .card-header { background:linear-gradient(135deg,#0d1f2d,#091318); padding:28px 32px; border-bottom:1px solid rgba(0,229,255,0.15); }
    .logo { display:flex; align-items:center; gap:10px; margin-bottom:0; }
    .logo-icon { background:#00e5ff; color:#000; width:36px; height:36px; border-radius:8px; display:inline-flex; align-items:center; justify-content:center; font-weight:800; font-size:0.85rem; }
    .logo-text { font-size:1.1rem; font-weight:800; color:#f0f0f8; }
    .logo-text span { color:#00e5ff; }
    .card-body { padding:32px; }
    h1 { font-size:1.3rem; font-weight:800; margin:0 0 16px; letter-spacing:-0.02em; }
    p { margin:0 0 16px; color:#9090a8; font-size:0.92rem; }
    p.dark { color:#f0f0f8; }
    .btn { display:inline-block; background:linear-gradient(135deg,#00e5ff,#00b4cc); color:#000 !important; text-decoration:none; padding:12px 24px; border-radius:10px; font-weight:700; font-size:0.92rem; margin:8px 0 20px; }
    .stat-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:20px 0; }
    .stat-box { background:#1a1a24; border:1px solid rgba(255,255,255,0.07); border-radius:10px; padding:14px 16px; }
    .stat-label { font-size:0.7rem; text-transform:uppercase; letter-spacing:0.06em; color:#6b6b85; margin-bottom:4px; font-family:monospace; }
    .stat-val { font-size:1.4rem; font-weight:800; }
    .score-good { color:#00ff87; }
    .score-med  { color:#ffd60a; }
    .score-bad  { color:#ff3b5c; }
    .sev-critical { color:#ff3b5c; }
    .sev-high     { color:#ff8c42; }
    .sev-medium   { color:#ffd60a; }
    .sev-low      { color:#00e5ff; }
    .divider { border:none; border-top:1px solid rgba(255,255,255,0.07); margin:24px 0; }
    .footer { text-align:center; font-size:0.75rem; color:#6b6b85; padding:20px; }
    .footer a { color:#00e5ff; text-decoration:none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="card-header">
        <div class="logo">
          <div class="logo-icon">PC</div>
          <div class="logo-text">Pen<span>Checker</span></div>
        </div>
      </div>
      <div class="card-body">${content}</div>
    </div>
    <div class="footer">
      <p>&copy; ${new Date().getFullYear()} PenChecker. <a href="${BASE_URL}/unsubscribe">Unsubscribe</a> · <a href="${BASE_URL}/privacy.html">Privacy Policy</a></p>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Welcome email sent after signup.
 */
async function sendWelcomeEmail(to, firstName) {
  const name = firstName || 'there';
  return sendMail(to, 'Welcome to PenChecker! 🛡️', baseTemplate(`
    <h1>Welcome, ${name}!</h1>
    <p class="dark">Your PenChecker account is ready. You now have access to real HTTP-based security scanning — no simulated results, just genuine findings from your actual sites.</p>
    <p>Here's what you can do right now:</p>
    <ul style="color:#9090a8;font-size:0.9rem;margin:0 0 20px;padding-left:20px;">
      <li style="margin-bottom:8px;">🔍 <strong style="color:#f0f0f8;">Run your first scan</strong> — paste any URL and get results in under 60 seconds</li>
      <li style="margin-bottom:8px;">🌐 <strong style="color:#f0f0f8;">Add your domains</strong> — verify ownership and enable automated monitoring</li>
      <li style="margin-bottom:8px;">🤖 <strong style="color:#f0f0f8;">Ask the AI assistant</strong> — get copy-paste fix code for every finding</li>
    </ul>
    <a href="${BASE_URL}/dashboard.html" class="btn">Go to Dashboard →</a>
    <hr class="divider"/>
    <p style="font-size:0.82rem;">Need help? Reply to this email or visit our <a href="${BASE_URL}/how.html" style="color:#00e5ff;">getting started guide</a>.</p>
  `));
}

/**
 * Password reset email.
 */
async function sendPasswordResetEmail(to, resetToken) {
  const resetLink = `${BASE_URL}/reset-password.html?token=${resetToken}`;
  return sendMail(to, 'Reset your PenChecker password', baseTemplate(`
    <h1>Reset Your Password</h1>
    <p class="dark">We received a request to reset the password for your PenChecker account.</p>
    <p>Click the button below to set a new password. This link expires in <strong style="color:#f0f0f8;">1 hour</strong>.</p>
    <a href="${resetLink}" class="btn">Reset Password →</a>
    <hr class="divider"/>
    <p style="font-size:0.82rem;color:#6b6b85;">If you didn't request a password reset, you can safely ignore this email. Your password won't change.</p>
    <p style="font-size:0.8rem;color:#6b6b85;word-break:break-all;">Or copy this link: ${resetLink}</p>
  `));
}

/**
 * Scan complete email — sent when a scan finishes.
 */
async function sendScanCompleteEmail(to, scan) {
  const score     = scan.security_score ?? 0;
  const scoreClass = score >= 7 ? 'score-good' : score >= 5 ? 'score-med' : 'score-bad';
  const scoreLabel = score >= 7 ? 'Good' : score >= 5 ? 'Needs Improvement' : 'Critical Issues';
  const reportUrl  = `${BASE_URL}/dashboard-report.html?id=${scan.id}`;

  const critHtml = scan.critical_count > 0
    ? `<div class="stat-box"><div class="stat-label">Critical</div><div class="stat-val sev-critical">${scan.critical_count}</div></div>`
    : '';
  const highHtml = scan.high_count > 0
    ? `<div class="stat-box"><div class="stat-label">High</div><div class="stat-val sev-high">${scan.high_count}</div></div>`
    : '';

  return sendMail(to, `Scan Complete: ${scan.target_domain} scored ${score.toFixed(1)}/10`, baseTemplate(`
    <h1>Scan Complete 🔍</h1>
    <p class="dark">Your security scan for <strong>${scan.target_domain}</strong> has finished.</p>
    <div class="stat-grid">
      <div class="stat-box">
        <div class="stat-label">Security Score</div>
        <div class="stat-val ${scoreClass}">${score.toFixed(1)}<span style="font-size:0.9rem;font-weight:400;">/10</span></div>
        <div style="font-size:0.72rem;color:#9090a8;margin-top:2px;">${scoreLabel}</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Total Findings</div>
        <div class="stat-val" style="color:#f0f0f8;">${scan.total_vulnerabilities || 0}</div>
      </div>
      ${critHtml}${highHtml}
    </div>
    <a href="${reportUrl}" class="btn">View Full Report →</a>
    <hr class="divider"/>
    <p style="font-size:0.82rem;">Scan type: ${(scan.scan_type || 'standard').toUpperCase()} · Duration: ${scan.duration_seconds || 0}s · <a href="${BASE_URL}/dashboard-ai.html" style="color:#00e5ff;">Ask AI for fixes →</a></p>
  `));
}

/**
 * Critical vulnerability alert — sent immediately when a critical finding is discovered.
 */
async function sendCriticalAlertEmail(to, scan, finding) {
  const reportUrl = `${BASE_URL}/dashboard-report.html?id=${scan.id}`;
  return sendMail(to, `🚨 Critical Vulnerability Found: ${finding.title}`, baseTemplate(`
    <h1 style="color:#ff3b5c;">Critical Vulnerability Detected</h1>
    <p class="dark">A <strong style="color:#ff3b5c;">CRITICAL</strong> security issue was found while scanning <strong>${scan.target_domain}</strong>.</p>
    <div class="stat-box" style="margin:20px 0;border-color:rgba(255,59,92,0.3);">
      <div class="stat-label">Finding</div>
      <div style="color:#f0f0f8;font-weight:700;font-size:1rem;margin:4px 0;">${finding.title}</div>
      <div style="color:#9090a8;font-size:0.85rem;">${finding.description?.substring(0, 200) || ''}...</div>
    </div>
    <p>This issue requires <strong style="color:#f0f0f8;">immediate attention</strong>. View the full report to see evidence, affected URLs, and copy-paste fix code.</p>
    <a href="${reportUrl}" class="btn">View Report & Fix →</a>
    <hr class="divider"/>
    <p style="font-size:0.82rem;color:#6b6b85;">CVSS Score: ${finding.cvss_score?.toFixed(1) || 'N/A'} · OWASP: ${finding.owasp_reference || 'N/A'}</p>
  `));
}

/**
 * Test email — sent from the Settings page.
 */
async function sendTestEmail(to) {
  return sendMail(to, '✅ PenChecker Email Test', baseTemplate(`
    <h1>Email Notifications Working!</h1>
    <p class="dark">Your email notifications are correctly configured. You'll receive alerts for:</p>
    <ul style="color:#9090a8;font-size:0.9rem;margin:0 0 20px;padding-left:20px;">
      <li style="margin-bottom:8px;">✅ Scan completion summaries with your security score</li>
      <li style="margin-bottom:8px;">🚨 Critical vulnerability alerts (immediate)</li>
      <li style="margin-bottom:8px;">🔄 Scheduled monitoring results</li>
    </ul>
    <a href="${BASE_URL}/dashboard-settings.html" class="btn">Back to Settings →</a>
  `));
}

module.exports = {
  sendMail,
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendScanCompleteEmail,
  sendCriticalAlertEmail,
  sendTestEmail,
};
