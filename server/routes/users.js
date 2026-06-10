'use strict';
const express = require('express');
const { DB } = require('../db');
const { auth } = require('../auth');
const { sendTestEmail } = require('../mailer');

const router = express.Router();
router.use(auth);

router.get('/me', async (req, res) => {
  try {
    const user = await DB.get(`SELECT id, email, full_name, avatar_url, phone, role, plan, is_active, two_factor_enabled, email_notifications, whatsapp_notifications, onboarding_completed, referral_code, created_at FROM users WHERE id = ?`, [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch profile' }); }
});

router.patch('/me', async (req, res) => {
  try {
    const allowed = ['full_name', 'phone', 'email_notifications', 'whatsapp_notifications', 'slack_webhook_url', 'discord_webhook_url', 'onboarding_completed', 'two_factor_enabled', 'two_factor_secret'];
    const updates = {};
    for (const key of allowed) { if (req.body[key] !== undefined) updates[key] = req.body[key]; }
    if (!Object.keys(updates).length) return res.status(400).json({ error: 'No valid fields to update' });
    updates.updated_at = new Date().toISOString();
    const sets = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    await DB.run(`UPDATE users SET ${sets} WHERE id = ?`, [...Object.values(updates), req.user.id]);
    const updated = await DB.get('SELECT id, email, full_name, role, plan, onboarding_completed, two_factor_enabled FROM users WHERE id = ?', [req.user.id]);
    res.json({ user: updated });
  } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

router.get('/stats', async (req, res) => {
  try {
    const uid = req.user.id;
    const { c: totalScans } = await DB.get('SELECT COUNT(*) as c FROM scans WHERE user_id = ?', [uid]);
    const { c: completedScans } = await DB.get(`SELECT COUNT(*) as c FROM scans WHERE user_id = ? AND status = 'completed'`, [uid]);
    const { c: totalFindings } = await DB.get(`SELECT COALESCE(SUM(total_vulnerabilities), 0) as c FROM scans WHERE user_id = ? AND status = 'completed'`, [uid]);
    const { c: criticalFindings } = await DB.get(`SELECT COALESCE(SUM(critical_count), 0) as c FROM scans WHERE user_id = ? AND status = 'completed'`, [uid]);
    const row = await DB.get(`SELECT ROUND(AVG(security_score), 1) as s FROM scans WHERE user_id = ? AND status = 'completed' AND security_score IS NOT NULL`, [uid]);
    const { c: totalDomains } = await DB.get('SELECT COUNT(*) as c FROM domains WHERE user_id = ?', [uid]);
    const { c: verifiedDomains } = await DB.get('SELECT COUNT(*) as c FROM domains WHERE user_id = ? AND is_verified = 1', [uid]);
    res.json({ totalScans, completedScans, totalFindings: Number(totalFindings), criticalFindings: Number(criticalFindings), avgScore: row?.s || 0, totalDomains, verifiedDomains });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch stats' }); }
});

router.get('/findings', async (req, res) => {
  try {
    const findings = await DB.all(
      `SELECT v.*, s.target_url, s.target_domain 
       FROM scan_vulnerabilities v
       JOIN scans s ON v.scan_id = s.id
       WHERE s.user_id = ? AND v.is_false_positive = 0 AND v.is_remediated = 0
       ORDER BY v.created_at DESC LIMIT 20`,
      [req.user.id]
    );
    res.json({ findings });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch findings' });
  }
});

router.get('/notifications', async (req, res) => {
  try {
    const notifs = await DB.all('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    res.json({ notifications: notifs });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch notifications' }); }
});

router.patch('/notifications/:id/read', async (req, res) => {
  try {
    await DB.run('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ message: 'Marked as read' });
  } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

router.post('/notifications/read-all', async (req, res) => {
  try {
    await DB.run('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'All notifications marked as read' });
  } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

// ─── Send Test Email ──────────────────────────────────────────────────────────
router.post('/test-email', async (req, res) => {
  try {
    const user = await DB.get('SELECT email FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const sent = await sendTestEmail(user.email);
    if (sent) {
      res.json({ message: `Test email sent to ${user.email}` });
    } else {
      res.status(503).json({ error: 'SMTP not configured. Add SMTP_USER and SMTP_PASS to your .env file.' });
    }
  } catch (err) {
    console.error('Test email error:', err);
    res.status(500).json({ error: 'Failed to send test email' });
  }
});


// ─── AI Chat Sessions Routes ──────────────────────────────────────────────────
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

router.get('/ai-chat', async (req, res) => {
  try {
    const sessions = await DB.all(
      'SELECT id, scan_id, session_title, messages, created_at, updated_at FROM ai_chat_sessions WHERE user_id = ? ORDER BY updated_at DESC LIMIT 50',
      [req.user.id]
    );
    // Parse messages JSON
    sessions.forEach(s => {
      try { s.messages = JSON.parse(s.messages || '[]'); } catch { s.messages = []; }
    });
    res.json({ sessions });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch chat sessions' });
  }
});

router.post('/ai-chat', async (req, res) => {
  try {
    const { session_title, scan_id } = req.body;
    const id = uuidv4();
    await DB.run(
      'INSERT INTO ai_chat_sessions (id, user_id, scan_id, session_title, messages) VALUES (?, ?, ?, ?, ?)',
      [id, req.user.id, scan_id || null, session_title || 'Security Q&A', '[]']
    );
    const newSession = await DB.get('SELECT * FROM ai_chat_sessions WHERE id = ?', [id]);
    newSession.messages = [];
    res.status(201).json({ session: newSession });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create chat session' });
  }
});

router.get('/ai-chat/:id', async (req, res) => {
  try {
    const session = await DB.get('SELECT * FROM ai_chat_sessions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!session) return res.status(404).json({ error: 'Chat session not found' });
    try { session.messages = JSON.parse(session.messages || '[]'); } catch { session.messages = []; }
    res.json({ session });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch chat session' });
  }
});

router.patch('/ai-chat/:id', async (req, res) => {
  try {
    const { messages } = req.body;
    const session = await DB.get('SELECT id FROM ai_chat_sessions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!session) return res.status(404).json({ error: 'Chat session not found' });

    const msgString = typeof messages === 'string' ? messages : JSON.stringify(messages || []);
    await DB.run(
      'UPDATE ai_chat_sessions SET messages = ?, updated_at = datetime(\'now\') WHERE id = ?',
      [msgString, req.params.id]
    );

    const updated = await DB.get('SELECT * FROM ai_chat_sessions WHERE id = ?', [req.params.id]);
    try { updated.messages = JSON.parse(updated.messages || '[]'); } catch { updated.messages = []; }
    res.json({ session: updated });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update chat session' });
  }
});

router.delete('/ai-chat/:id', async (req, res) => {
  try {
    const session = await DB.get('SELECT id FROM ai_chat_sessions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!session) return res.status(404).json({ error: 'Chat session not found' });
    await DB.run('DELETE FROM ai_chat_sessions WHERE id = ?', [req.params.id]);
    res.json({ message: 'Chat session deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete chat session' });
  }
});

router.post('/ai-chat/:id/message', async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message content is required' });

    const session = await DB.get('SELECT * FROM ai_chat_sessions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!session) return res.status(404).json({ error: 'Chat session not found' });

    let history = [];
    try { history = JSON.parse(session.messages || '[]'); } catch { history = []; }

    // Append user message
    history.push({ role: 'user', content: message });

    // Generate AI reply
    let reply = '';
    const apiKey = process.env.GEMINI_API_KEY;

    if (apiKey) {
      try {
        // Prepare contents for Gemini API (mapping 'user'/'assistant' roles to Gemini 'user'/'model')
        const contents = history.slice(-10).map(h => ({
          role: h.role === 'user' ? 'user' : 'model',
          parts: [{ text: h.content }]
        }));

        const response = await axios.post(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
          {
            contents,
            systemInstruction: {
              parts: [{
                text: `You are an expert web security assistant for PenChecker, a security scanning SaaS. You help developers understand and fix security vulnerabilities found during website scans. 
Your responses are:
- Practical and actionable — always provide concrete fix code when possible
- Security-first but developer-friendly — no jargon without explanation
- Concise and structured — use code blocks for all code samples
- Honest about severity — critical issues need urgent attention

Always wrap code in triple backticks with the language. Keep responses focused and under 400 words unless the user asks for more detail.`
              }]
            }
          },
          { timeout: 10000 }
        );

        reply = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
      } catch (err) {
        console.error('[AI] Gemini API error, falling back to offline responder:', err.message);
      }
    }

    if (!reply) {
      // Offline smart responder
      reply = getOfflineResponse(message);
    }

    // Append assistant reply
    history.push({ role: 'assistant', content: reply });

    // Save session back to DB
    await DB.run(
      'UPDATE ai_chat_sessions SET messages = ?, updated_at = datetime(\'now\') WHERE id = ?',
      [JSON.stringify(history), req.params.id]
    );

    res.json({ reply });
  } catch (err) {
    console.error('[AI] Message endpoint error:', err);
    res.status(500).json({ error: 'Failed to process message' });
  }
});

// Helper offline responder
function getOfflineResponse(q) {
  const ql = q.toLowerCase();
  if (ql.includes('csp') || ql.includes('content-security-policy')) {
    return `**Content-Security-Policy** prevents Cross-Site Scripting (XSS) and data injection attacks by restricting the origins of resources the browser is allowed to load.

**How to fix:**
Add this header to your server's HTTP responses:

*Nginx:*
\`\`\`nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';";
\`\`\`

*Apache:*
\`\`\`apache
Header always set Content-Security-Policy "default-src 'self'"
\`\`\`

*Node.js (Helmet middleware):*
\`\`\`javascript
const helmet = require('helmet');
app.use(helmet()); // Sets a secure default CSP automatically
\`\`\``;
  }
  if (ql.includes('xss') || ql.includes('cross-site')) {
    return `**Cross-Site Scripting (XSS)** occurs when an application includes untrusted data in a web page without proper validation or escaping.

**Prevention:**
1. **Escape Output:** Always sanitize and escape variables before rendering them in HTML.
\`\`\`javascript
// Safe text assignment
element.textContent = userInput;

// Dangerous
element.innerHTML = userInput;
\`\`\`
2. Use **Content-Security-Policy (CSP)** to restrict inline scripts.
3. Mark cookies as **HttpOnly** so client-side JavaScript cannot access session tokens.`;
  }
  if (ql.includes('sql') || ql.includes('injection')) {
    return `**SQL Injection** happens when user-supplied input is directly concatenated into a SQL statement, allowing attackers to execute arbitrary SQL commands.

**Fix: Parameterized Queries**
Always use prepared statements / parameterized queries.

*Node.js sqlite3:*
\`\`\`javascript
// GOOD — Parameterized
db.all("SELECT * FROM users WHERE email = ?", [userEmail], callback);

// BAD — Concatenated (Vulnerable!)
db.all("SELECT * FROM users WHERE email = '" + userEmail + "'", callback);
\`\`\``;
  }
  if (ql.includes('hsts') || ql.includes('strict-transport')) {
    return `**HSTS (HTTP Strict Transport Security)** forces browsers to interact with your site only over secure HTTPS connections.

**Fix:**
Add this header to your server:
\`\`\`nginx
# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
\`\`\``;
  }
  if (ql.includes('x-frame') || ql.includes('clickjacking')) {
    return `**Clickjacking** is an attack where a user is tricked into clicking an element on a page that is hidden or disguised as another page.

**Fix:**
Set the **X-Frame-Options** header to prevent your site from being embedded in an iframe on other sites.
\`\`\`nginx
# Nginx
add_header X-Frame-Options "DENY" always;
# Or allow only your own site:
add_header X-Frame-Options "SAMEORIGIN" always;
\`\`\``;
  }
  return `I'm here to help with your security findings!

* **CSP & Headers:** Ask about Content-Security-Policy, HSTS, or X-Frame-Options.
* **Vulnerabilities:** Ask about XSS, SQL Injection, or Clickjacking.
* **Remediation:** Request specific configuration templates for Nginx, Apache, or Node.js.

What security finding would you like to investigate or fix?`;
}

router.post('/change-password', async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    if (new_password.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }
    const user = await DB.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const bcrypt = require('bcryptjs');
    const valid = await bcrypt.compare(current_password, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Incorrect current password' });

    const newHash = await bcrypt.hash(new_password, 12);
    await DB.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, req.user.id]);

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ─── Security Badges Endpoints ───────────────────────────────────────────────
router.get('/badges/latest', async (req, res) => {
  try {
    const badge = await DB.get(
      `SELECT * FROM security_badges WHERE user_id = ? AND is_active = 1
       ORDER BY earned_at DESC LIMIT 1`,
      [req.user.id]
    );
    res.json({ badge });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch latest badge' });
  }
});

router.post('/badges', async (req, res) => {
  try {
    const { domain, security_score, badge_level } = req.body;
    if (!domain || security_score === undefined) {
      return res.status(400).json({ error: 'Domain and security_score are required' });
    }

    const id = uuidv4();
    const embedToken = 'pc-badge-' + Math.random().toString(36).substring(2, 18);
    
    // Inactivate any old badges for this domain
    await DB.run('UPDATE security_badges SET is_active = 0 WHERE user_id = ? AND domain = ?', [req.user.id, domain]);

    await DB.run(
      `INSERT INTO security_badges (id, user_id, domain, security_score, badge_level, embed_token, is_active)
       VALUES (?, ?, ?, ?, ?, ?, 1)`,
      [id, req.user.id, domain, security_score, badge_level || 'info', embedToken]
    );

    const newBadge = await DB.get('SELECT * FROM security_badges WHERE id = ?', [id]);
    res.status(201).json({ badge: newBadge });
  } catch (err) {
    console.error('Save badge error:', err);
    res.status(500).json({ error: 'Failed to save security badge' });
  }
});

module.exports = router;
