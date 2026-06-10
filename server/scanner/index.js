'use strict';
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const { DB } = require('../db');
const { checkHeaders }          = require('./header-checks');
const { checkSSL }              = require('./ssl-checks');
const { detectTechnologies, getPathsToCheck } = require('./tech-detect');
const { analyzeContent }        = require('./content-checks');
const { checkPaths, checkOpenRedirects } = require('./path-checks');
const { checkCookies }          = require('./cookie-checks');
const { checkCORS }             = require('./cors-checks');
const { calculateScore }        = require('./scoring');
const { sendScanCompleteEmail, sendCriticalAlertEmail } = require('../mailer');

const TIMEOUT      = parseInt(process.env.SCANNER_TIMEOUT       || '15000');
const MAX_REDIRECTS = parseInt(process.env.SCANNER_MAX_REDIRECTS || '5');

async function runScan(scanId) {
  const scan = await DB.get('SELECT * FROM scans WHERE id = ?', [scanId]);
  if (!scan) { console.error(`[Scanner] Scan ${scanId} not found`); return; }

  const log = [];
  async function addLog(msg, type = 'info') {
    const ts = new Date().toISOString();
    log.push({ ts, msg, type });
    await DB.run('UPDATE scans SET scan_log = ?, current_step = ? WHERE id = ?', [JSON.stringify(log), msg, scanId]);
    console.log(`[Scanner][${scanId.substring(0, 8)}] ${msg}`);
  }

  async function updateProgress(progress, step) {
    await DB.run('UPDATE scans SET progress = ?, current_step = ? WHERE id = ?', [progress, step, scanId]);
  }

  try {
    let targetUrl = scan.target_url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    await addLog(`Starting scan for ${targetUrl}`, 'info');
    await updateProgress(5, 'Initializing scanner...');

    // ─── Step 1: Initial HTTP request ─────────────────────────────────────
    await updateProgress(10, 'Connecting to target...');
    await addLog('Sending initial HTTP request...', 'info');

    let response;
    let finalUrl = targetUrl;
    let isHttps  = targetUrl.startsWith('https');

    try {
      response = await axios.get(targetUrl, {
        timeout: TIMEOUT,
        maxRedirects: MAX_REDIRECTS,
        validateStatus: () => true,
        headers: {
          'User-Agent':      'Mozilla/5.0 (compatible; PenChecker-Scanner/1.0; +https://penchecker.io/bot)',
          'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Origin':          'https://evil-cors-test.example.com', // For CORS detection
        },
      });
      finalUrl = response.request?.res?.responseUrl || targetUrl;
      isHttps  = finalUrl.startsWith('https');
      await addLog(`Connected — HTTP ${response.status} (${finalUrl})`, 'ok');
    } catch (err) {
      const httpUrl = targetUrl.replace('https://', 'http://');
      try {
        await addLog(`HTTPS failed (${err.code || err.message}), trying HTTP...`, 'warn');
        response = await axios.get(httpUrl, {
          timeout: TIMEOUT, maxRedirects: MAX_REDIRECTS, validateStatus: () => true,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PenChecker-Scanner/1.0)',
            'Origin': 'https://evil-cors-test.example.com',
          },
        });
        finalUrl = httpUrl;
        isHttps  = false;
        await addLog(`Connected via HTTP — HTTP ${response.status}`, 'warn');
      } catch (err2) {
        await addLog(`Cannot reach target: ${err2.message}`, 'error');
        await DB.run(`UPDATE scans SET status = 'failed', error_message = ?, completed_at = datetime('now') WHERE id = ?`, [err2.message, scanId]);
        return;
      }
    }

    const headers      = response.headers || {};
    const html         = typeof response.data === 'string' ? response.data : '';
    const serverHeader = headers.server || '';
    await updateProgress(18, 'Analyzing response headers...');

    // ─── Step 2: Technology Detection ─────────────────────────────────────
    await addLog('Detecting technology stack...', 'info');
    const technologies = detectTechnologies(headers, html);
    const techNames    = technologies.map(t => t.name).join(', ') || 'Unknown';
    await addLog(`Detected: ${techNames}`, 'ok');
    await updateProgress(25, 'Technology detection complete');

    // ─── Step 3: Security Header Analysis ─────────────────────────────────
    await addLog('Analyzing HTTP security headers...', 'info');
    const headerFindings = checkHeaders(headers, isHttps);
    await addLog(`Header check: ${headerFindings.length} issue(s) found`, headerFindings.length > 0 ? 'warn' : 'ok');
    await updateProgress(35, `Found ${headerFindings.length} header issue(s)`);

    // ─── Step 4: Cookie Security Analysis ─────────────────────────────────
    await addLog('Analyzing cookie security attributes...', 'info');
    const cookieFindings = checkCookies(headers, isHttps);
    await addLog(`Cookie check: ${cookieFindings.length} issue(s) found`, cookieFindings.length > 0 ? 'warn' : 'ok');
    await updateProgress(42, 'Cookie analysis complete');

    // ─── Step 5: CORS Analysis ────────────────────────────────────────────
    await addLog('Checking CORS configuration...', 'info');
    const corsFindings = checkCORS(headers, finalUrl);
    await addLog(`CORS check: ${corsFindings.length} issue(s) found`, corsFindings.length > 0 ? 'warn' : 'ok');
    await updateProgress(48, 'CORS analysis complete');

    // ─── Step 6: SSL/TLS Analysis ─────────────────────────────────────────
    await addLog('Analyzing SSL/TLS configuration...', 'info');
    const sslFindings = await checkSSL(finalUrl);
    await addLog(`SSL check: ${sslFindings.filter(f => f.severity !== 'info').length} issue(s) found`, 'ok');
    await updateProgress(58, 'SSL analysis complete');

    // ─── Step 7: Content Analysis ─────────────────────────────────────────
    let contentFindings = [];
    if (html.length > 100) {
      await addLog('Analyzing page content for security issues...', 'info');
      contentFindings = analyzeContent(html, finalUrl, isHttps);
      await addLog(`Content analysis: ${contentFindings.length} issue(s) found`, contentFindings.length > 0 ? 'warn' : 'ok');
    }
    await updateProgress(68, 'Content analysis complete');

    // ─── Step 8: Open Redirect Check ──────────────────────────────────────
    await addLog('Checking for open redirect vulnerabilities...', 'info');
    const redirectFindings = await checkOpenRedirects(finalUrl, async (msg) => { await addLog(msg, 'info'); });
    await addLog(`Open redirect check: ${redirectFindings.length} issue(s) found`, redirectFindings.length > 0 ? 'warn' : 'ok');
    await updateProgress(75, 'Redirect checks complete');

    // ─── Step 9: Path Discovery ───────────────────────────────────────────
    let pathFindings = [];
    const pathsToCheck = getPathsToCheck(technologies);
    const maxPaths = scan.scan_type === 'quick' ? 3 : scan.scan_type === 'standard' ? Math.min(pathsToCheck.length, 10) : pathsToCheck.length;
    if (scan.scan_type === 'quick') {
      const criticalPaths = [
        { path: '/.env',      severity: 'critical', title: 'Exposed .env File',       description: 'Environment file may contain credentials and API keys.' },
        { path: '/.git/HEAD', severity: 'high',     title: 'Exposed .git Repository', description: 'Source code may be reconstructed from the git repository.' },
        { path: '/robots.txt', severity: 'info',    title: 'robots.txt Found',         description: 'Crawl directives and possibly sensitive path disclosures.' },
      ];
      await addLog('Running quick path checks...', 'info');
      pathFindings = await checkPaths(finalUrl, criticalPaths, async (msg) => { await addLog(msg, 'info'); });
    } else {
      await addLog(`Checking ${maxPaths} sensitive path(s)...`, 'info');
      pathFindings = await checkPaths(finalUrl, pathsToCheck.slice(0, maxPaths), async (msg) => { await addLog(msg, 'info'); });
    }
    await addLog(`Path discovery: ${pathFindings.filter(f => f.severity !== 'info').length} issue(s) found`, 'ok');
    await updateProgress(88, 'Path discovery complete');

    // ─── Step 10: Score & Aggregate ───────────────────────────────────────
    await addLog('Calculating security score...', 'info');
    const allFindings = [...headerFindings, ...cookieFindings, ...corsFindings, ...sslFindings, ...contentFindings, ...redirectFindings, ...pathFindings];
    const { score, counts, total } = calculateScore(allFindings);
    await addLog(`Security score: ${score}/10 | ${total} total finding(s)`, score >= 7 ? 'ok' : 'warn');
    await updateProgress(95, 'Saving results...');

    // ─── Step 11: Save findings ───────────────────────────────────────────
    for (const f of allFindings) {
      await DB.run(
        `INSERT INTO scan_vulnerabilities (id, scan_id, vulnerability_type, category, severity, cvss_score, confidence_score, title, description, evidence, affected_url, fix_difficulty, fix_description, fix_code_snippet, owasp_reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidv4(), scanId, f.vulnerability_type || 'Unknown', f.category || 'other', f.severity || 'info', f.cvss_score || 0, f.confidence_score || 80, f.title, f.description || '', f.evidence || '', f.affected_url || finalUrl, f.fix_difficulty || 'moderate', f.fix_description || '', f.fix_code_snippet || '', f.owasp_reference || '']
      );
    }

    // ─── Step 12: Update scan record ──────────────────────────────────────
    const startedAt      = new Date(scan.created_at).getTime();
    const durationSeconds = Math.floor((Date.now() - startedAt) / 1000);

    await DB.run(
      `UPDATE scans SET status = 'completed', progress = 100, current_step = 'Scan complete',
       security_score = ?, total_vulnerabilities = ?, critical_count = ?, high_count = ?,
       medium_count = ?, low_count = ?, info_count = ?, technologies_detected = ?,
       headers_checked = ?, final_url = ?, server_software = ?,
       completed_at = datetime('now'), duration_seconds = ?, scan_log = ?
       WHERE id = ?`,
      [score, total, counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0, counts.info || 0,
       JSON.stringify(technologies), Object.keys(headers).length, finalUrl, serverHeader,
       durationSeconds, JSON.stringify(log), scanId]
    );

    await addLog(`Scan complete — score: ${score}/10, ${total} findings in ${durationSeconds}s`, 'ok');
    console.log(`[Scanner] Scan ${scanId} completed. Score: ${score}/10, Findings: ${total}`);

    // ─── Step 13: Email Notifications ─────────────────────────────────────
    try {
      const user = await DB.get('SELECT email, email_notifications FROM users WHERE id = ?', [scan.user_id]);
      if (user && user.email_notifications) {
        const completedScan = await DB.get('SELECT * FROM scans WHERE id = ?', [scanId]);
        sendScanCompleteEmail(user.email, completedScan).catch(() => {});

        // Send critical alert for each critical finding
        const criticalFindings = allFindings.filter(f => f.severity === 'critical');
        for (const finding of criticalFindings.slice(0, 2)) { // Max 2 critical alerts per scan
          sendCriticalAlertEmail(user.email, completedScan, finding).catch(() => {});
        }
      }
    } catch (emailErr) {
      console.error('[Scanner] Email notification error:', emailErr.message);
    }

  } catch (err) {
    console.error(`[Scanner] Fatal error in scan ${scanId}:`, err);
    await DB.run(`UPDATE scans SET status = 'failed', error_message = ?, completed_at = datetime('now') WHERE id = ?`, [err.message, scanId]);
  }
}

module.exports = { runScan };
