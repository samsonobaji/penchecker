'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { DB } = require('../db');
const { auth } = require('../auth');
const { runScan } = require('../scanner');

const router = express.Router();
router.use(auth);

// ─── Start Scan ───────────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const { target_url, scan_type = 'quick', scan_mode = 'passive', industry_profile = 'general' } = req.body;
    if (!target_url) return res.status(400).json({ error: 'target_url is required' });

    let domain = target_url.trim();
    if (!/^https?:\/\//i.test(domain)) domain = 'https://' + domain;
    let targetDomain;
    try { targetDomain = new URL(domain).hostname.replace(/^www\./, ''); }
    catch { return res.status(400).json({ error: 'Invalid URL format' }); }

    const blacklisted = await DB.get('SELECT domain FROM scan_blacklist WHERE domain = ? AND is_active = 1', [targetDomain]);
    if (blacklisted) return res.status(403).json({ error: `Scanning ${targetDomain} is not permitted by PenChecker policy.` });

    const scanId = uuidv4();
    await DB.run(
      `INSERT INTO scans (id, user_id, target_url, target_domain, scan_type, scan_mode, industry_profile, status, progress, started_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'running', 0, datetime('now'))`,
      [scanId, req.user.id, domain, targetDomain, scan_type, scan_mode, industry_profile]
    );

    await DB.run(
      `INSERT INTO consent_logs (id, user_id, target_url, ip_address, user_agent, consent_text) VALUES (?, ?, ?, ?, ?, ?)`,
      [uuidv4(), req.user.id, domain, req.ip, req.headers['user-agent'] || '', 'I confirm I own this domain or have written permission to test it.']
    );

    setImmediate(() => runScan(scanId));
    res.status(201).json({ id: scanId, status: 'running', message: 'Scan started' });
  } catch (err) {
    console.error('Start scan error:', err);
    res.status(500).json({ error: 'Could not start scan' });
  }
});

// ─── List Scans ───────────────────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit)  || 20, 100);
    const offset = parseInt(req.query.offset) || 0;
    const scans  = await DB.all(
      `SELECT id, target_url, target_domain, scan_type, scan_mode, status, progress,
              security_score, total_vulnerabilities, critical_count, high_count, medium_count,
              low_count, info_count, started_at, completed_at, duration_seconds, created_at
       FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [req.user.id, limit, offset]
    );
    const { c: total } = await DB.get('SELECT COUNT(*) as c FROM scans WHERE user_id = ?', [req.user.id]);
    res.json({ scans, total, limit, offset });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

// ─── Get Scan Progress ────────────────────────────────────────────────────────
router.get('/:id/progress', async (req, res) => {
  try {
    const scan = await DB.get(
      `SELECT id, status, progress, current_step, security_score, total_vulnerabilities,
              critical_count, high_count, medium_count, low_count, info_count,
              started_at, completed_at, scan_log, error_message
       FROM scans WHERE id = ? AND user_id = ?`,
      [req.params.id, req.user.id]
    );
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    try { scan.scan_log = JSON.parse(scan.scan_log || '[]'); } catch { scan.scan_log = []; }
    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// ─── Get Full Scan ────────────────────────────────────────────────────────────
router.get('/:id', async (req, res) => {
  try {
    const scan = await DB.get('SELECT * FROM scans WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    try { scan.technologies_detected = JSON.parse(scan.technologies_detected || '[]'); } catch { scan.technologies_detected = []; }
    try { scan.scan_log = JSON.parse(scan.scan_log || '[]'); } catch { scan.scan_log = []; }

    const vulnerabilities = await DB.all(
      `SELECT * FROM scan_vulnerabilities WHERE scan_id = ?
       ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, cvss_score DESC`,
      [req.params.id]
    );
    res.json({ ...scan, vulnerabilities });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch scan' });
  }
});

// ─── Delete Scan ──────────────────────────────────────────────────────────────
router.delete('/:id', async (req, res) => {
  try {
    const scan = await DB.get('SELECT id, status FROM scans WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.status === 'running') return res.status(409).json({ error: 'Cannot delete a running scan' });
    await DB.run('DELETE FROM scans WHERE id = ?', [req.params.id]);
    res.json({ message: 'Scan deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ─── Export PDF Report ────────────────────────────────────────────────────────
router.get('/:id/export/pdf', async (req, res) => {
  try {
    const scan = await DB.get('SELECT * FROM scans WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.status !== 'completed') return res.status(400).json({ error: 'Scan must be completed before exporting' });

    let techs = [];
    try { techs = JSON.parse(scan.technologies_detected || '[]'); } catch {}

    const vulns = await DB.all(
      `SELECT * FROM scan_vulnerabilities WHERE scan_id = ?
       ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`,
      [req.params.id]
    );

    const PDFDocument = require('pdfkit');
    const doc = new PDFDocument({ margin: 50, size: 'A4' });

    // Set response headers for PDF download
    const safeFilename = `penchecker-report-${scan.target_domain}-${new Date(scan.created_at).toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    doc.pipe(res);

    // ── Color palette ──
    const DARK    = '#1a1a2e';
    const CYAN    = '#00c8e0';
    const WHITE   = '#f0f0f8';
    const MUTED   = '#9090a8';
    const RED     = '#ff3b5c';
    const ORANGE  = '#ff8c42';
    const YELLOW  = '#d4a017';
    const GREEN   = '#00c870';
    const PURPLE  = '#a855f7';

    const score     = scan.security_score || 0;
    const scoreCol  = score >= 7 ? GREEN : score >= 5 ? YELLOW : RED;
    const scoreLabel = score >= 7 ? 'GOOD' : score >= 5 ? 'NEEDS IMPROVEMENT' : 'CRITICAL';

    function sevColor(sev) {
      return { critical: RED, high: ORANGE, medium: YELLOW, low: CYAN, info: PURPLE }[sev] || MUTED;
    }

    // ── Page 1: Header ────────────────────────────────────────────────────────
    // Background header bar
    doc.rect(0, 0, doc.page.width, 140).fill(DARK);

    // Logo area
    doc.fontSize(22).fillColor(WHITE).font('Helvetica-Bold')
       .text('PenChecker', 50, 42);
    doc.fontSize(10).fillColor(CYAN).font('Helvetica')
       .text('Security Scan Report', 50, 68);

    // Score circle (right side)
    const cx = doc.page.width - 90, cy = 70;
    doc.circle(cx, cy, 38).lineWidth(4).strokeColor(scoreCol).stroke();
    doc.fontSize(20).fillColor(scoreCol).font('Helvetica-Bold')
       .text(score.toFixed(1), cx - 20, cy - 14, { width: 40, align: 'center' });
    doc.fontSize(7).fillColor(MUTED).font('Helvetica')
       .text('/10', cx - 20, cy + 8, { width: 40, align: 'center' });
    doc.fontSize(7).fillColor(scoreCol).font('Helvetica-Bold')
       .text(scoreLabel, cx - 40, cy + 22, { width: 80, align: 'center' });

    // Scan metadata
    doc.y = 158;
    doc.fontSize(18).fillColor(WHITE).font('Helvetica-Bold').text(scan.target_domain, 50);
    doc.fontSize(9).fillColor(MUTED).font('Helvetica')
       .text(`${scan.final_url || scan.target_url}  ·  Scan Type: ${(scan.scan_type || 'standard').toUpperCase()}  ·  Duration: ${scan.duration_seconds || 0}s`, 50);
    doc.fontSize(9).fillColor(MUTED)
       .text(`Scanned: ${new Date(scan.completed_at || scan.created_at).toUTCString()}`, 50);

    doc.moveDown(1.2);

    // ── Stat boxes ────────────────────────────────────────────────────────────
    const stats = [
      { label: 'Total Findings', val: scan.total_vulnerabilities || 0, col: WHITE },
      { label: 'Critical',  val: scan.critical_count || 0, col: RED },
      { label: 'High',      val: scan.high_count     || 0, col: ORANGE },
      { label: 'Medium',    val: scan.medium_count   || 0, col: YELLOW },
      { label: 'Low',       val: scan.low_count      || 0, col: CYAN },
      { label: 'Info',      val: scan.info_count     || 0, col: PURPLE },
    ];
    const bw = 72, bh = 56, bx0 = 50, by = doc.y;
    stats.forEach((s, i) => {
      const bx = bx0 + i * (bw + 8);
      doc.roundedRect(bx, by, bw, bh, 6).fillAndStroke('#13131a', '#2a2a3a');
      doc.fontSize(7).fillColor(MUTED).font('Helvetica').text(s.label.toUpperCase(), bx + 6, by + 10, { width: bw - 12 });
      doc.fontSize(22).fillColor(s.col).font('Helvetica-Bold').text(s.val.toString(), bx, by + 20, { width: bw, align: 'center' });
    });

    doc.y = by + bh + 20;
    doc.moveTo(50, doc.y).lineTo(doc.page.width - 50, doc.y).lineWidth(0.5).strokeColor('#2a2a3a').stroke();
    doc.moveDown(0.8);

    // ── Technologies ──────────────────────────────────────────────────────────
    if (techs.length > 0) {
      doc.fontSize(12).fillColor(WHITE).font('Helvetica-Bold').text('Detected Technologies');
      doc.moveDown(0.3);
      doc.fontSize(9).fillColor(MUTED).font('Helvetica')
         .text(techs.map(t => `${t.name}${t.version ? ' ' + t.version : ''}`).join('  ·  '), 50);
      doc.moveDown(1);
    }

    // ── Findings ──────────────────────────────────────────────────────────────
    if (vulns.length > 0) {
      doc.fontSize(12).fillColor(WHITE).font('Helvetica-Bold').text('Security Findings');
      doc.moveDown(0.5);

      for (const v of vulns) {
        // Page break if needed
        if (doc.y > doc.page.height - 180) doc.addPage();

        const col = sevColor(v.severity);

        // Finding header
        doc.rect(50, doc.y, doc.page.width - 100, 24).fill('#13131a');
        const sevLabel = (v.severity || 'info').toUpperCase();
        doc.fontSize(7).fillColor(col).font('Helvetica-Bold').text(sevLabel, 58, doc.y + 7);
        doc.fontSize(9).fillColor(WHITE).font('Helvetica-Bold').text(v.title, 108, doc.y + 6, { width: doc.page.width - 170 });
        if (v.cvss_score > 0) {
          doc.fontSize(7).fillColor(MUTED).font('Helvetica')
             .text(`CVSS ${v.cvss_score.toFixed(1)}`, doc.page.width - 100, doc.y + 7, { width: 50 });
        }
        doc.y += 28;

        // Description
        if (v.description) {
          doc.fontSize(8).fillColor(MUTED).font('Helvetica')
             .text(v.description.substring(0, 400), 58, doc.y, { width: doc.page.width - 116 });
          doc.moveDown(0.4);
        }

        // Evidence
        if (v.evidence) {
          doc.fontSize(7).fillColor('#4a4a6a').font('Helvetica')
             .text('Evidence: ' + v.evidence.substring(0, 200), 58, doc.y, { width: doc.page.width - 116 });
          doc.moveDown(0.4);
        }

        // Fix
        if (v.fix_description) {
          doc.fontSize(8).fillColor(GREEN).font('Helvetica-Bold').text('Fix: ', 58, doc.y, { continued: true });
          doc.fillColor(MUTED).font('Helvetica').text(v.fix_description.substring(0, 250));
          doc.moveDown(0.4);
        }

        doc.moveDown(0.6);
        doc.moveTo(58, doc.y).lineTo(doc.page.width - 58, doc.y).lineWidth(0.3).strokeColor('#2a2a3a').stroke();
        doc.moveDown(0.5);
      }
    } else {
      doc.fontSize(10).fillColor(GREEN).font('Helvetica-Bold')
         .text('No vulnerabilities found — excellent security posture!', 50);
    }

    // ── Footer on each page ───────────────────────────────────────────────────
    const pageCount = doc.bufferedPageRange().count;
    for (let i = 0; i < pageCount; i++) {
      doc.switchToPage(i);
      doc.fontSize(7).fillColor(MUTED).font('Helvetica')
         .text(`PenChecker Security Report · ${scan.target_domain} · Page ${i + 1} of ${pageCount}`,
               50, doc.page.height - 30, { align: 'center', width: doc.page.width - 100 });
    }

    doc.end();
  } catch (err) {
    console.error('PDF export error:', err);
    if (!res.headersSent) res.status(500).json({ error: 'Failed to generate PDF report' });
  }
});

module.exports = router;
