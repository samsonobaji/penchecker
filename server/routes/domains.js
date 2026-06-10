'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { DB } = require('../db');
const { auth } = require('../auth');

const router = express.Router();
router.use(auth);

router.get('/', async (req, res) => {
  try {
    const domains = await DB.all(
      `SELECT d.*, 
              d.monitoring_enabled AS is_monitoring,
              s.security_score AS latest_score,
              s.completed_at AS last_scan_at
       FROM domains d
       LEFT JOIN (
         SELECT target_domain, security_score, completed_at,
                ROW_NUMBER() OVER (PARTITION BY target_domain ORDER BY completed_at DESC) as rn
         FROM scans
         WHERE user_id = ? AND status = 'completed'
       ) s ON d.domain = s.target_domain AND s.rn = 1
       WHERE d.user_id = ?
       ORDER BY d.created_at DESC`,
      [req.user.id, req.user.id]
    );
    res.json({ domains });
  } catch (err) {
    console.error('Fetch domains error:', err);
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
});

router.post('/', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain is required' });
    let cleanDomain = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
    if (!cleanDomain.includes('.')) return res.status(400).json({ error: 'Invalid domain format' });

    const existing = await DB.get('SELECT id FROM domains WHERE user_id = ? AND domain = ?', [req.user.id, cleanDomain]);
    if (existing) return res.status(409).json({ error: 'Domain already added' });

    const id = uuidv4();
    const verifyToken = 'pc-verify-' + Math.random().toString(36).substring(2, 18);
    await DB.run('INSERT INTO domains (id, user_id, domain, verification_token) VALUES (?, ?, ?, ?)', [id, req.user.id, cleanDomain, verifyToken]);
    const newDomain = await DB.get('SELECT * FROM domains WHERE id = ?', [id]);
    res.status(201).json({ domain: newDomain });
  } catch (err) { res.status(500).json({ error: 'Failed to add domain' }); }
});

router.post('/:id/verify', async (req, res) => {
  try {
    const domain = await DB.get('SELECT * FROM domains WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!domain) return res.status(404).json({ error: 'Domain not found' });

    const { method = 'dns_txt' } = req.body;
    const axios = require('axios');
    let verified = false;
    let verifyError = '';

    if (method === 'file_upload') {
      try {
        const url = `https://${domain.domain}/.well-known/penchecker-verify.txt`;
        const response = await axios.get(url, { timeout: 8000, validateStatus: () => true });
        if (response.status === 200 && String(response.data).includes(domain.verification_token)) verified = true;
        else verifyError = `Token not found at ${url}`;
      } catch (e) { verifyError = e.message; }
    } else if (method === 'meta_tag') {
      try {
        const url = `https://${domain.domain}`;
        const response = await axios.get(url, { timeout: 10000, validateStatus: () => true });
        if (response.status === 200 && String(response.data).includes(domain.verification_token)) verified = true;
        else verifyError = `Token not found in page HTML`;
      } catch (e) { verifyError = e.message; }
    } else {
      return res.json({ status: 'pending', message: 'Add the DNS TXT record below, then click Verify again.', dns_record: `Name: _penchecker.${domain.domain}\nType: TXT\nValue: ${domain.verification_token}` });
    }

    if (verified) {
      await DB.run(`UPDATE domains SET is_verified = 1, verification_method = ?, verified_at = datetime('now') WHERE id = ?`, [method, domain.id]);
      res.json({ verified: true, message: 'Domain verified successfully' });
    } else {
      res.status(400).json({ verified: false, error: verifyError || 'Verification failed' });
    }
  } catch (err) { res.status(500).json({ error: 'Verification failed' }); }
});

router.patch('/:id', async (req, res) => {
  try {
    const domain = await DB.get('SELECT id, monitoring_enabled FROM domains WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!domain) return res.status(404).json({ error: 'Domain not found' });

    const { monitoring_enabled, monitoring_frequency } = req.body;
    const validFrequencies = ['daily', 'weekly', 'monthly'];

    if (monitoring_enabled !== undefined) {
      const enabling = monitoring_enabled ? 1 : 0;
      await DB.run('UPDATE domains SET monitoring_enabled = ? WHERE id = ?', [enabling, req.params.id]);
      if (enabling && !domain.monitoring_enabled) {
        const { computeNextScanAt } = require('../scheduler');
        const freq = monitoring_frequency || 'weekly';
        const nextAt = computeNextScanAt(freq);
        await DB.run('UPDATE domains SET next_monitor_at = ? WHERE id = ?', [nextAt, req.params.id]);
      }
    }
    if (monitoring_frequency && validFrequencies.includes(monitoring_frequency)) {
      await DB.run('UPDATE domains SET monitoring_frequency = ? WHERE id = ?', [monitoring_frequency, req.params.id]);
    }
    const updated = await DB.get('SELECT * FROM domains WHERE id = ?', [req.params.id]);
    res.json({ domain: updated });
  } catch (err) {
    console.error('Domain update error:', err);
    res.status(500).json({ error: 'Update failed' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const domain = await DB.get('SELECT id FROM domains WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!domain) return res.status(404).json({ error: 'Domain not found' });
    await DB.run('DELETE FROM domains WHERE id = ?', [req.params.id]);
    res.json({ message: 'Domain removed' });
  } catch (err) { res.status(500).json({ error: 'Delete failed' }); }
});

module.exports = router;
