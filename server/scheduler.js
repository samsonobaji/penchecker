'use strict';
/**
 * scheduler.js — Automated domain monitoring via node-cron
 * Runs every hour, finds domains due for re-scanning, and queues new scans.
 */
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const { DB } = require('./db');
const { runScan } = require('./scanner');

let isRunning = false;

async function runMonitoringJob() {
  if (isRunning) return; // Prevent overlapping runs
  isRunning = true;

  try {
    const now = new Date().toISOString();

    // Find all enabled monitored domains that are due for a scan
    const dueDomains = await DB.all(
      `SELECT d.id as domain_id, d.user_id, d.domain, d.monitoring_frequency
       FROM domains d
       WHERE d.monitoring_enabled = 1
         AND (d.next_monitor_at IS NULL OR d.next_monitor_at <= ?)
       LIMIT 20`,
      [now]
    );

    if (dueDomains.length === 0) {
      isRunning = false;
      return;
    }

    console.log(`[Scheduler] Found ${dueDomains.length} domain(s) due for monitoring`);

    for (const domain of dueDomains) {
      try {
        // Create a new scan for this domain
        const scanId  = uuidv4();
        const target  = `https://${domain.domain}`;

        await DB.run(
          `INSERT INTO scans (id, user_id, target_url, target_domain, scan_type, scan_mode, industry_profile, status, progress, started_at)
           VALUES (?, ?, ?, ?, 'standard', 'passive', 'general', 'running', 0, datetime('now'))`,
          [scanId, domain.user_id, target, domain.domain]
        );

        // Log consent (automated monitoring = user pre-approved)
        await DB.run(
          `INSERT INTO consent_logs (id, user_id, target_url, consent_text) VALUES (?, ?, ?, ?)`,
          [uuidv4(), domain.user_id, target, 'Automated monitoring — user pre-approved domain for scheduled scans.']
        );

        // Compute next scan time
        const nextAt = computeNextScanAt(domain.monitoring_frequency);

        // Update domain timestamps
        await DB.run(
          `UPDATE domains SET last_monitored_at = datetime('now'), next_monitor_at = ? WHERE id = ?`,
          [nextAt, domain.domain_id]
        );

        // Create in-app notification
        await DB.run(
          `INSERT INTO notifications (id, user_id, title, message, type) VALUES (?, ?, ?, ?, ?)`,
          [uuidv4(), domain.user_id, 'Scheduled Scan Started', `Automated scan started for ${domain.domain}.`, 'scan_started']
        );

        console.log(`[Scheduler] Queued scan ${scanId} for ${domain.domain} (next: ${nextAt})`);

        // Run scan (non-blocking)
        setImmediate(() => runScan(scanId));

      } catch (domainErr) {
        console.error(`[Scheduler] Error scanning ${domain.domain}:`, domainErr.message);
      }
    }
  } catch (err) {
    console.error('[Scheduler] Job error:', err.message);
  } finally {
    isRunning = false;
  }
}

/**
 * Compute the next scan timestamp based on frequency setting.
 */
function computeNextScanAt(frequency) {
  const now = new Date();
  switch (frequency) {
    case 'daily':   now.setDate(now.getDate() + 1);   break;
    case 'weekly':  now.setDate(now.getDate() + 7);   break;
    case 'monthly': now.setMonth(now.getMonth() + 1); break;
    default:        now.setDate(now.getDate() + 7);   break; // Default: weekly
  }
  return now.toISOString();
}

/**
 * Start the monitoring scheduler.
 * Runs every hour at the top of the hour.
 */
function startScheduler() {
  // Run every hour: '0 * * * *'
  // Also run once 30 seconds after startup (to catch any overdue domains)
  setTimeout(runMonitoringJob, 30000);

  cron.schedule('0 * * * *', () => {
    console.log('[Scheduler] Hourly monitoring check triggered');
    runMonitoringJob();
  });

  console.log('[Scheduler] Domain monitoring scheduler started (runs every hour)');
}

module.exports = { startScheduler, computeNextScanAt };
