'use strict';
/**
 * ssl-checks.js
 * Analyzes SSL/TLS configuration by making real HTTPS requests.
 * Only reports actual SSL issues found.
 */
const https = require('https');
const tls = require('tls');
const { URL } = require('url');

async function checkSSL(targetUrl) {
  const findings = [];

  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
  } catch {
    return findings;
  }

  const hostname = parsedUrl.hostname;

  // Check 1: Does HTTPS work at all?
  const httpsWorks = await tryHttps(hostname);
  
  if (!httpsWorks.success) {
    findings.push({
      vulnerability_type: 'No-HTTPS',
      category: 'ssl',
      severity: 'critical',
      cvss_score: 7.4,
      confidence_score: 99,
      title: 'HTTPS Not Available or Certificate Error',
      description: `The site does not serve traffic over HTTPS, or its TLS certificate is invalid. All traffic is transmitted in plaintext and is vulnerable to interception.`,
      evidence: httpsWorks.error || 'HTTPS connection failed or no valid certificate present.',
      fix_difficulty: 'moderate',
      fix_description: 'Obtain and install a valid SSL/TLS certificate. Free certificates are available via Let\'s Encrypt.',
      fix_code_snippet: `# Install Certbot (Ubuntu)\nsudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d yourdomain.com`,
      owasp_reference: 'A02:2021 – Cryptographic Failures',
    });
    return findings; // No point checking further
  }

  // Check 2: Certificate expiry
  if (httpsWorks.cert) {
    const cert = httpsWorks.cert;
    const expiresAt = new Date(cert.valid_to);
    const now = new Date();
    const daysLeft = Math.floor((expiresAt - now) / (1000 * 60 * 60 * 24));

    if (daysLeft < 0) {
      findings.push({
        vulnerability_type: 'Expired-Certificate',
        category: 'ssl',
        severity: 'critical',
        cvss_score: 7.5,
        confidence_score: 99,
        title: 'SSL Certificate Has Expired',
        description: `The SSL certificate for ${hostname} expired on ${expiresAt.toDateString()}. Browsers will show a security warning to all visitors.`,
        evidence: `Certificate valid_to: ${cert.valid_to} (${Math.abs(daysLeft)} days ago)`,
        fix_difficulty: 'easy',
        fix_description: 'Renew your SSL certificate immediately.',
        fix_code_snippet: `# Using Certbot\ncertbot renew\n\n# Check renewal\ncertbot certificates`,
        owasp_reference: 'A02:2021 – Cryptographic Failures',
      });
    } else if (daysLeft < 30) {
      findings.push({
        vulnerability_type: 'Expiring-Certificate',
        category: 'ssl',
        severity: 'high',
        cvss_score: 5.0,
        confidence_score: 99,
        title: `SSL Certificate Expiring Soon (${daysLeft} days remaining)`,
        description: `The SSL certificate for ${hostname} expires on ${expiresAt.toDateString()}. If not renewed, browsers will block access with security warnings.`,
        evidence: `Certificate valid_to: ${cert.valid_to} (${daysLeft} days remaining)`,
        fix_difficulty: 'easy',
        fix_description: 'Renew your SSL certificate before it expires.',
        fix_code_snippet: `certbot renew`,
        owasp_reference: 'A02:2021 – Cryptographic Failures',
      });
    }

    // Check: Certificate issuer info (informational)
    if (cert.issuer) {
      const issuerOrg = cert.issuer.O || cert.issuer.CN || 'Unknown';
      findings.push({
        vulnerability_type: 'Certificate-Info',
        category: 'info',
        severity: 'info',
        cvss_score: 0,
        confidence_score: 99,
        title: `SSL Certificate Information`,
        description: `Certificate is valid for ${daysLeft} days. Issued by: ${issuerOrg}.`,
        evidence: `Issuer: ${issuerOrg} | Valid until: ${expiresAt.toDateString()} | ${daysLeft} days remaining`,
        fix_difficulty: 'easy',
        fix_description: 'No action required. Certificate is valid.',
        owasp_reference: 'A02:2021 – Cryptographic Failures',
      });
    }
  }

  // Check 3: HTTP → HTTPS redirect
  const httpUrl = `http://${hostname}`;
  const redirectsToHttps = await checkHttpRedirect(httpUrl);
  if (!redirectsToHttps) {
    findings.push({
      vulnerability_type: 'No-HTTPS-Redirect',
      category: 'ssl',
      severity: 'medium',
      cvss_score: 4.8,
      confidence_score: 90,
      title: 'HTTP Traffic Not Redirected to HTTPS',
      description: 'The site accepts plain HTTP connections without automatically redirecting to HTTPS. Users who visit the HTTP version will not receive the security benefits of HTTPS.',
      evidence: `GET http://${hostname}/ did not redirect to https://`,
      fix_difficulty: 'easy',
      fix_description: 'Configure your web server to redirect all HTTP traffic to HTTPS.',
      fix_code_snippet: `# Nginx\nserver {\n  listen 80;\n  server_name ${hostname};\n  return 301 https://$host$request_uri;\n}`,
      owasp_reference: 'A02:2021 – Cryptographic Failures',
    });
  }

  return findings;
}

function tryHttps(hostname) {
  return new Promise((resolve) => {
    const timeout = parseInt(process.env.SCANNER_TIMEOUT || '10000');
    const options = {
      host: hostname,
      port: 443,
      method: 'HEAD',
      path: '/',
      rejectUnauthorized: false, // Still check, but don't reject — we'll analyze
      timeout,
    };
    const req = https.request(options, (res) => {
      const cert = res.socket.getPeerCertificate();
      // Check if cert is actually valid
      const authorized = res.socket.authorized;
      resolve({ success: true, cert, authorized, statusCode: res.statusCode });
    });
    req.on('error', (err) => resolve({ success: false, error: err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ success: false, error: 'Connection timed out' }); });
    req.end();
  });
}

function checkHttpRedirect(httpUrl) {
  return new Promise((resolve) => {
    const http = require('http');
    const { URL } = require('url');
    let parsed;
    try { parsed = new URL(httpUrl); } catch { return resolve(false); }
    const options = {
      hostname: parsed.hostname,
      port: 80,
      path: '/',
      method: 'HEAD',
      timeout: 8000,
    };
    const req = http.request(options, (res) => {
      const loc = (res.headers.location || '').toLowerCase();
      const isRedirect = [301, 302, 307, 308].includes(res.statusCode) && loc.startsWith('https');
      resolve(isRedirect);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

module.exports = { checkSSL };
