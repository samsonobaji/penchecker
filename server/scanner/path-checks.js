'use strict';
/**
 * path-checks.js
 * Checks for sensitive exposed paths by making real HTTP requests.
 * ONLY reports a path as exposed if it returns a 200 (or 403) status.
 * Never reports 404s as findings.
 * Also checks for open redirect vulnerabilities.
 */
const axios = require('axios');
const { URL } = require('url');

async function checkPaths(baseUrl, pathsToCheck, onProgress) {
  const findings = [];
  const TIMEOUT = parseInt(process.env.SCANNER_TIMEOUT || '8000');
  
  for (const pathDef of pathsToCheck) {
    try {
      const url = `${baseUrl.replace(/\/$/, '')}${pathDef.path}`;
      const response = await axios.get(url, {
        timeout: TIMEOUT,
        maxRedirects: 3,
        validateStatus: () => true, // Don't throw on any status
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; PenChecker-Scanner/1.0; +https://penchecker.io/bot)',
        },
      });

      const status = response.status;
      const contentType = (response.headers['content-type'] || '').toLowerCase();
      const body = typeof response.data === 'string' ? response.data.substring(0, 500) : JSON.stringify(response.data).substring(0, 500);

      if (onProgress) onProgress(`Checked ${pathDef.path} → ${status}`);

      // robots.txt — always informational
      if (pathDef.path === '/robots.txt' && status === 200) {
        const { analyzeRobotsTxt } = require('./content-checks');
        const robotsFindings = analyzeRobotsTxt(body, baseUrl);
        findings.push(...robotsFindings);
        findings.push({
          vulnerability_type: 'Robots-Txt-Found',
          category: 'info',
          severity: 'info',
          cvss_score: 0,
          confidence_score: 99,
          title: 'robots.txt File Found',
          description: 'A robots.txt file was found. It provides crawling directives and may reveal application structure.',
          evidence: `GET ${url} → 200 OK\nContent preview:\n${body.substring(0, 200)}`,
          fix_difficulty: 'easy',
          fix_description: 'Ensure robots.txt does not reveal sensitive paths.',
          owasp_reference: 'A05:2021 – Security Misconfiguration',
        });
        continue;
      }

      // Only report actual exposure (200 or 403 = path exists)
      if (status === 200) {
        // Additional verification: check if it's actually the file we expect
        const isActuallyExposed = verifyExposure(pathDef.path, body, contentType, status);

        if (isActuallyExposed) {
          let fixDesc = `Restrict access to ${pathDef.path} via web server configuration or remove the file.`;
          let fixSnippet = `# Nginx — block access\nlocation ~ ${escapeRegex(pathDef.path)} {\n  deny all;\n  return 404;\n}`;

          if (pathDef.path === '/.env') {
            fixDesc = `Follow these steps to secure your environment file:\n1. Move the .env file OUTSIDE of your web root directory (e.g. above your public_html or dist folder) so it is not accessible via web browsers. Keep only public assets (index.html, js, css) in the web root.\n2. If relocation is not immediately possible, configure your web server to block HTTP requests to this path.\n3. Revoke and rotate all database passwords, API credentials, and application keys immediately, as they must now be considered compromised.`;
            fixSnippet = `# Nginx configuration - Block .env access\nlocation ~ /\\.env {\n    deny all;\n    return 404;\n}\n\n# Apache configuration (.htaccess) - Block .env access\n<FilesMatch "^\\.env$">\n    Order allow,deny\n    Deny from all\n</FilesMatch>\n\n# IIS web.config - Hide .env segment\n<configuration>\n  <system.webServer>\n    <security>\n      <requestFiltering>\n        <hiddenSegments>\n          <add segment=".env" />\n        </hiddenSegments>\n      </requestFiltering>\n    </security>\n  </system.webServer>\n</configuration>`;
          }

          findings.push({
            vulnerability_type: `Exposed-${pathDef.path.replace(/\W+/g, '-').replace(/^-+|-+$/g, '')}`,
            category: 'exposure',
            severity: pathDef.severity,
            cvss_score: severityToCvss(pathDef.severity),
            confidence_score: 90,
            title: pathDef.title,
            description: pathDef.description,
            affected_url: url,
            evidence: `GET ${url} → HTTP ${status}\nContent-Type: ${contentType}\nPreview: ${body.substring(0, 200)}`,
            fix_difficulty: 'easy',
            fix_description: fixDesc,
            fix_code_snippet: fixSnippet,
            owasp_reference: 'A05:2021 – Security Misconfiguration',
          });
        }
      } else if (status === 403) {
        // 403 means path exists but is protected — lower severity info
        if (isHighValuePath(pathDef.path)) {
          findings.push({
            vulnerability_type: `Restricted-${pathDef.path.replace(/\W+/g, '-').replace(/^-+|-+$/g, '')}`,
            category: 'info',
            severity: 'info',
            cvss_score: 1.0,
            confidence_score: 80,
            title: `${pathDef.title} (Access Restricted)`,
            description: `${pathDef.description} The path exists but access is currently restricted (HTTP 403).`,
            affected_url: url,
            evidence: `GET ${url} → HTTP 403 Forbidden (path exists, access blocked)`,
            fix_difficulty: 'easy',
            fix_description: 'Good — access is restricted. Consider removing the file entirely if it is not needed.',
            owasp_reference: 'A05:2021 – Security Misconfiguration',
          });
        }
      }
    } catch (err) {
      // Timeout or connection error — skip silently
      if (onProgress) onProgress(`Skipped ${pathDef.path} (${err.code || 'error'})`);
    }
  }

  return findings;
}

/**
 * Extra verification to prevent false positives.
 * Checks if the response actually looks like the file we expected.
 */
function verifyExposure(path, body, contentType, status) {
  const lowerBody = body.toLowerCase();
  
  if (path === '/.env') {
    // .env file should contain KEY=VALUE pairs
    return /[A-Z_]+=.+/.test(body) || body.includes('APP_KEY') || body.includes('DB_');
  }
  if (path === '/.git/HEAD') {
    return body.startsWith('ref:') || body.trim().match(/^[0-9a-f]{40}$/);
  }
  if (path === '/phpinfo.php' || path === '/info.php') {
    return lowerBody.includes('phpinfo') || lowerBody.includes('php version');
  }
  if (path.includes('.log')) {
    return body.length > 50; // Log files have content
  }
  if (path === '/package.json') {
    return lowerBody.includes('"name"') && lowerBody.includes('"version"');
  }
  if (path.endsWith('.htaccess')) {
    return lowerBody.includes('rewriterule') || lowerBody.includes('order allow') || body.includes('Options');
  }
  // Default: if it returns 200 with content, consider it exposed
  return body.length > 20 && !lowerBody.includes('404') && !lowerBody.includes('not found');
}

function isHighValuePath(path) {
  const highValue = ['/.env', '/.git', '/phpinfo', '/phpmyadmin', '/wp-config', '/admin'];
  return highValue.some(p => path.startsWith(p));
}

function severityToCvss(severity) {
  const map = { critical: 9.1, high: 7.5, medium: 5.3, low: 3.1, info: 0 };
  return map[severity] || 3.0;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * checkOpenRedirects — tests common redirect parameters with a canary external URL.
 * Only reports if the server actually redirects to the injected value (no false positives).
 * @param {string} baseUrl  - Final resolved URL of the target
 * @param {function} onProgress
 * @returns {Array}
 */
async function checkOpenRedirects(baseUrl, onProgress) {
  const findings = [];
  const TIMEOUT = parseInt(process.env.SCANNER_TIMEOUT || '8000');
  const CANARY = 'https://evil.example.com/open-redirect-test';

  // Common open redirect parameter names
  const params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'redirect_uri',
                  'destination', 'goto', 'target', 'redir', 'location', 'continue'];

  let found = false;

  for (const param of params) {
    if (found) break; // One confirmed finding is enough
    try {
      const testUrl = `${baseUrl.replace(/\/$/, '')}?${param}=${encodeURIComponent(CANARY)}`;
      if (onProgress) onProgress(`Checking open redirect: ?${param}=...`);

      const response = await axios.get(testUrl, {
        timeout: TIMEOUT,
        maxRedirects: 0,  // Don't follow redirects — we want to see the Location header
        validateStatus: s => s >= 200 && s < 400,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PenChecker-Scanner/1.0)' },
      }).catch(e => e.response); // Axios throws on 3xx when maxRedirects=0

      if (!response) continue;
      const status = response.status;
      const location = response.headers?.location || '';

      // Confirm redirect to our canary
      if ((status === 301 || status === 302 || status === 303 || status === 307 || status === 308)
          && location.includes('evil.example.com')) {
        found = true;
        findings.push({
          vulnerability_type: 'Open Redirect',
          category:           'redirect',
          severity:           'medium',
          cvss_score:         6.1,
          confidence_score:   98,
          title:              `Open Redirect via ?${param}= Parameter`,
          description:        `The application redirects users to an external URL supplied via the "${param}" parameter without validation. Attackers exploit this to craft phishing links that appear to originate from your trusted domain (e.g., yourdomain.com/redirect?${param}=https://phishing.com).`,
          evidence:           `GET ${testUrl}\n→ HTTP ${status} Location: ${location}`,
          affected_url:       testUrl,
          fix_difficulty:     'moderate',
          fix_description:    `Validate redirect targets against a whitelist of allowed domains. Never redirect to user-supplied URLs without validation.`,
          fix_code_snippet:   `// Express.js — safe redirect helper\nconst ALLOWED_REDIRECT_HOSTS = ['yourdomain.com', 'app.yourdomain.com'];\n\nfunction safeRedirect(res, url, fallback = '/') {\n  try {\n    const parsed = new URL(url);\n    if (ALLOWED_REDIRECT_HOSTS.includes(parsed.hostname)) {\n      return res.redirect(parsed.toString());\n    }\n  } catch (e) {\n    // Relative URLs are OK\n    if (!url.startsWith('http')) return res.redirect(url);\n  }\n  return res.redirect(fallback);\n}`,
          owasp_reference:    'OWASP A01:2021 – Broken Access Control',
        });
      }
    } catch {
      // Silently skip params that error
    }
  }

  return findings;
}

module.exports = { checkPaths, checkOpenRedirects };
