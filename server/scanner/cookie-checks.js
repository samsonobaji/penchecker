'use strict';
/**
 * cookie-checks.js
 * Analyses Set-Cookie response headers for security misconfigurations.
 * All findings are based on actual response data — no simulation.
 */

/**
 * @param {object} headers  - HTTP response headers (lowercased keys)
 * @param {boolean} isHttps - Whether the connection was over HTTPS
 * @returns {Array}         - Array of finding objects
 */
function checkCookies(headers, isHttps) {
  const findings = [];

  // Collect all Set-Cookie header values (can be an array or a string)
  let cookies = headers['set-cookie'];
  if (!cookies) return findings;
  if (!Array.isArray(cookies)) cookies = [cookies];

  for (const raw of cookies) {
    const lower = raw.toLowerCase();

    // Extract cookie name for evidence
    const name = raw.split('=')[0].trim();

    // ── Secure flag (only meaningful over HTTPS) ──────────────────────────────
    if (isHttps && !/;\s*secure\b/i.test(raw)) {
      findings.push({
        vulnerability_type: 'Cookie Missing Secure Flag',
        category:           'cookie',
        severity:           'medium',
        cvss_score:         5.3,
        confidence_score:   95,
        title:              `Cookie "${name}" Missing Secure Flag`,
        description:        'The Secure attribute instructs browsers to only send the cookie over encrypted HTTPS connections. Without it, the cookie can be transmitted over unencrypted HTTP, exposing it to network interception (man-in-the-middle attacks).',
        evidence:           `Set-Cookie: ${raw.substring(0, 120)}`,
        affected_url:       '',
        fix_difficulty:     'easy',
        fix_description:    'Add the Secure attribute to the Set-Cookie directive.',
        fix_code_snippet:   `// Express.js example\nres.cookie('session', value, { secure: true, httpOnly: true, sameSite: 'strict' });\n\n// Nginx (for proxy_pass scenarios)\nproxy_cookie_flags ~ secure httponly samesite=strict;`,
        owasp_reference:    'OWASP A05:2021 – Security Misconfiguration',
      });
    }

    // ── HttpOnly flag ─────────────────────────────────────────────────────────
    if (!/;\s*httponly\b/i.test(raw)) {
      findings.push({
        vulnerability_type: 'Cookie Missing HttpOnly Flag',
        category:           'cookie',
        severity:           'medium',
        cvss_score:         4.7,
        confidence_score:   95,
        title:              `Cookie "${name}" Missing HttpOnly Flag`,
        description:        'The HttpOnly attribute prevents client-side JavaScript from accessing the cookie. Without it, a successful XSS attack could steal the session token and allow account takeover.',
        evidence:           `Set-Cookie: ${raw.substring(0, 120)}`,
        affected_url:       '',
        fix_difficulty:     'easy',
        fix_description:    'Add the HttpOnly attribute to all session/auth cookies.',
        fix_code_snippet:   `// Express.js\nres.cookie('session', value, { httpOnly: true, secure: true });`,
        owasp_reference:    'OWASP A07:2021 – Identification and Authentication Failures',
      });
    }

    // ── SameSite attribute ────────────────────────────────────────────────────
    if (!/;\s*samesite\s*=/i.test(raw)) {
      findings.push({
        vulnerability_type: 'Cookie Missing SameSite Attribute',
        category:           'cookie',
        severity:           'low',
        cvss_score:         3.1,
        confidence_score:   90,
        title:              `Cookie "${name}" Missing SameSite Attribute`,
        description:        'The SameSite attribute controls whether cookies are sent with cross-site requests. Without it, the browser defaults to "Lax" in modern browsers, but older browsers may send cookies with all cross-site requests, enabling CSRF attacks.',
        evidence:           `Set-Cookie: ${raw.substring(0, 120)}`,
        affected_url:       '',
        fix_difficulty:     'easy',
        fix_description:    'Add SameSite=Strict or SameSite=Lax to cookies. Use Strict for session cookies.',
        fix_code_snippet:   `// Express.js\nres.cookie('session', value, { sameSite: 'strict' });\n\n// Nginx proxy header rewrite\nproxy_cookie_flags ~ samesite=strict;`,
        owasp_reference:    'OWASP A01:2021 – Broken Access Control',
      });
    }

    // ── Session cookie with no expiry / very long max-age ────────────────────
    const maxAgeMatch = lower.match(/;\s*max-age\s*=\s*(\d+)/);
    if (maxAgeMatch) {
      const maxAgeDays = parseInt(maxAgeMatch[1]) / 86400;
      if (maxAgeDays > 30) {
        findings.push({
          vulnerability_type: 'Cookie Long Expiry',
          category:           'cookie',
          severity:           'info',
          cvss_score:         2.1,
          confidence_score:   80,
          title:              `Cookie "${name}" Has Long Expiry (${Math.round(maxAgeDays)} days)`,
          description:        `The cookie is set to persist for ${Math.round(maxAgeDays)} days. Long-lived session cookies extend the window of exploitation if the token is stolen. Consider shorter session durations with sliding expiry.`,
          evidence:           `Set-Cookie: ${raw.substring(0, 120)}`,
          affected_url:       '',
          fix_difficulty:     'easy',
          fix_description:    'Reduce Max-Age to 7 days or less for session cookies. Implement sliding expiry server-side.',
          fix_code_snippet:   `// Express.js — 7-day sliding expiry\nres.cookie('session', value, { maxAge: 7 * 24 * 60 * 60 * 1000 });`,
          owasp_reference:    'OWASP A07:2021 – Identification and Authentication Failures',
        });
      }
    }
  }

  // Deduplicate by vulnerability_type (don't report the same class of issue 10 times)
  const seen = new Set();
  return findings.filter(f => {
    const key = f.vulnerability_type;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { checkCookies };
