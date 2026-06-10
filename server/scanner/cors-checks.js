'use strict';
/**
 * cors-checks.js
 * Checks for CORS (Cross-Origin Resource Sharing) misconfigurations.
 * All checks are based on actual response headers — no simulation.
 */

/**
 * @param {object} headers     - HTTP response headers (lowercased keys)
 * @param {string} finalUrl    - The final resolved URL of the target
 * @returns {Array}            - Array of finding objects
 */
function checkCORS(headers, finalUrl) {
  const findings = [];

  const acao = headers['access-control-allow-origin'];
  const acac = (headers['access-control-allow-credentials'] || '').toLowerCase();
  const acam = headers['access-control-allow-methods'];

  if (!acao) return findings; // No CORS headers — nothing to check

  // ── Wildcard origin ───────────────────────────────────────────────────────
  if (acao === '*') {
    if (acac === 'true') {
      // Wildcard + credentials = CRITICAL (browsers block it, but misconfigured
      // servers show developer intent to allow this which is dangerous)
      findings.push({
        vulnerability_type: 'CORS Wildcard With Credentials',
        category:           'cors',
        severity:           'critical',
        cvss_score:         9.1,
        confidence_score:   95,
        title:              'CORS: Wildcard Origin With Credentials Allowed',
        description:        'The server sets Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true. While browsers will block this combination, the server\'s intent suggests a misconfigured CORS policy that may be exploitable with custom HTTP clients, allowing cross-origin authenticated requests from any origin.',
        evidence:           `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        affected_url:       finalUrl,
        fix_difficulty:     'easy',
        fix_description:    'Never combine wildcard origin with credentials. Explicitly whitelist allowed origins.',
        fix_code_snippet:   `// Express.js — whitelist specific origins\nconst allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];\napp.use(cors({\n  origin: (origin, cb) => {\n    if (!origin || allowedOrigins.includes(origin)) cb(null, true);\n    else cb(new Error('CORS not allowed'));\n  },\n  credentials: true\n}));`,
        owasp_reference:    'OWASP A05:2021 – Security Misconfiguration',
      });
    } else {
      // Wildcard without credentials — medium risk (fine for public APIs, bad for authenticated)
      findings.push({
        vulnerability_type: 'CORS Wildcard Origin',
        category:           'cors',
        severity:           'medium',
        cvss_score:         5.4,
        confidence_score:   90,
        title:              'CORS: Wildcard Origin Policy (Access-Control-Allow-Origin: *)',
        description:        'The server allows cross-origin requests from any domain. While acceptable for fully public APIs, this is dangerous for endpoints that return sensitive data or are used with authentication. Any website can read responses from these endpoints.',
        evidence:           `Access-Control-Allow-Origin: ${acao}`,
        affected_url:       finalUrl,
        fix_difficulty:     'easy',
        fix_description:    'Replace the wildcard with an explicit list of trusted origins.',
        fix_code_snippet:   `// Nginx\nadd_header Access-Control-Allow-Origin "https://yourdomain.com" always;\n\n// Express.js\napp.use(cors({ origin: 'https://yourdomain.com' }));`,
        owasp_reference:    'OWASP A05:2021 – Security Misconfiguration',
      });
    }
  }

  // ── Overly permissive methods ─────────────────────────────────────────────
  if (acam && /\bDELETE\b|\bPUT\b|\bPATCH\b/i.test(acam) && acao === '*') {
    findings.push({
      vulnerability_type: 'CORS Permissive Methods',
      category:           'cors',
      severity:           'medium',
      cvss_score:         4.9,
      confidence_score:   85,
      title:              'CORS: Dangerous HTTP Methods Allowed from Any Origin',
      description:        `The server allows cross-origin requests using ${acam} methods from any origin. This permits destructive operations (DELETE, PUT, PATCH) to be initiated from arbitrary third-party websites.`,
      evidence:           `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Methods: ${acam}`,
      affected_url:       finalUrl,
      fix_difficulty:     'moderate',
      fix_description:    'Restrict CORS to GET/POST for public endpoints. Require explicit origin for mutation methods.',
      fix_code_snippet:   `// Express.js\napp.use(cors({\n  origin: 'https://yourdomain.com',\n  methods: ['GET', 'POST'],\n  credentials: true\n}));`,
      owasp_reference:    'OWASP A01:2021 – Broken Access Control',
    });
  }

  return findings;
}

module.exports = { checkCORS };
