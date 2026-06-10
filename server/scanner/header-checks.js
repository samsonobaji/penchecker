'use strict';
/**
 * header-checks.js
 * Analyzes HTTP response headers for security issues.
 * ONLY reports what is actually missing or misconfigured.
 */

const SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    severity: 'high',
    cvss: 6.5,
    category: 'headers',
    title: 'Missing Content-Security-Policy Header',
    description: 'The Content-Security-Policy (CSP) header is not set. CSP helps prevent Cross-Site Scripting (XSS) and data injection attacks by controlling which resources the browser is allowed to load.',
    description_simple: 'Your site does not tell browsers what content is safe to load, making it easier for attackers to inject malicious scripts.',
    fix: 'Add a Content-Security-Policy header to your web server or application. Start with a strict policy and relax as needed.',
    fix_code: `# Nginx\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:;";\n\n# Apache\nHeader always set Content-Security-Policy "default-src 'self';"`,
    owasp: 'A05:2021 – Security Misconfiguration',
    difficulty: 'moderate',
    confidence: 99,
  },
  {
    name: 'X-Frame-Options',
    severity: 'medium',
    cvss: 4.3,
    category: 'headers',
    title: 'Missing X-Frame-Options Header',
    description: 'The X-Frame-Options header is not set. Without this header, your site can be embedded in an iframe on a malicious site, enabling Clickjacking attacks.',
    description_simple: 'Your site can be hidden inside another website in an invisible frame, tricking users into clicking on things they did not intend to.',
    fix: 'Add the X-Frame-Options header with value DENY or SAMEORIGIN.',
    fix_code: `# Nginx\nadd_header X-Frame-Options "SAMEORIGIN" always;\n\n# Apache\nHeader always set X-Frame-Options "SAMEORIGIN"`,
    owasp: 'A05:2021 – Security Misconfiguration',
    difficulty: 'easy',
    confidence: 99,
  },
  {
    name: 'X-Content-Type-Options',
    severity: 'medium',
    cvss: 4.0,
    category: 'headers',
    title: 'Missing X-Content-Type-Options Header',
    description: 'The X-Content-Type-Options header is not set to "nosniff". Browsers may attempt to MIME-sniff the content type, which can be exploited to execute malicious scripts.',
    description_simple: 'Browsers may guess the type of file being served and execute something that was not intended to be executed.',
    fix: 'Add X-Content-Type-Options: nosniff to all HTTP responses.',
    fix_code: `# Nginx\nadd_header X-Content-Type-Options "nosniff" always;\n\n# Apache\nHeader always set X-Content-Type-Options "nosniff"`,
    owasp: 'A05:2021 – Security Misconfiguration',
    difficulty: 'easy',
    confidence: 99,
  },
  {
    name: 'Strict-Transport-Security',
    severity: 'high',
    cvss: 6.0,
    category: 'ssl',
    title: 'Missing HTTP Strict Transport Security (HSTS)',
    description: 'The Strict-Transport-Security (HSTS) header is missing. Without HSTS, browsers may still allow HTTP connections, leaving users vulnerable to protocol downgrade attacks.',
    description_simple: 'Your site does not force browsers to always use the secure HTTPS connection, which could allow attackers to intercept traffic.',
    fix: 'Add a Strict-Transport-Security header with a max-age of at least 1 year.',
    fix_code: `# Nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n\n# Apache\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`,
    owasp: 'A02:2021 – Cryptographic Failures',
    difficulty: 'easy',
    confidence: 99,
  },
  {
    name: 'Referrer-Policy',
    severity: 'low',
    cvss: 3.1,
    category: 'headers',
    title: 'Missing Referrer-Policy Header',
    description: 'No Referrer-Policy header is set. By default, browsers may send the full URL in the Referer header to external sites, potentially leaking sensitive information.',
    description_simple: 'When a user clicks a link on your site, the destination site may see the URL they came from, including any sensitive parameters.',
    fix: 'Add a Referrer-Policy header with an appropriate value.',
    fix_code: `# Nginx\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
    owasp: 'A05:2021 – Security Misconfiguration',
    difficulty: 'easy',
    confidence: 95,
  },
  {
    name: 'Permissions-Policy',
    severity: 'low',
    cvss: 2.8,
    category: 'headers',
    title: 'Missing Permissions-Policy Header',
    description: 'The Permissions-Policy header (formerly Feature-Policy) is not set. This header controls access to browser features like camera, microphone, and geolocation.',
    description_simple: 'Any script on your page can request access to your users camera, microphone, or location without restriction.',
    fix: 'Add a Permissions-Policy header that restricts access to browser features.',
    fix_code: `# Nginx\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=(self)" always;`,
    owasp: 'A05:2021 – Security Misconfiguration',
    difficulty: 'easy',
    confidence: 90,
  },
];

const INFO_HEADERS = [
  { name: 'Server', pattern: /.+/, message: 'Server header reveals software' },
  { name: 'X-Powered-By', pattern: /.+/, message: 'X-Powered-By header reveals technology' },
  { name: 'X-AspNet-Version', pattern: /.+/, message: 'ASP.NET version disclosed' },
  { name: 'X-Generator', pattern: /.+/, message: 'Generator software disclosed' },
];

function checkHeaders(headers, isHttps) {
  const findings = [];
  const lowerHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    lowerHeaders[k.toLowerCase()] = v;
  }

  // Check required security headers
  for (const h of SECURITY_HEADERS) {
    const val = lowerHeaders[h.name.toLowerCase()];
    
    // Skip HSTS check if site is not HTTPS (would be a separate SSL finding)
    if (h.name === 'Strict-Transport-Security' && !isHttps) continue;

    if (!val) {
      findings.push({
        vulnerability_type: h.name,
        category: h.category,
        severity: h.severity,
        cvss_score: h.cvss,
        confidence_score: h.confidence,
        title: h.title,
        description: h.description,
        evidence: `HTTP response header "${h.name}" is absent from the server response.`,
        fix_difficulty: h.difficulty,
        fix_description: h.fix,
        fix_code_snippet: h.fix_code,
        owasp_reference: h.owasp,
      });
    } else {
      // Check for weak CSP
      if (h.name === 'Content-Security-Policy' && (val.includes("'unsafe-eval'") || val === '' || val.includes('*'))) {
        findings.push({
          vulnerability_type: 'Weak-CSP',
          category: 'headers',
          severity: 'medium',
          cvss_score: 4.5,
          confidence_score: 85,
          title: 'Weak Content-Security-Policy Detected',
          description: `The CSP header is present but uses unsafe directives: "${val.substring(0, 120)}"`,
          evidence: `Content-Security-Policy: ${val.substring(0, 200)}`,
          fix_difficulty: 'moderate',
          fix_description: 'Remove unsafe-eval and wildcard (*) directives from your CSP policy.',
          fix_code_snippet: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';`,
          owasp_reference: 'A05:2021 – Security Misconfiguration',
        });
      }
    }
  }

  // Check for information disclosure in response headers
  for (const h of INFO_HEADERS) {
    const val = lowerHeaders[h.name.toLowerCase()];
    if (val && h.pattern.test(val)) {
      findings.push({
        vulnerability_type: 'Information-Disclosure-Header',
        category: 'info',
        severity: 'info',
        cvss_score: 2.0,
        confidence_score: 99,
        title: `Server Information Disclosed via ${h.name} Header`,
        description: `The ${h.name} response header reveals server software information that could help an attacker identify vulnerable components.`,
        evidence: `${h.name}: ${val}`,
        fix_difficulty: 'easy',
        fix_description: `Remove or obscure the ${h.name} header in your web server configuration.`,
        fix_code_snippet: `# Nginx — in nginx.conf:\nserver_tokens off;\n\n# Apache — in httpd.conf:\nServerSignature Off\nServerTokens Prod`,
        owasp_reference: 'A05:2021 – Security Misconfiguration',
      });
    }
  }

  // Check CORS
  const acao = lowerHeaders['access-control-allow-origin'];
  if (acao === '*') {
    findings.push({
      vulnerability_type: 'Permissive-CORS',
      category: 'misconfiguration',
      severity: 'medium',
      cvss_score: 5.3,
      confidence_score: 99,
      title: 'Overly Permissive CORS Policy',
      description: 'The Access-Control-Allow-Origin header is set to * (wildcard), allowing any domain to make cross-origin requests to this server.',
      evidence: 'Access-Control-Allow-Origin: *',
      fix_difficulty: 'moderate',
      fix_description: 'Restrict the CORS policy to only allow trusted origins.',
      fix_code_snippet: `# Nginx\nadd_header Access-Control-Allow-Origin "https://yourdomain.com";`,
      owasp_reference: 'A01:2021 – Broken Access Control',
    });
  }

  return findings;
}

module.exports = { checkHeaders };
