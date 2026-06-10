'use strict';
/**
 * content-checks.js
 * Analyzes real HTML content for security issues.
 * Only reports what is actually found in the HTML.
 */
const cheerio = require('cheerio');

function analyzeContent(html, baseUrl, isHttps) {
  const findings = [];
  if (!html || html.length < 10) return findings;

  let $;
  try {
    $ = cheerio.load(html);
  } catch {
    return findings;
  }

  // ─── 1. Forms without CSRF protection ─────────────────────────────────────
  const forms = $('form');
  let formsWithoutCsrf = 0;
  let formCount = 0;

  forms.each((_, form) => {
    formCount++;
    const method = ($(form).attr('method') || 'get').toLowerCase();
    if (method !== 'post') return; // Only POST forms need CSRF

    // Look for common CSRF token field names
    const hasCsrfField = $(form).find(
      'input[name*="csrf"], input[name*="_token"], input[name*="nonce"], input[name*="authenticity_token"], input[name*="__RequestVerificationToken"]'
    ).length > 0;

    // Check for meta csrf tag
    const hasMetaCsrf = $('meta[name="csrf-token"]').length > 0;

    if (!hasCsrfField && !hasMetaCsrf) {
      formsWithoutCsrf++;
    }
  });

  if (formsWithoutCsrf > 0) {
    findings.push({
      vulnerability_type: 'Missing-CSRF-Protection',
      category: 'auth',
      severity: 'high',
      cvss_score: 6.5,
      confidence_score: 75,
      title: 'Potential Cross-Site Request Forgery (CSRF)',
      description: `${formsWithoutCsrf} POST form(s) found without visible CSRF token fields. This may allow attackers to trick authenticated users into submitting unintended actions.`,
      evidence: `${formsWithoutCsrf} of ${formCount} POST form(s) lack CSRF protection tokens.`,
      fix_difficulty: 'moderate',
      fix_description: 'Implement CSRF tokens in all state-changing forms. Most frameworks have built-in CSRF protection.',
      fix_code_snippet: `<!-- Add hidden CSRF token to each form -->\n<form method="POST">\n  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">\n  ...\n</form>`,
      owasp_reference: 'A01:2021 – Broken Access Control',
    });
  }

  // ─── 2. Forms submitting over HTTP (mixed content) ─────────────────────────
  if (isHttps) {
    let insecureForms = 0;
    forms.each((_, form) => {
      const action = $(form).attr('action') || '';
      if (action.startsWith('http://')) insecureForms++;
    });
    if (insecureForms > 0) {
      findings.push({
        vulnerability_type: 'Insecure-Form-Action',
        category: 'ssl',
        severity: 'high',
        cvss_score: 6.1,
        confidence_score: 99,
        title: `${insecureForms} Form(s) Submit Data Over Insecure HTTP`,
        description: `Form action URLs point to HTTP (not HTTPS) endpoints. Data submitted in these forms is transmitted in plaintext.`,
        evidence: `${insecureForms} form(s) have action attributes pointing to http:// URLs`,
        fix_difficulty: 'easy',
        fix_description: 'Update all form action URLs to use HTTPS.',
        owasp_reference: 'A02:2021 – Cryptographic Failures',
      });
    }
  }

  // ─── 3. HTML comments that may leak sensitive info ────────────────────────
  const sensitiveCommentPatterns = [
    /password/i, /passwd/i, /secret/i, /api[_\s-]key/i, /token/i,
    /todo.*auth/i, /hack/i, /remove.*before.*prod/i, /debug/i,
    /username/i, /admin/i, /\/admin\//i, /test.*cred/i,
  ];
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let match;
  const sensitiveComments = [];
  const rawHtml = $.html();

  while ((match = commentRegex.exec(rawHtml)) !== null) {
    const comment = match[1].trim();
    if (comment.length < 3 || comment.startsWith('[if') || comment.startsWith('[endif')) continue;
    for (const pattern of sensitiveCommentPatterns) {
      if (pattern.test(comment)) {
        sensitiveComments.push(comment.substring(0, 100));
        break;
      }
    }
  }

  if (sensitiveComments.length > 0) {
    findings.push({
      vulnerability_type: 'Sensitive-Info-In-Comments',
      category: 'exposure',
      severity: 'medium',
      cvss_score: 4.3,
      confidence_score: 70,
      title: 'Potentially Sensitive Information in HTML Comments',
      description: 'HTML comments containing potentially sensitive keywords were found in the page source. These are visible to anyone who views the page source.',
      evidence: `Found ${sensitiveComments.length} suspicious comment(s):\n${sensitiveComments.map(c => `  <!-- ${c} -->`).join('\n')}`,
      fix_difficulty: 'easy',
      fix_description: 'Remove all HTML comments from production code, especially those containing credentials, paths, or TODO notes.',
      owasp_reference: 'A05:2021 – Security Misconfiguration',
    });
  }

  // ─── 4. Mixed content (HTTP resources on HTTPS page) ─────────────────────
  if (isHttps) {
    const httpResources = [];
    $('script[src], img[src], link[href], iframe[src]').each((_, el) => {
      const src = $(el).attr('src') || $(el).attr('href') || '';
      if (src.startsWith('http://')) {
        httpResources.push({ tag: el.tagName, src: src.substring(0, 80) });
      }
    });

    if (httpResources.length > 0) {
      findings.push({
        vulnerability_type: 'Mixed-Content',
        category: 'ssl',
        severity: 'medium',
        cvss_score: 4.3,
        confidence_score: 99,
        title: `Mixed Content — ${httpResources.length} Resource(s) Loaded Over HTTP`,
        description: `The HTTPS page loads ${httpResources.length} resource(s) over insecure HTTP. Browsers may block these resources and the connection is vulnerable to MITM attacks.`,
        evidence: httpResources.slice(0, 3).map(r => `<${r.tag} src="${r.src}">`).join('\n'),
        fix_difficulty: 'easy',
        fix_description: 'Update all resource URLs to use HTTPS or protocol-relative URLs (//).',
        fix_code_snippet: `<!-- Change:\n<script src="http://example.com/script.js">\n<!-- To:\n<script src="https://example.com/script.js">`,
        owasp_reference: 'A02:2021 – Cryptographic Failures',
      });
    }
  }

  // ─── 5. Autocomplete enabled on password/sensitive fields ─────────────────
  const pwFields = $('input[type="password"]');
  let insecureAutoComplete = 0;
  pwFields.each((_, el) => {
    const ac = ($(el).attr('autocomplete') || '').toLowerCase();
    if (ac !== 'off' && ac !== 'new-password' && ac !== 'current-password') {
      insecureAutoComplete++;
    }
  });

  if (insecureAutoComplete > 0) {
    findings.push({
      vulnerability_type: 'Password-Autocomplete',
      category: 'auth',
      severity: 'low',
      cvss_score: 2.6,
      confidence_score: 85,
      title: 'Password Field Allows Browser Autocomplete',
      description: `${insecureAutoComplete} password field(s) do not explicitly disable browser autocomplete. On shared computers, this may lead to credential exposure.`,
      evidence: `${insecureAutoComplete} <input type="password"> element(s) without autocomplete="off"`,
      fix_difficulty: 'easy',
      fix_description: 'Add autocomplete="off" or autocomplete="current-password" to password fields.',
      fix_code_snippet: `<input type="password" name="password" autocomplete="current-password">`,
      owasp_reference: 'A07:2021 – Identification and Authentication Failures',
    });
  }

  // ─── 6. External scripts without integrity check ─────────────────────────
  const externalScripts = $('script[src]').filter((_, el) => {
    const src = $(el).attr('src') || '';
    return src.startsWith('http') || src.startsWith('//');
  });
  let scriptsWithoutSRI = 0;
  externalScripts.each((_, el) => {
    if (!$(el).attr('integrity')) scriptsWithoutSRI++;
  });

  if (scriptsWithoutSRI > 2) { // Only flag if there are several
    findings.push({
      vulnerability_type: 'Missing-SRI',
      category: 'misconfiguration',
      severity: 'low',
      cvss_score: 3.7,
      confidence_score: 80,
      title: 'External Scripts Without Subresource Integrity (SRI)',
      description: `${scriptsWithoutSRI} external script(s) loaded without integrity attributes. If the CDN is compromised, malicious code could be injected.`,
      evidence: `${scriptsWithoutSRI} external <script> tags lack integrity="sha256-..." attributes`,
      fix_difficulty: 'moderate',
      fix_description: 'Add SRI integrity hashes to all external scripts.',
      fix_code_snippet: `<!-- Generate hash at: https://www.srihash.org/ -->\n<script\n  src="https://cdn.example.com/library.min.js"\n  integrity="sha256-HASH_HERE"\n  crossorigin="anonymous">\n</script>`,
      owasp_reference: 'A08:2021 – Software and Data Integrity Failures',
    });
  }

  return findings;
}

/**
 * Analyze robots.txt for sensitive path disclosures
 */
function analyzeRobotsTxt(robotsTxt, baseUrl) {
  const findings = [];
  if (!robotsTxt) return findings;

  const sensitivePathPatterns = [
    /admin/i, /config/i, /backup/i, /\.env/i, /secret/i,
    /private/i, /internal/i, /\.git/i, /database/i, /log/i,
    /api\/v\d/i, /swagger/i, /phpmyadmin/i,
  ];

  const disallowedPaths = [];
  const lines = robotsTxt.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.toLowerCase().startsWith('disallow:')) {
      const path = trimmed.substring(9).trim();
      if (path && path !== '/' && path !== '*') {
        for (const pattern of sensitivePathPatterns) {
          if (pattern.test(path)) {
            disallowedPaths.push(path);
            break;
          }
        }
      }
    }
  }

  if (disallowedPaths.length > 0) {
    findings.push({
      vulnerability_type: 'Sensitive-Paths-In-Robots',
      category: 'exposure',
      severity: 'low',
      cvss_score: 3.1,
      confidence_score: 90,
      title: 'Sensitive Paths Disclosed in robots.txt',
      description: 'The robots.txt file reveals potentially sensitive directory paths that may be worth investigating.',
      evidence: `Sensitive Disallow entries found:\n${disallowedPaths.map(p => `  Disallow: ${p}`).join('\n')}`,
      fix_difficulty: 'easy',
      fix_description: 'Avoid listing sensitive paths in robots.txt. Security through obscurity is not a substitute for proper access control.',
      owasp_reference: 'A05:2021 – Security Misconfiguration',
    });
  }

  return findings;
}

module.exports = { analyzeContent, analyzeRobotsTxt };
