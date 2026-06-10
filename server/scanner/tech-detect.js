'use strict';
/**
 * tech-detect.js
 * Detects technology stack from REAL HTTP response headers and HTML content.
 * Only reports technologies that are actually detected.
 */

// Map of tech detection rules
const HEADER_TECH = [
  // Server headers
  { header: 'server', pattern: /nginx/i, tech: 'Nginx', category: 'webserver' },
  { header: 'server', pattern: /apache/i, tech: 'Apache', category: 'webserver' },
  { header: 'server', pattern: /iis\//i, tech: 'IIS', category: 'webserver' },
  { header: 'server', pattern: /litespeed/i, tech: 'LiteSpeed', category: 'webserver' },
  { header: 'server', pattern: /cloudflare/i, tech: 'Cloudflare', category: 'cdn' },
  // X-Powered-By
  { header: 'x-powered-by', pattern: /php\//i, tech: 'PHP', category: 'language' },
  { header: 'x-powered-by', pattern: /asp\.net/i, tech: 'ASP.NET', category: 'framework' },
  { header: 'x-powered-by', pattern: /express/i, tech: 'Express.js', category: 'framework' },
  { header: 'x-powered-by', pattern: /next\.js/i, tech: 'Next.js', category: 'framework' },
  // CDN / WAF
  { header: 'cf-ray', pattern: /.+/, tech: 'Cloudflare', category: 'cdn' },
  { header: 'x-amz-cf-id', pattern: /.+/, tech: 'Amazon CloudFront', category: 'cdn' },
  { header: 'x-vercel-id', pattern: /.+/, tech: 'Vercel', category: 'hosting' },
  { header: 'x-netlify', pattern: /.+/, tech: 'Netlify', category: 'hosting' },
  { header: 'x-github-request-id', pattern: /.+/, tech: 'GitHub Pages', category: 'hosting' },
  // Cookie-based detection
  { header: 'set-cookie', pattern: /PHPSESSID/i, tech: 'PHP', category: 'language' },
  { header: 'set-cookie', pattern: /laravel_session/i, tech: 'Laravel', category: 'framework' },
  { header: 'set-cookie', pattern: /JSESSIONID/i, tech: 'Java', category: 'language' },
  { header: 'set-cookie', pattern: /django/i, tech: 'Django', category: 'framework' },
  { header: 'set-cookie', pattern: /ASP\.NET_SessionId/i, tech: 'ASP.NET', category: 'framework' },
  { header: 'set-cookie', pattern: /__stripe_mid/i, tech: 'Stripe', category: 'payment' },
];

const HTML_TECH = [
  // WordPress
  { pattern: /wp-content|wp-includes/i, tech: 'WordPress', category: 'cms' },
  { pattern: /wp-login\.php/i, tech: 'WordPress', category: 'cms' },
  // Drupal
  { pattern: /sites\/default\/files|drupal/i, tech: 'Drupal', category: 'cms' },
  // Joomla
  { pattern: /\/components\/com_|joomla/i, tech: 'Joomla', category: 'cms' },
  // React
  { pattern: /__REACT_APP__|data-reactroot|react\.production\.min\.js/i, tech: 'React', category: 'framework' },
  // Next.js
  { pattern: /__NEXT_DATA__|_next\/static/i, tech: 'Next.js', category: 'framework' },
  // Vue
  { pattern: /vue\.min\.js|vue\.runtime/i, tech: 'Vue.js', category: 'framework' },
  // Angular
  { pattern: /ng-version|angular\.min\.js/i, tech: 'Angular', category: 'framework' },
  // jQuery
  { pattern: /jquery\//i, tech: 'jQuery', category: 'library' },
  // Bootstrap
  { pattern: /bootstrap\.min\.(css|js)/i, tech: 'Bootstrap', category: 'css-framework' },
  // Tailwind
  { pattern: /tailwindcss|tailwind\.min\.css/i, tech: 'Tailwind CSS', category: 'css-framework' },
  // Shopify
  { pattern: /cdn\.shopify\.com/i, tech: 'Shopify', category: 'ecommerce' },
  // WooCommerce
  { pattern: /woocommerce/i, tech: 'WooCommerce', category: 'ecommerce' },
  // Google Analytics
  { pattern: /google-analytics\.com\/analytics\.js|gtag\('/i, tech: 'Google Analytics', category: 'analytics' },
  // Cloudflare
  { pattern: /\/cdn-cgi\/|cloudflare\.com/i, tech: 'Cloudflare', category: 'cdn' },
  // Meta generator
  { pattern: /<meta[^>]+name="generator"[^>]+content="([^"]+)"/i, tech: 'META_GENERATOR', capture: 1, category: 'cms' },
];

function detectTechnologies(headers, html) {
  const detected = new Map(); // Use Map to avoid duplicates

  // Normalize headers
  const lh = {};
  for (const [k, v] of Object.entries(headers)) {
    lh[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }

  // Header-based detection
  for (const rule of HEADER_TECH) {
    const val = lh[rule.header];
    if (val && rule.pattern.test(val)) {
      if (!detected.has(rule.tech)) {
        detected.set(rule.tech, { name: rule.tech, category: rule.category, source: `header:${rule.header}` });
      }
    }
  }

  // HTML-based detection
  if (html) {
    for (const rule of HTML_TECH) {
      if (rule.tech === 'META_GENERATOR') {
        const match = html.match(rule.pattern);
        if (match && match[rule.capture]) {
          const techName = match[rule.capture].trim();
          if (!detected.has(techName)) {
            detected.set(techName, { name: techName, category: rule.category, source: 'meta:generator' });
          }
        }
      } else if (rule.pattern.test(html)) {
        if (!detected.has(rule.tech)) {
          detected.set(rule.tech, { name: rule.tech, category: rule.category, source: 'html' });
        }
      }
    }
  }

  return Array.from(detected.values());
}

/**
 * Returns which paths are worth checking based on detected tech.
 * ONLY returns paths relevant to the detected stack.
 */
function getPathsToCheck(technologies) {
  const techNames = technologies.map(t => t.name.toLowerCase());
  const paths = [];

  // Universal paths (always check)
  paths.push(
    { path: '/.env', severity: 'critical', title: 'Exposed .env File', description: 'Environment file exposed publicly. May contain database credentials, API keys, and secrets.' },
    { path: '/.git/HEAD', severity: 'high', title: 'Exposed .git Repository', description: 'Git repository metadata is publicly accessible. Attackers can reconstruct source code.' },
    { path: '/robots.txt', severity: 'info', title: 'robots.txt Found', description: 'robots.txt file found. Review for sensitive path disclosures.', alwaysReport: false, sensitiveCheck: true },
    { path: '/sitemap.xml', severity: 'info', title: 'Sitemap Found', description: 'XML sitemap found. Useful for understanding site structure.' },
    { path: '/.htaccess', severity: 'medium', title: 'Exposed .htaccess File', description: 'Apache .htaccess configuration file is publicly readable.' },
    { path: '/config.json', severity: 'high', title: 'Exposed config.json', description: 'Configuration file may be publicly accessible.' },
    { path: '/package.json', severity: 'medium', title: 'Exposed package.json', description: 'Node.js package file is publicly accessible, revealing dependencies and versions.' },
  );

  // WordPress-specific paths
  if (techNames.some(t => t.includes('wordpress'))) {
    paths.push(
      { path: '/wp-login.php', severity: 'medium', title: 'WordPress Login Page Exposed', description: 'WordPress admin login page is accessible. Consider IP restriction or renaming the login URL.' },
      { path: '/wp-admin/', severity: 'medium', title: 'WordPress Admin Directory Accessible', description: 'WordPress admin area is accessible without restriction.' },
      { path: '/xmlrpc.php', severity: 'high', title: 'WordPress XML-RPC Enabled', description: 'XML-RPC endpoint is enabled. This can be abused for brute-force attacks and DDoS amplification.' },
      { path: '/wp-config.php.bak', severity: 'critical', title: 'WordPress Config Backup Exposed', description: 'wp-config.php backup file found. Contains database credentials.' },
      { path: '/wp-content/debug.log', severity: 'high', title: 'WordPress Debug Log Exposed', description: 'Debug log file is publicly accessible. May contain sensitive error information.' },
    );
  }

  // PHP-specific paths
  if (techNames.some(t => t.includes('php') || t.includes('laravel') || t.includes('drupal') || t.includes('joomla'))) {
    paths.push(
      { path: '/phpinfo.php', severity: 'critical', title: 'PHP Info Page Exposed', description: 'phpinfo() page is publicly accessible. Reveals full server configuration, paths, and PHP settings.' },
      { path: '/info.php', severity: 'critical', title: 'PHP Info Page Exposed', description: 'phpinfo() page is publicly accessible.' },
      { path: '/phpmyadmin/', severity: 'high', title: 'phpMyAdmin Accessible', description: 'phpMyAdmin database management interface is publicly accessible.' },
      { path: '/admin/config.php', severity: 'critical', title: 'Admin Config File Exposed', description: 'Admin configuration file may be publicly readable.' },
    );
  }

  // Laravel-specific
  if (techNames.some(t => t.includes('laravel'))) {
    paths.push(
      { path: '/.env', severity: 'critical', title: 'Laravel .env File Exposed', description: 'Laravel environment file with APP_KEY, database credentials, and other secrets.' },
      { path: '/storage/logs/laravel.log', severity: 'high', title: 'Laravel Log File Exposed', description: 'Application log file is publicly accessible. May contain sensitive error traces.' },
    );
  }

  // ASP.NET specific
  if (techNames.some(t => t.includes('asp.net'))) {
    paths.push(
      { path: '/elmah.axd', severity: 'high', title: 'ELMAH Error Log Exposed', description: 'Error logging handler is publicly accessible. May expose application errors and stack traces.' },
      { path: '/trace.axd', severity: 'high', title: 'ASP.NET Trace Enabled', description: 'ASP.NET tracing is enabled and accessible publicly.' },
    );
  }

  // Deduplicate paths
  const seen = new Set();
  return paths.filter(p => {
    if (seen.has(p.path)) return false;
    seen.add(p.path);
    return true;
  });
}

module.exports = { detectTechnologies, getPathsToCheck };
