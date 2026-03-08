/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Hidden Route & Endpoint Discovery
    Exhaustive probing of common and uncommon paths to find
    hidden admin panels, APIs, debug endpoints, and leaked routes
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch } = require('../helpers/http');

// Massive route wordlist for discovery
const ROUTE_WORDLIST = {
  admin: [
    '/admin', '/admin/', '/admin/login', '/admin/dashboard',
    '/administrator', '/admin-panel', '/_admin', '/cp',
    '/manage', '/manager', '/management', '/backoffice',
    '/cms', '/portal', '/controlpanel', '/webadmin',
    '/siteadmin', '/adm', '/root', '/superadmin',
    '/admin/users', '/admin/settings', '/admin/config',
  ],
  api: [
    '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
    '/api/users', '/api/user', '/api/auth', '/api/login',
    '/api/admin', '/api/config', '/api/settings', '/api/env',
    '/api/health', '/api/status', '/api/version', '/api/info',
    '/api/debug', '/api/test', '/api/ping', '/api/docs',
    '/api/swagger', '/api/schema', '/api/graphql',
    '/api/webhook', '/api/webhooks', '/api/callback',
    '/api/export', '/api/import', '/api/backup',
    '/api/upload', '/api/files', '/api/media',
    '/api/search', '/api/data', '/api/db',
    '/api/keys', '/api/tokens', '/api/secrets',
    '/api/internal', '/api/_internal', '/api/private',
    '/v1', '/v2', '/v3',
  ],
  debug: [
    '/debug', '/debug/', '/debug/info', '/debug/vars',
    '/_debug', '/__debug__', '/trace', '/_trace',
    '/console', '/_console', '/devtools', '/_devtools',
    '/profiler', '/_profiler', '/metrics', '/_metrics',
    '/stats', '/_stats', '/monitor', '/_monitor',
    '/status', '/_status', '/health', '/_health',
    '/info', '/_info', '/server-info', '/__info',
    '/phpinfo', '/phpinfo.php', '/apc.php',
    '/test', '/test/', '/_test', '/testing',
    '/actuator', '/actuator/env', '/actuator/health',
    '/actuator/info', '/actuator/configprops',
    '/actuator/beans', '/actuator/mappings',
    '/.env', '/.env.local', '/.env.production',
    '/env', '/config', '/_config',
  ],
  auth: [
    '/login', '/signin', '/sign-in', '/auth', '/auth/login',
    '/logout', '/signout', '/sign-out', '/auth/logout',
    '/register', '/signup', '/sign-up', '/auth/register',
    '/forgot-password', '/reset-password', '/change-password',
    '/auth/callback', '/auth/token', '/auth/verify',
    '/oauth', '/oauth/authorize', '/oauth/token',
    '/sso', '/saml', '/cas/login',
    '/.auth/me', '/.auth/login', '/.auth/logout',
    '/token', '/jwt', '/session',
  ],
  static: [
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/.well-known/security.txt', '/.well-known/openid-configuration',
    '/.well-known/jwks.json', '/.well-known/assetlinks.json',
    '/.well-known/apple-app-site-association',
    '/favicon.ico', '/manifest.json', '/browserconfig.xml',
    '/humans.txt', '/security.txt', '/ads.txt', '/app-ads.txt',
  ],
  git: [
    '/.git/HEAD', '/.git/config', '/.git/index',
    '/.git/description', '/.git/COMMIT_EDITMSG',
    '/.gitignore', '/.gitattributes',
    '/.svn/entries', '/.svn/wc.db',
    '/.hg/store', '/.bzr/README',
  ],
  config: [
    '/package.json', '/package-lock.json', '/yarn.lock',
    '/composer.json', '/composer.lock', '/Gemfile', '/Gemfile.lock',
    '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
    '/.dockerenv', '/Makefile', '/Procfile', '/Vagrantfile',
    '/webpack.config.js', '/vite.config.js', '/next.config.js',
    '/tsconfig.json', '/jsconfig.json', '/babel.config.js',
    '/.babelrc', '/.eslintrc', '/.eslintrc.json',
    '/.prettierrc', '/tailwind.config.js',
    '/.npmrc', '/.yarnrc', '/pnpm-lock.yaml',
    '/vercel.json', '/netlify.toml', '/fly.toml',
    '/firebase.json', '/.firebaserc',
    '/wrangler.toml', '/serverless.yml',
    '/wp-config.php', '/wp-config-sample.php',
    '/web.config', '/.htaccess', '/.htpasswd',
    '/nginx.conf', '/httpd.conf',
    '/server.xml', '/application.yml', '/application.properties',
  ],
  backup: [
    '/backup', '/backups', '/bak', '/dump',
    '/database.sql', '/db.sql', '/backup.sql', '/dump.sql',
    '/data.sql', '/export.sql', '/mysql.sql', '/postgres.sql',
    '/backup.zip', '/backup.tar.gz', '/backup.tar',
    '/site.zip', '/www.zip', '/web.zip', '/public.zip',
    '/db.sqlite', '/database.sqlite', '/data.db',
    '/backup.bak', '/old', '/_old', '/archive',
  ],
  nextjs: [
    '/_next/data', '/_next/static', '/_next/image',
    '/_next/webpack-hmr', '/_next/static/development',
    '/api/auth/session', '/api/auth/signin', '/api/auth/csrf',
    '/api/auth/providers', '/api/auth/callback',
    '/api/trpc', '/_error', '/404', '/500',
  ],
  wordpress: [
    '/wp-admin', '/wp-login.php', '/wp-json',
    '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts',
    '/wp-content/debug.log', '/wp-content/uploads',
    '/xmlrpc.php', '/wp-cron.php', '/wp-config.php.bak',
  ],
  misc: [
    '/graphql', '/graphiql', '/playground', '/explorer',
    '/swagger', '/swagger-ui', '/swagger.json', '/swagger.yaml',
    '/openapi.json', '/openapi.yaml', '/api-docs', '/redoc',
    '/docs', '/documentation', '/help', '/readme',
    '/changelog', '/release-notes', '/version',
    '/error', '/errors', '/404', '/500',
    '/cgi-bin', '/cgi', '/scripts',
    '/tmp', '/temp', '/cache', '/log', '/logs',
    '/upload', '/uploads', '/files', '/media', '/assets',
    '/public', '/private', '/internal', '/secret',
    '/dev', '/development', '/staging', '/production',
    '/socket.io', '/ws', '/websocket', '/wss',
    '/feed', '/rss', '/atom',
    '/healthz', '/readyz', '/livez',
    '/__nextjs_original-stack-frame', '/__webpack_hmr',
  ],
  // ── Attack surface: brute-force, DDoS, network management ──
  network: [
    '/vpn', '/vpn/login', '/vpn/status', '/vpn/dashboard',
    '/tailscale', '/tailscale/status', '/tailscale/peers', '/tailscale/acls',
    '/wireguard', '/wg', '/wg/status', '/wg/peers',
    '/openvpn', '/ovpn', '/ovpn/status',
    '/.well-known/tailscale', '/ts/status', '/ts/peers',
    '/derp', '/_derp', '/derp/probe',
    '/network', '/network/status', '/network/topology',
    '/internal/network', '/api/v1/network', '/api/network',
    '/mgmt', '/management', '/netmgmt',
    '/tunnel', '/tunnels', '/tunnel/status',
    '/mesh', '/mesh/status', '/mesh/nodes',
    '/zerotier', '/zt', '/zt/status',
  ],
  monitoring: [
    '/prometheus', '/prometheus/metrics', '/metrics/prometheus',
    '/grafana', '/grafana/', '/grafana/login',
    '/netdata', '/netdata/dashboard',
    '/kibana', '/kibana/',
    '/jaeger', '/zipkin', '/tempo',
    '/portainer', '/portainer/',
    '/traefik', '/traefik/dashboard',
    '/loki', '/loki/ready',
    '/alertmanager', '/alertmanager/',
    '/pushgateway',
    '/node-exporter', '/cadvisor',
    '/-/healthy', '/-/ready', '/-/reload',
    '/api/v1/alerts', '/api/v1/targets', '/api/v1/rules',
  ],
  php: [
    '/phpinfo.php', '/info.php', '/php-info.php', '/test.php',
    '/phpmyadmin', '/phpmyadmin/', '/pma', '/pma/',
    '/adminer.php', '/adminer', '/dbadmin',
    '/mysql', '/mysqladmin', '/mysqlmanager',
    '/config.php', '/configuration.php', '/settings.php',
    '/install.php', '/setup.php', '/upgrade.php',
    '/update.php', '/migrate.php',
    '/error_log', '/php_errors.log', '/php.log',
    '/laravel.log', '/storage/logs/laravel.log',
    '/storage/app', '/storage/framework',
    '/artisan', '/index.php/config',
    '/wp-includes/wlwmanifest.xml',
    '/wordpress/wp-login.php',
  ],
  ddos_bruteforce: [
    '/login', '/signin', '/auth/signin', '/auth/sign-in',
    '/api/auth/signin', '/api/auth/login',
    '/user/login', '/users/login', '/account/login',
    '/session', '/session/new', '/sessions/new',
    '/auth/v1/token', '/auth/v1/signup', '/auth/v1/otp',
    '/auth/v1/recover', '/auth/v1/resend',
    '/api/password-reset', '/api/forgot-password',
    '/api/otp/send', '/api/otp/verify',
    '/api/2fa', '/api/mfa', '/api/totp',
    '/admin/login', '/admin/signin',
    '/superadmin/login', '/root/login',
    '/.htpasswd', '/.passwd', '/passwd',
    '/etc/passwd', '/etc/shadow',  // Path traversal test
  ],
};

async function deepRouteDiscovery(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const discoveredRoutes = [];
  const brokenRoutes = [];

  // Flatten all routes
  const allRoutes = Object.values(ROUTE_WORDLIST).flat();
  const totalRoutes = allRoutes.length;

  emit({ type: 'log', level: 'info', message: `[Route Scanner] Iniciando varredura de ${totalRoutes} rotas...` });

  // ─── Phase 1: Discover routes via sitemap/robots ──────────
  const robotsRes = await safeFetch(baseUrl + '/robots.txt', { timeout: 5000 });
  if (robotsRes.ok && robotsRes.text) {
    const disallowed = [];
    const sitemaps = [];
    for (const line of robotsRes.text.split('\n')) {
      const disMatch = line.match(/Disallow:\s*(.+)/i);
      if (disMatch) disallowed.push(disMatch[1].trim());
      const siteMatch = line.match(/Sitemap:\s*(.+)/i);
      if (siteMatch) sitemaps.push(siteMatch[1].trim());
    }
    
    if (disallowed.length > 0) {
      emit({ type: 'log', level: 'warn', message: `[Route Scanner] robots.txt encontrado com ${disallowed.length} caminho(s) Disallow` });
      
      // These disallowed paths are interesting — scan them
      for (const path of disallowed) {
        if (path && path !== '/' && !allRoutes.includes(path)) {
          allRoutes.push(path);
        }
      }

      results.push({
        check: 'Routes — robots.txt',
        status: 'INFO',
        severity: 'info',
        message: `robots.txt encontrado com ${disallowed.length} caminhos bloqueados.`,
        details: { disallowed, sitemaps }
      });
    }
  }

  // Sitemap
  const sitemapRes = await safeFetch(baseUrl + '/sitemap.xml', { timeout: 5000 });
  if (sitemapRes.ok && sitemapRes.text?.includes('<urlset')) {
    const urlMatches = sitemapRes.text.match(/<loc>([^<]+)<\/loc>/g) || [];
    const sitemapUrls = urlMatches.map(m => m.replace(/<\/?loc>/g, ''));
    
    if (sitemapUrls.length > 0) {
      results.push({
        check: 'Routes — Sitemap',
        status: 'INFO',
        severity: 'info',
        message: `sitemap.xml encontrado com ${sitemapUrls.length} URL(s).`,
        details: { urls: sitemapUrls.slice(0, 30) }
      });
    }
  }

  // ─── Phase 2: Brute-force route discovery ─────────────────
  // Get baseline 404 signature for comparison
  const baseline404 = await safeFetch(baseUrl + '/this-definitely-does-not-exist-xyzzy-12345', { timeout: 5000 });
  const baseline404Status = baseline404.status;
  const baseline404Length = baseline404.text?.length || 0;
  const baseline404Hash = simpleHash(baseline404.text || '');

  emit({ type: 'log', level: 'info', message: `[Route Scanner] Baseline 404: status=${baseline404Status}, length=${baseline404Length}` });

  // Process in batches of 10 for speed
  const BATCH = 10;
  let processed = 0;

  for (let i = 0; i < allRoutes.length; i += BATCH) {
    const batch = allRoutes.slice(i, i + BATCH);
    
    const batchResults = await Promise.all(batch.map(async (route) => {
      const url = baseUrl + route;
      const res = await safeFetch(url, { timeout: 6000 });
      return { route, url, res };
    }));

    for (const { route, url, res } of batchResults) {
      processed++;
      
      if (res.status === 0) continue; // Connection error, skip

      // Determine if this is a real page vs 404
      const isReal = isRealRoute(res, baseline404Status, baseline404Length, baseline404Hash);

      if (isReal) {
        const category = categorizeRoute(route);
        const riskLevel = assessRouteRisk(route, res);

        discoveredRoutes.push({
          path: route,
          status: res.status,
          size: res.text?.length || 0,
          contentType: res.headers?.['content-type'] || 'unknown',
          category,
          risk: riskLevel,
          redirectsTo: res.url !== url ? res.url : null,
          headers: {
            server: res.headers?.['server'],
            poweredBy: res.headers?.['x-powered-by'],
            auth: res.headers?.['www-authenticate'] ? true : false,
          }
        });

        if (riskLevel === 'critical' || riskLevel === 'high') {
          emit({ type: 'log', level: 'warn', message: `[Route Scanner] ENCONTRADO [${riskLevel.toUpperCase()}]: ${route} (${res.status})` });
        }
      }

      // Detect broken routes (non-standard error responses)
      if (res.status >= 500) {
        brokenRoutes.push({
          path: route,
          status: res.status,
          statusText: res.statusText,
          errorPreview: (res.text || '').substring(0, 200),
          hasStackTrace: (res.text || '').includes('at ') && (res.text || '').includes('.js:'),
          leaksInfo: (res.text || '').includes('Error:') || (res.text || '').includes('Exception')
        });
      }
    }

    // Progress update every 50 routes
    if (processed % 50 < BATCH) {
      emit({ type: 'log', level: 'info', message: `[Route Scanner] ${processed}/${allRoutes.length} rotas verificadas...` });
    }
  }

  emit({ type: 'log', level: 'info', message: `[Route Scanner] Varredura concluída: ${discoveredRoutes.length} rotas encontradas` });

  // ─── Phase 3: Compile results ─────────────────────────────

  // Discovered routes
  if (discoveredRoutes.length > 0) {
    const criticals = discoveredRoutes.filter(r => r.risk === 'critical');
    const highs = discoveredRoutes.filter(r => r.risk === 'high');
    const grouped = groupByCategory(discoveredRoutes);

    results.push({
      check: 'Routes — Hidden/Exposed Endpoints',
      status: criticals.length > 0 ? 'FAIL' : (highs.length > 0 ? 'WARN' : 'INFO'),
      severity: criticals.length > 0 ? 'critical' : (highs.length > 0 ? 'high' : 'medium'),
      message: `${discoveredRoutes.length} rota(s) descoberta(s). ${criticals.length} crítica(s), ${highs.length} alta(s).`,
      details: {
        total: discoveredRoutes.length,
        byCategory: grouped,
        criticalRoutes: criticals,
        highRoutes: highs,
        allRoutes: discoveredRoutes.slice(0, 60),
        recommendation: criticals.length > 0 
          ? 'URGENTE: Rotas críticas descobertas (admin, debug, config). Bloqueie ou proteja esses endpoints.'
          : 'Revise as rotas expostas e garanta que endpoints sensíveis estejam protegidos.'
      }
    });
  } else {
    results.push({
      check: 'Routes — Discovery',
      status: 'PASS',
      severity: 'info',
      message: `Nenhuma rota oculta/exposta encontrada entre ${allRoutes.length} caminhos testados.`,
      details: { pathsTested: allRoutes.length }
    });
  }

  // Broken routes
  if (brokenRoutes.length > 0) {
    const withStackTrace = brokenRoutes.filter(r => r.hasStackTrace);
    const withInfo = brokenRoutes.filter(r => r.leaksInfo);

    results.push({
      check: 'Routes — Broken/Error Routes',
      status: 'WARN',
      severity: withStackTrace.length > 0 ? 'high' : 'medium',
      message: `${brokenRoutes.length} rota(s) com erro (5xx). ${withStackTrace.length} expõem stack traces!`,
      details: {
        broken: brokenRoutes.slice(0, 20),
        withStackTrace: withStackTrace.length,
        leakingInfo: withInfo.length,
        recommendation: 'Configure error handling adequado para não expor detalhes internos em erros 5xx.'
      }
    });
  }

  // ─── Phase 4: Extract routes from JS source ───────────────
  const mainPage = await safeFetch(baseUrl, { timeout: 10000 });
  if (mainPage.ok && mainPage.text) {
    const jsRoutes = extractRoutesFromSource(mainPage.text);
    if (jsRoutes.length > 0) {
      results.push({
        check: 'Routes — Extracted from Source',
        status: 'INFO',
        severity: 'low',
        message: `${jsRoutes.length} rota(s) extraída(s) do código fonte da página.`,
        details: {
          routes: jsRoutes.slice(0, 40),
          recommendation: 'Verifique se todas as rotas extraídas do código fonte devem ser públicas.'
        }
      });
    }
  }

  return results;
}

function isRealRoute(res, baseline404Status, baseline404Length, baseline404Hash) {
  // Definitive 404
  if (res.status === 404) return false;
  
  // Successful responses
  if (res.status >= 200 && res.status < 300) {
    // But check if it's a soft 404 (same content as baseline)
    const resHash = simpleHash(res.text || '');
    if (resHash === baseline404Hash && res.text?.length === baseline404Length) return false;
    return true;
  }

  // Redirects are interesting
  if (res.status >= 300 && res.status < 400) return true;

  // Auth required = route exists
  if (res.status === 401 || res.status === 403) return true;

  // Server errors = route exists but broken
  if (res.status >= 500) return true;

  // Method not allowed = route exists
  if (res.status === 405) return true;

  return false;
}

function categorizeRoute(route) {
  for (const [category, routes] of Object.entries(ROUTE_WORDLIST)) {
    if (routes.includes(route)) return category;
  }
  return 'other';
}

function assessRouteRisk(route, res) {
  const path = route.toLowerCase();
  
  // Critical: admin, debug, config files, git, backups
  if (path.match(/\/(admin|root|superadmin|backoffice|debug|actuator|phpinfo|server-status)/)) {
    return res.status >= 200 && res.status < 300 ? 'critical' : 'high';
  }
  if (path.match(/\/(\.git|\.svn|\.hg|\.env|\.htpasswd)/)) {
    return res.status >= 200 && res.status < 300 ? 'critical' : 'high';
  }
  if (path.match(/\.(sql|bak|backup|dump|sqlite|db)$/)) {
    return res.status >= 200 && res.status < 300 ? 'critical' : 'medium';
  }
  if (path.match(/\/(wp-config|web\.config|nginx\.conf|httpd\.conf|docker-compose|Dockerfile)/)) {
    return res.status >= 200 && res.status < 300 ? 'critical' : 'high';
  }

  // High: API endpoints, auth, internal
  if (path.match(/\/(api\/(?:admin|internal|private|secret|keys|tokens|debug|config|env))/)) {
    return 'high';
  }
  if (path.includes('swagger') || path.includes('graphiql') || path.includes('playground')) {
    return res.status >= 200 && res.status < 300 ? 'high' : 'medium';
  }

  // Medium: Standard API, auth, known tools
  if (path.match(/\/(api|auth|login|graphql|webhook)/)) return 'medium';
  if (path.match(/\/(package\.json|composer\.json|tsconfig)/)) {
    return res.status >= 200 && res.status < 300 ? 'medium' : 'low';
  }

  // Low: Static, known safe
  if (path.match(/\/(robots\.txt|sitemap|manifest|favicon)/)) return 'low';

  return 'low';
}

function extractRoutesFromSource(html) {
  const routes = new Set();
  
  // Look for route patterns in JS/HTML
  const patterns = [
    /["']\/(?:api|auth|admin|dashboard|settings|profile|users?|posts?|products?|orders?|cart|checkout|search|contact|about|blog|docs|help|terms|privacy|FAQ)[\/\w-]*["']/gi,
    /path:\s*["'](\/[^"'{}\n]+)["']/g,
    /route:\s*["'](\/[^"'{}\n]+)["']/g,
    /href=["'](\/[^"']+)["']/gi,
    /to=["'](\/[^"']+)["']/gi,
    /navigate\s*\(\s*["'](\/[^"']+)["']/gi,
    /router\.(?:get|post|put|delete|patch)\s*\(\s*["'](\/[^"']+)["']/gi,
    /fetch\s*\(\s*["'](\/[^"']+)["']/gi,
    /axios\.(?:get|post|put|delete)\s*\(\s*["'](\/[^"']+)["']/gi,
  ];

  for (const pat of patterns) {
    let m;
    while ((m = pat.exec(html)) !== null) {
      const route = (m[1] || m[0]).replace(/["']/g, '');
      if (route.startsWith('/') && route.length > 1 && route.length < 100) {
        routes.add(route);
      }
    }
  }

  return [...routes];
}

function groupByCategory(routes) {
  const groups = {};
  for (const r of routes) {
    if (!groups[r.category]) groups[r.category] = [];
    groups[r.category].push({ path: r.path, status: r.status, risk: r.risk });
  }
  return groups;
}

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const chr = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return hash;
}

module.exports = { deepRouteDiscovery };
