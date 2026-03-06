/*  ═══════════════════════════════════════════════════════════════════
    STACK DETECTOR — Detects technologies used by the target site
    Analyzes HTML, headers, JS, and meta tags to fingerprint the stack
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

const TECH_SIGNATURES = {
  // Frameworks
  'React':        { html: [/react/i, /data-reactroot/i, /__NEXT_DATA__/], headers: [], js: [/react\.production/i, /react-dom/i] },
  'Next.js':      { html: [/__NEXT_DATA__/, /_next\/static/i, /next\/router/i], headers: ['x-nextjs-cache', 'x-vercel-id'], js: [] },
  'Vue.js':       { html: [/vue\.js/i, /data-v-[a-f0-9]/i, /__vue__/i], headers: [], js: [/vue\.runtime/i, /vue\.global/i] },
  'Nuxt.js':      { html: [/__NUXT__/, /_nuxt\//i], headers: [], js: [] },
  'Angular':      { html: [/ng-version/i, /ng-app/i, /angular\.js/i, /zone\.js/i], headers: [], js: [] },
  'Svelte':       { html: [/svelte/i, /__svelte/i], headers: [], js: [/svelte\/internal/i] },
  'SvelteKit':    { html: [/__sveltekit/i, /_app\/immutable/i], headers: [], js: [] },
  'Remix':        { html: [/remix/i, /__remixContext/i], headers: [], js: [] },
  'Astro':        { html: [/astro-island/i, /is:visible/i], headers: [], js: [] },
  'Gatsby':       { html: [/gatsby/i, /___gatsby/i], headers: [], js: [] },
  'jQuery':       { html: [/jquery[.\-]?\d/i, /jquery\.min\.js/i], headers: [], js: [/jQuery/] },
  'Ember.js':     { html: [/ember\.js/i, /data-ember/i], headers: [], js: [] },

  // CSS Frameworks
  'Tailwind CSS': { html: [/tailwindcss/i, /class="[^"]*\b(?:flex|grid|bg-|text-|p-|m-)\b/], headers: [], js: [] },
  'Bootstrap':    { html: [/bootstrap\.min/i, /class="[^"]*\bcontainer\b[^"]*\brow\b/], headers: [], js: [] },
  'Material UI':  { html: [/mui/i, /MuiThemeProvider/i], headers: [], js: [] },
  'Chakra UI':    { html: [/chakra/i], headers: [], js: [] },

  // Hosting/Platforms
  'Vercel':       { html: [], headers: ['x-vercel-id', 'x-vercel-cache'], js: [] },
  'Netlify':      { html: [], headers: ['x-nf-request-id', 'netlify'], js: [] },
  'Cloudflare':   { html: [], headers: ['cf-ray', 'cf-cache-status'], js: [/cloudflare/i] },
  'AWS':          { html: [], headers: ['x-amz-request-id', 'x-amzn-requestid'], js: [] },
  'Google Cloud':  { html: [], headers: ['x-cloud-trace-context'], js: [] },
  'Firebase':     { html: [/firebase/i, /firebaseapp/i], headers: [], js: [/firebase/i] },
  'Heroku':       { html: [], headers: ['via: 1.1 vegur'], js: [] },
  'Railway':      { html: [], headers: ['x-railway'], js: [] },

  // Backend/APIs
  'Supabase':     { html: [/supabase/i], headers: ['x-sb-', 'x-supabase'], js: [/supabase/i, /@supabase\/supabase-js/i] },
  'PostgREST':    { html: [], headers: ['content-profile'], js: [] },
  'Node.js':      { html: [], headers: ['x-powered-by: Express'], js: [] },
  'Express':      { html: [], headers: ['x-powered-by: Express'], js: [] },
  'Nginx':        { html: [], headers: ['server: nginx'], js: [] },
  'Apache':       { html: [], headers: ['server: apache'], js: [] },
  'WordPress':    { html: [/wp-content/i, /wp-includes/i, /wordpress/i], headers: [], js: [] },
  'Stripe':       { html: [/stripe\.js/i, /js\.stripe\.com/i], headers: [], js: [/stripe/i] },
  'reCAPTCHA':    { html: [/recaptcha/i, /google\.com\/recaptcha/i], headers: [], js: [] },
  'hCaptcha':     { html: [/hcaptcha/i], headers: [], js: [] },

  // Analytics/Tracking
  'Google Analytics':   { html: [/google-analytics\.com/i, /googletagmanager/i, /gtag/i], headers: [], js: [] },
  'Hotjar':             { html: [/hotjar/i, /static\.hotjar\.com/i], headers: [], js: [] },
  'Sentry':             { html: [/sentry\.io/i, /browser\.sentry/i], headers: [], js: [/sentry/i] },
  'Segment':            { html: [/segment\.com/i, /analytics\.js/i], headers: [], js: [] },
  'Mixpanel':           { html: [/mixpanel/i], headers: [], js: [] },
  'Intercom':           { html: [/intercom/i, /widget\.intercom/i], headers: [], js: [] },

  // Auth
  'Auth0':         { html: [/auth0/i], headers: [], js: [/auth0/i] },
  'Clerk':         { html: [/clerk/i, /__clerk/i], headers: [], js: [] },
  'NextAuth':      { html: [/next-auth/i, /api\/auth/i], headers: [], js: [] },

  // Databases (client-side evidence)
  'MongoDB':       { html: [/mongodb/i], headers: [], js: [/mongodb/i] },
  'Prisma':        { html: [], headers: [], js: [/prisma/i] },

  // Build tools
  'Webpack':       { html: [/webpack/i, /webpackJsonp/i], headers: [], js: [] },
  'Vite':          { html: [/@vite/i, /vite\.config/i], headers: [], js: [] },
  'Turbopack':     { html: [/turbopack/i], headers: [], js: [] },
  'Parcel':        { html: [/parcel/i], headers: [], js: [] },
};

async function detectStack(config, emit) {
  const results = [];
  const detected = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  emit({ type: 'log', level: 'info', message: '[Stack] Detectando tecnologias...' });

  // Fetch main page
  const mainPage = await safeFetch(baseUrl, { timeout: 15000 });
  if (!mainPage.ok) {
    return [{
      check: 'Stack Detection',
      status: 'ERROR',
      severity: 'info',
      message: 'Não foi possível acessar a página principal para detecção de stack.',
      details: null
    }];
  }

  const html = mainPage.text || '';
  const respHeaders = mainPage.headers || {};
  const headerString = Object.entries(respHeaders).map(([k,v]) => `${k}: ${v}`).join('\n').toLowerCase();

  // Fetch JS bundles
  let jsContent = '';
  const scriptUrls = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["']/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    let src = match[1];
    if (src.startsWith('//')) src = 'https:' + src;
    else if (src.startsWith('/')) src = baseUrl + src;
    else if (!src.startsWith('http')) src = baseUrl + '/' + src;
    scriptUrls.push(src);
  }

  // Fetch first 10 JS files
  const jsFetches = scriptUrls.slice(0, 10).map(url =>
    safeFetch(url, { timeout: 8000 }).then(r => r.ok ? r.text : '')
  );
  const jsResults = await Promise.all(jsFetches);
  jsContent = jsResults.join('\n');

  // Check each technology
  for (const [tech, sigs] of Object.entries(TECH_SIGNATURES)) {
    let found = false;
    let evidence = [];

    // Check HTML
    for (const pattern of sigs.html) {
      if (pattern.test(html)) {
        found = true;
        evidence.push(`HTML match: ${pattern.source.substring(0, 40)}`);
        break;
      }
    }

    // Check headers
    for (const headerSig of sigs.headers) {
      if (headerString.includes(headerSig.toLowerCase())) {
        found = true;
        evidence.push(`Header: ${headerSig}`);
        break;
      }
    }

    // Check JS
    if (!found) {
      for (const pattern of sigs.js) {
        if (pattern.test(jsContent)) {
          found = true;
          evidence.push(`JS match: ${pattern.source.substring(0, 40)}`);
          break;
        }
      }
    }

    if (found) {
      detected.push({ name: tech, evidence });
      emit({ type: 'log', level: 'info', message: `[Stack] ✓ Detectado: ${tech}` });
    }
  }

  // Additional: Check meta generator
  const generatorMatch = html.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
  if (generatorMatch) {
    detected.push({ name: `Generator: ${generatorMatch[1]}`, evidence: ['meta generator tag'] });
  }

  // Additional: Check HTTP2/HTTPS
  const protocol = baseUrl.startsWith('https') ? 'HTTPS' : 'HTTP';
  detected.push({ name: protocol, evidence: ['URL protocol'] });

  // Categorize
  const categories = {
    'Frontend Framework': [],
    'CSS Framework': [],
    'Meta Framework': [],
    'Hosting': [],
    'Backend': [],
    'Analytics': [],
    'Auth Provider': [],
    'Build Tool': [],
    'Other': [],
  };

  const categoryMap = {
    'React': 'Frontend Framework', 'Vue.js': 'Frontend Framework', 'Angular': 'Frontend Framework',
    'Svelte': 'Frontend Framework', 'jQuery': 'Frontend Framework', 'Ember.js': 'Frontend Framework',
    'Next.js': 'Meta Framework', 'Nuxt.js': 'Meta Framework', 'SvelteKit': 'Meta Framework',
    'Remix': 'Meta Framework', 'Astro': 'Meta Framework', 'Gatsby': 'Meta Framework',
    'Tailwind CSS': 'CSS Framework', 'Bootstrap': 'CSS Framework', 'Material UI': 'CSS Framework', 'Chakra UI': 'CSS Framework',
    'Vercel': 'Hosting', 'Netlify': 'Hosting', 'Cloudflare': 'Hosting', 'AWS': 'Hosting',
    'Google Cloud': 'Hosting', 'Heroku': 'Hosting', 'Railway': 'Hosting',
    'Supabase': 'Backend', 'PostgREST': 'Backend', 'Node.js': 'Backend', 'Express': 'Backend',
    'Nginx': 'Backend', 'Apache': 'Backend', 'WordPress': 'Backend', 'Firebase': 'Backend', 'Stripe': 'Backend',
    'Google Analytics': 'Analytics', 'Hotjar': 'Analytics', 'Sentry': 'Analytics',
    'Segment': 'Analytics', 'Mixpanel': 'Analytics', 'Intercom': 'Analytics',
    'Auth0': 'Auth Provider', 'Clerk': 'Auth Provider', 'NextAuth': 'Auth Provider',
    'Webpack': 'Build Tool', 'Vite': 'Build Tool', 'Turbopack': 'Build Tool', 'Parcel': 'Build Tool',
  };

  for (const d of detected) {
    const cat = categoryMap[d.name] || 'Other';
    if (categories[cat]) categories[cat].push(d.name);
    else categories['Other'].push(d.name);
  }

  // Clean empty categories
  const activeCategories = {};
  for (const [k, v] of Object.entries(categories)) {
    if (v.length > 0) activeCategories[k] = v;
  }

  results.push({
    check: 'Stack Detection',
    status: detected.length > 0 ? 'INFO' : 'WARN',
    severity: 'info',
    message: `${detected.length} tecnologia(s) detectada(s): ${detected.map(d => d.name).join(', ')}`,
    details: {
      technologies: detected,
      categories: activeCategories,
      totalDetected: detected.length,
      scriptsAnalyzed: scriptUrls.length,
    }
  });

  return results;
}

module.exports = { detectStack };
