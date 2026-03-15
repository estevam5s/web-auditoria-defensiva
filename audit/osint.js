/*  ═══════════════════════════════════════════════════════════════════
    OSINT / INTERNET FOOTPRINT MODULE
    Varredura de presença do site na internet:
      ✓ DNS records (A, MX, NS, TXT, CNAME)
      ✓ Certificate Transparency (crt.sh)
      ✓ Wayback Machine (archive.org)
      ✓ GitHub mentions (API pública)
      ✓ HackerNews mentions (Algolia API)
      ✓ Reddit mentions (API pública)
      ✓ DuckDuckGo (HTML scraping)
      ✓ Social media URL probing
      ✓ Google Dorks gerados automaticamente
      ✓ Shodan DNS resolve (sem key)
      ✓ Related domains via crt.sh
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');
const dns   = require('dns').promises;

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

async function safeFetch(url, opts = {}) {
  try {
    const { headers: extraHeaders, timeout: customTimeout, ...restOpts } = opts;
    const res = await fetch(url, {
      timeout: customTimeout || 12000,
      headers: { 'User-Agent': UA, 'Accept': 'application/json,text/html,*/*', ...extraHeaders },
      ...restOpts,
    });
    return res;
  } catch {
    return null;
  }
}

async function safeJSON(url, opts = {}) {
  const res = await safeFetch(url, opts);
  if (!res?.ok) return null;
  try { return await res.json(); } catch { return null; }
}

async function safeText(url, opts = {}) {
  const res = await safeFetch(url, opts);
  if (!res?.ok) return null;
  try { return await res.text(); } catch { return null; }
}

// ── 1. DNS Records ────────────────────────────────────────────────
async function getDNS(domain) {
  const result = { a: [], aaaa: [], mx: [], ns: [], txt: [], cname: [] };
  await Promise.allSettled([
    dns.resolve4(domain).then(r  => { result.a    = r; }).catch(() => {}),
    dns.resolve6(domain).then(r  => { result.aaaa = r; }).catch(() => {}),
    dns.resolveMx(domain).then(r => { result.mx   = r.map(m => `${m.priority} ${m.exchange}`); }).catch(() => {}),
    dns.resolveNs(domain).then(r => { result.ns   = r; }).catch(() => {}),
    dns.resolveTxt(domain).then(r => { result.txt  = r.flat().slice(0, 10); }).catch(() => {}),
    dns.resolveCname(domain).then(r => { result.cname = r; }).catch(() => {}),
  ]);
  return result;
}

// ── 2. Certificate Transparency (crt.sh) ──────────────────────────
async function getCerts(domain) {
  const data = await safeJSON(`https://crt.sh/?q=%25.${domain}&output=json`);
  if (!data || !Array.isArray(data)) return { total: 0, certs: [], subdomains: [] };

  const uniqueCerts = new Map();
  const subdomains  = new Set();

  for (const c of data) {
    const name = c.name_value || '';
    name.split('\n').forEach(n => {
      const clean = n.trim().replace('*.', '');
      if (clean && clean.includes('.')) subdomains.add(clean);
    });

    const key = `${c.issuer_ca_id}:${c.not_before}`;
    if (!uniqueCerts.has(key)) {
      uniqueCerts.set(key, {
        commonName:   (c.common_name || '').slice(0, 80),
        issuer:       (c.issuer_name || '').replace(/^.*CN=/, '').slice(0, 60),
        notBefore:    c.not_before,
        notAfter:     c.not_after,
        names:        name.split('\n').map(n => n.trim()).filter(Boolean),
      });
    }
  }

  return {
    total:      uniqueCerts.size,
    certs:      [...uniqueCerts.values()].slice(0, 15),
    subdomains: [...subdomains]
      .filter(s => s !== domain && s.endsWith(domain))
      .slice(0, 30),
  };
}

// ── 3. Wayback Machine ─────────────────────────────────────────────
async function getWayback(domain) {
  const avail = await safeJSON(`https://archive.org/wayback/available?url=${domain}`);
  const cdx   = await safeJSON(
    `http://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&limit=5&fl=timestamp,original,statuscode&filter=statuscode:200&collapse=urlkey&fastLatest=true`
  );

  const snaps = [];
  if (Array.isArray(cdx) && cdx.length > 1) {
    for (const row of cdx.slice(1, 6)) {
      snaps.push({
        timestamp: row[0],
        url:       row[1],
        status:    row[2],
        archiveUrl: `https://web.archive.org/web/${row[0]}/${row[1]}`,
      });
    }
  }

  const closest = avail?.archived_snapshots?.closest;
  return {
    available:  !!closest?.available,
    snapshotUrl: closest?.url || null,
    timestamp:  closest?.timestamp || null,
    recentSnaps: snaps,
  };
}

// ── 4. GitHub mentions ─────────────────────────────────────────────
async function getGitHub(domain) {
  const data = await safeJSON(
    `https://api.github.com/search/code?q=${encodeURIComponent(`"${domain}"`)}&per_page=8&sort=indexed`,
    { headers: { 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'supabase-guard-osint' } }
  );

  if (!data?.items) return { total: 0, items: [] };
  return {
    total: data.total_count || 0,
    items: data.items.slice(0, 8).map(i => ({
      name:       i.name,
      path:       i.path,
      repo:       i.repository?.full_name,
      repoUrl:    i.repository?.html_url,
      fileUrl:    i.html_url,
      language:   i.repository?.language,
      stars:      i.repository?.stargazers_count,
    })),
  };
}

// ── 5. HackerNews mentions ─────────────────────────────────────────
async function getHackerNews(domain) {
  const data = await safeJSON(
    `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(domain)}&hitsPerPage=8&tags=story`
  );
  if (!data?.hits) return { total: 0, items: [] };
  return {
    total: data.nbHits || 0,
    items: data.hits.slice(0, 8).map(h => ({
      title:     h.title,
      url:       h.url,
      hnUrl:     `https://news.ycombinator.com/item?id=${h.objectID}`,
      points:    h.points,
      comments:  h.num_comments,
      author:    h.author,
      date:      h.created_at,
    })),
  };
}

// ── 6. Reddit mentions ─────────────────────────────────────────────
async function getReddit(domain) {
  const data = await safeJSON(
    `https://www.reddit.com/search.json?q=${encodeURIComponent(`site:${domain} OR "${domain}"`)}&sort=relevance&limit=8`,
    { headers: { 'User-Agent': 'supabase-guard-osint/1.0' } }
  );
  if (!data?.data?.children) return { total: 0, items: [] };
  return {
    total: data.data.dist || 0,
    items: data.data.children.slice(0, 8).map(c => ({
      title:     c.data.title,
      subreddit: c.data.subreddit,
      url:       `https://reddit.com${c.data.permalink}`,
      score:     c.data.score,
      comments:  c.data.num_comments,
      author:    c.data.author,
      date:      new Date(c.data.created_utc * 1000).toISOString(),
    })),
  };
}

// ── 7. DuckDuckGo HTML scraping ────────────────────────────────────
async function getDuckDuckGo(domain) {
  const queries = [
    `"${domain}"`,
    `site:twitter.com OR site:x.com "${domain}"`,
    `site:linkedin.com "${domain}"`,
    `site:facebook.com "${domain}"`,
  ];

  const allResults = [];
  for (const q of queries.slice(0, 2)) {   // limit to avoid being blocked
    const html = await safeText(
      `https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`,
      { headers: { 'User-Agent': UA, 'Accept-Language': 'pt-BR,pt;q=0.9' } }
    );
    if (!html) continue;

    // Parse result links from DDG HTML
    const linkRe   = /class="result__a"[^>]*href="([^"]+)"/g;
    const titleRe  = /class="result__a"[^>]*>([^<]+)<\/a>/g;
    const snippetRe = /class="result__snippet"[^>]*>([^<]+)</g;

    let lm, tm, sm;
    const links = [], titles = [], snippets = [];
    while ((lm = linkRe.exec(html))   !== null) links.push(lm[1]);
    while ((tm = titleRe.exec(html))  !== null) titles.push(tm[1].trim());
    while ((sm = snippetRe.exec(html)) !== null) snippets.push(sm[1].trim());

    for (let i = 0; i < Math.min(links.length, 5); i++) {
      const url = links[i];
      if (url && url.startsWith('http') && !url.includes('duckduckgo.com')) {
        allResults.push({
          url,
          title:   titles[i] || url,
          snippet: snippets[i] || '',
          query:   q,
        });
      }
    }
  }

  return { total: allResults.length, results: allResults };
}

// ── 8. Social Media URL probing ────────────────────────────────────
async function probeSocial(domain) {
  // Extract a likely handle from the domain (e.g. "myapp.com" → "myapp")
  const handle = domain.split('.')[0].toLowerCase().replace(/[^a-z0-9-]/g, '');

  const platforms = [
    { name: 'Twitter / X',  url: `https://twitter.com/${handle}`,                  icon: '🐦' },
    { name: 'Instagram',    url: `https://instagram.com/${handle}`,                 icon: '📸' },
    { name: 'LinkedIn',     url: `https://linkedin.com/company/${handle}`,          icon: '💼' },
    { name: 'Facebook',     url: `https://facebook.com/${handle}`,                  icon: '📘' },
    { name: 'GitHub',       url: `https://github.com/${handle}`,                    icon: '🐙' },
    { name: 'YouTube',      url: `https://youtube.com/@${handle}`,                  icon: '▶️' },
    { name: 'TikTok',       url: `https://tiktok.com/@${handle}`,                   icon: '🎵' },
    { name: 'Pinterest',    url: `https://pinterest.com/${handle}`,                 icon: '📌' },
    { name: 'Product Hunt', url: `https://producthunt.com/products/${handle}`,      icon: '🚀' },
    { name: 'Dev.to',       url: `https://dev.to/${handle}`,                        icon: '👾' },
    { name: 'Medium',       url: `https://medium.com/@${handle}`,                   icon: '✍️' },
    { name: 'npm',          url: `https://npmjs.com/~${handle}`,                    icon: '📦' },
  ];

  const results = await Promise.allSettled(
    platforms.map(async p => {
      const res = await safeFetch(p.url, { redirect: 'follow', timeout: 6000 });
      // A 200 or a redirect that ends in a valid page suggests presence
      const found = res && (res.status === 200 || (res.status >= 301 && res.status <= 302));
      return { ...p, found: !!found, status: res?.status || 0 };
    })
  );

  return results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value)
    .filter(r => r.status !== 404 && r.status !== 0);
}

// ── 9. Google Dorks ────────────────────────────────────────────────
function buildDorks(domain) {
  const enc = encodeURIComponent;
  const goog = q => `https://www.google.com/search?q=${enc(q)}`;
  const bing  = q => `https://www.bing.com/search?q=${enc(q)}`;
  const ddg   = q => `https://duckduckgo.com/?q=${enc(q)}`;

  const dorks = [
    // Presença em redes sociais
    { category: '📱 Redes Sociais', name: 'Twitter / X',    query: `site:twitter.com "${domain}"`,    google: goog(`site:twitter.com "${domain}"`),    bing: bing(`site:twitter.com "${domain}"`) },
    { category: '📱 Redes Sociais', name: 'LinkedIn',        query: `site:linkedin.com "${domain}"`,   google: goog(`site:linkedin.com "${domain}"`),   bing: bing(`site:linkedin.com "${domain}"`) },
    { category: '📱 Redes Sociais', name: 'Facebook',        query: `site:facebook.com "${domain}"`,   google: goog(`site:facebook.com "${domain}"`),   bing: bing(`site:facebook.com "${domain}"`) },
    { category: '📱 Redes Sociais', name: 'Instagram',       query: `site:instagram.com "${domain}"`,  google: goog(`site:instagram.com "${domain}"`),  bing: bing(`site:instagram.com "${domain}"`) },
    { category: '📱 Redes Sociais', name: 'Reddit',          query: `site:reddit.com "${domain}"`,     google: goog(`site:reddit.com "${domain}"`),     bing: bing(`site:reddit.com "${domain}"`) },
    { category: '📱 Redes Sociais', name: 'YouTube',         query: `site:youtube.com "${domain}"`,    google: goog(`site:youtube.com "${domain}"`),    bing: bing(`site:youtube.com "${domain}"`) },
    { category: '📱 Redes Sociais', name: 'TikTok',          query: `site:tiktok.com "${domain}"`,     google: goog(`site:tiktok.com "${domain}"`),     bing: bing(`site:tiktok.com "${domain}"`) },

    // Menções técnicas
    { category: '💻 Técnico',       name: 'GitHub',          query: `site:github.com "${domain}"`,     google: goog(`site:github.com "${domain}"`),     bing: bing(`site:github.com "${domain}"`) },
    { category: '💻 Técnico',       name: 'StackOverflow',   query: `site:stackoverflow.com "${domain}"`, google: goog(`site:stackoverflow.com "${domain}"`), bing: bing(`site:stackoverflow.com "${domain}"`) },
    { category: '💻 Técnico',       name: 'Dev.to',          query: `site:dev.to "${domain}"`,         google: goog(`site:dev.to "${domain}"`),         bing: bing(`site:dev.to "${domain}"`) },
    { category: '💻 Técnico',       name: 'Medium',          query: `site:medium.com "${domain}"`,     google: goog(`site:medium.com "${domain}"`),     bing: bing(`site:medium.com "${domain}"`) },
    { category: '💻 Técnico',       name: 'npm',             query: `site:npmjs.com "${domain}"`,      google: goog(`site:npmjs.com "${domain}"`),      bing: bing(`site:npmjs.com "${domain}"`) },

    // Segurança / OSINT
    { category: '🔐 Segurança',     name: 'Credenciais vazadas', query: `"${domain}" password OR "api_key" OR secret OR token`, google: goog(`"${domain}" password OR "api_key" OR secret OR token`), bing: bing(`"${domain}" password OR "api_key" OR secret`) },
    { category: '🔐 Segurança',     name: 'Arquivos expostos',   query: `site:${domain} filetype:env OR filetype:log OR filetype:sql`, google: goog(`site:${domain} filetype:env OR filetype:log OR filetype:sql`), bing: bing(`site:${domain} filetype:env OR filetype:sql`) },
    { category: '🔐 Segurança',     name: 'Emails do domínio',   query: `"@${domain}"`,                google: goog(`"@${domain}"`),                    bing: bing(`"@${domain}"`) },
    { category: '🔐 Segurança',     name: 'Login pages',         query: `site:${domain} inurl:login OR inurl:admin OR inurl:dashboard`, google: goog(`site:${domain} inurl:login OR inurl:admin`), bing: bing(`site:${domain} inurl:login OR inurl:admin`) },
    { category: '🔐 Segurança',     name: 'PDFs e documentos',   query: `"${domain}" filetype:pdf OR filetype:xls OR filetype:csv`, google: goog(`"${domain}" filetype:pdf OR filetype:xls`), bing: bing(`"${domain}" filetype:pdf OR filetype:xls`) },

    // Menções externas
    { category: '🌐 Menções',       name: 'Sites que linkam',    query: `"${domain}" -site:${domain}`, google: goog(`"${domain}" -site:${domain}`),      bing: bing(`"${domain}" -site:${domain}`) },
    { category: '🌐 Menções',       name: 'Fóruns e comunidades', query: `"${domain}" fórum OR forum OR community OR comunidade`, google: goog(`"${domain}" forum OR community`), bing: bing(`"${domain}" forum OR community`) },
    { category: '🌐 Menções',       name: 'Cache do Google',     query: `cache:${domain}`,             google: goog(`cache:${domain}`),                 bing: bing(`cache:${domain}`) },
    { category: '🌐 Menções',       name: 'Sites relacionados',  query: `related:${domain}`,           google: goog(`related:${domain}`),               bing: bing(`related:${domain}`) },
    { category: '🌐 Menções',       name: 'Produto Hunt',        query: `site:producthunt.com "${domain}"`, google: goog(`site:producthunt.com "${domain}"`), bing: bing(`site:producthunt.com "${domain}"`) },

    // DuckDuckGo
    { category: '🦆 DuckDuckGo',    name: 'Menções gerais',      query: `"${domain}"`,                 ddg: ddg(`"${domain}"`),                         google: goog(`"${domain}"`) },
    { category: '🦆 DuckDuckGo',    name: 'Redes sociais',       query: `"${domain}" site:twitter.com OR site:linkedin.com OR site:reddit.com`, ddg: ddg(`"${domain}" site:twitter.com OR site:linkedin.com`), google: goog(`"${domain}" (site:twitter.com OR site:linkedin.com)`) },
  ];

  return dorks;
}

// ── 10. Shodan DNS (no key) ───────────────────────────────────────
async function getShodan(domain) {
  const data = await safeJSON(`https://api.shodan.io/dns/resolve?hostnames=${domain}`);
  if (!data) return null;
  return data[domain] || null;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN OSINT RUNNER — streams progress via onEvent callback
// ═══════════════════════════════════════════════════════════════════
async function runOSINT(targetUrl, onEvent) {
  let domain;
  try {
    domain = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`).hostname;
  } catch {
    onEvent({ type: 'error', message: 'URL inválida' });
    return;
  }

  // Remove www prefix for cleaner lookups
  const rootDomain = domain.replace(/^www\./, '');

  onEvent({ type: 'start', domain, rootDomain });

  const results = {
    domain:    rootDomain,
    timestamp: new Date().toISOString(),
    dns:       null,
    certs:     null,
    wayback:   null,
    github:    null,
    hackernews: null,
    reddit:    null,
    duckduckgo: null,
    social:    null,
    dorks:     buildDorks(rootDomain),
    shodan:    null,
  };

  const steps = [
    {
      key: 'dns',
      label: 'Resolvendo registros DNS',
      fn: () => getDNS(rootDomain),
    },
    {
      key: 'certs',
      label: 'Buscando certificados SSL (crt.sh)',
      fn: () => getCerts(rootDomain),
    },
    {
      key: 'wayback',
      label: 'Verificando Wayback Machine (archive.org)',
      fn: () => getWayback(rootDomain),
    },
    {
      key: 'github',
      label: 'Buscando menções no GitHub',
      fn: () => getGitHub(rootDomain),
    },
    {
      key: 'hackernews',
      label: 'Buscando menções no HackerNews',
      fn: () => getHackerNews(rootDomain),
    },
    {
      key: 'reddit',
      label: 'Buscando menções no Reddit',
      fn: () => getReddit(rootDomain),
    },
    {
      key: 'duckduckgo',
      label: 'Varredura DuckDuckGo',
      fn: () => getDuckDuckGo(rootDomain),
    },
    {
      key: 'social',
      label: 'Sondando perfis em redes sociais',
      fn: () => probeSocial(rootDomain),
    },
    {
      key: 'shodan',
      label: 'Consultando Shodan DNS',
      fn: () => getShodan(rootDomain),
    },
  ];

  let done = 0;
  for (const step of steps) {
    onEvent({ type: 'progress', step: step.key, label: step.label, done, total: steps.length });
    try {
      results[step.key] = await step.fn();
    } catch {
      results[step.key] = null;
    }
    done++;
    onEvent({ type: 'step_done', step: step.key, result: results[step.key], done, total: steps.length });
  }

  results.dorks = buildDorks(rootDomain);

  onEvent({ type: 'complete', results });
}

module.exports = { runOSINT, buildDorks };
