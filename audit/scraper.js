/*  ═══════════════════════════════════════════════════════════════════
    SITE SCRAPER — Downloads target site source code as ZIP
    Recursive crawler: HTML pages + CSS + JS + images + fonts
    Uses node-fetch v2 + archiver — no ESM dependencies
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');
const archiver = require('archiver');

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/**
 * Robust recursive site downloader.
 * Crawls same-domain pages (depth 2), downloads all CSS/JS/images/fonts.
 */
async function lightScrape(targetUrl, outputStream, onProgress) {
  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.pipe(outputStream);

  let base;
  try {
    base = new URL(targetUrl);
  } catch {
    throw new Error(`URL inválida: ${targetUrl}`);
  }

  const baseOrigin = base.origin;
  const baseHostname = base.hostname;
  const visitedPages = new Set();
  const assetsMap = new Map(); // resolvedUrl -> zipPath

  const FETCH_HEADERS = {
    'User-Agent': DEFAULT_UA,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8',
    'Accept-Encoding': 'identity',
  };

  async function fetchSafe(url, extraOpts = {}) {
    try {
      return await fetch(url, {
        headers: FETCH_HEADERS,
        timeout: 12000,
        redirect: 'follow',
        ...extraOpts,
      });
    } catch {
      return null;
    }
  }

  function resolveUrl(src, fromUrl) {
    if (!src || src.startsWith('data:') || src.startsWith('javascript:') || src.startsWith('mailto:')) return null;
    try {
      return new URL(src.trim().split(/[?#]/)[0], fromUrl).href;
    } catch {
      return null;
    }
  }

  function urlToZipPath(url, prefix = 'pages') {
    try {
      const u = new URL(url);
      let p = u.pathname.replace(/^\//, '') || 'index.html';
      if (p.endsWith('/')) p += 'index.html';
      if (!p.match(/\.[a-zA-Z0-9]{1,6}$/)) p += '/index.html';
      return `${prefix}/${p.replace(/[<>:"|?*\\]/g, '_')}`;
    } catch {
      return `${prefix}/page_${Math.random().toString(36).slice(2)}.html`;
    }
  }

  function assetZipPath(resolvedUrl) {
    try {
      const url = new URL(resolvedUrl);
      const filename = (url.pathname.split('/').pop() || `asset_${assetsMap.size}`).substring(0, 120);
      const ext = filename.split('.').pop().toLowerCase();
      const dir = ext === 'css' ? 'css'
        : ['js', 'mjs', 'jsx', 'ts', 'tsx'].includes(ext) ? 'js'
        : ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'ico', 'bmp', 'avif'].includes(ext) ? 'images'
        : ['woff', 'woff2', 'ttf', 'eot', 'otf'].includes(ext) ? 'fonts'
        : ['mp4', 'webm', 'ogg', 'mp3'].includes(ext) ? 'media'
        : 'assets';
      return `${dir}/${filename}`;
    } catch {
      return `assets/asset_${assetsMap.size}`;
    }
  }

  const ASSET_PATTERNS = [
    /<link[^>]+rel=["'][^"']*stylesheet[^"']*["'][^>]+href=["']([^"'>]+)["']/gi,
    /<link[^>]+href=["']([^"'>]+\.css[^"'>]*)["']/gi,
    /<script[^>]+src=["']([^"'>]+)["']/gi,
    /<img[^>]+src=["']([^"'>]+)["']/gi,
    /<source[^>]+src=["']([^"'>]+)["']/gi,
    /<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"'>]+)["']/gi,
    /url\(["']?([^"')]+\.(woff2?|ttf|eot|otf|svg|png|jpg|jpeg|gif|webp|ico))["']?\)/gi,
  ];

  function collectAssets(html, fromUrl) {
    for (const pattern of ASSET_PATTERNS) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(html)) !== null) {
        const resolved = resolveUrl(m[1], fromUrl);
        if (resolved && !assetsMap.has(resolved)) {
          assetsMap.set(resolved, assetZipPath(resolved));
        }
      }
    }
  }

  function extractInternalLinks(html, fromUrl) {
    const links = new Set();
    const re = /href=["']([^"'#][^"']*)["']/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
      const resolved = resolveUrl(m[1], fromUrl);
      if (!resolved) continue;
      try {
        const u = new URL(resolved);
        if (u.hostname === baseHostname && !visitedPages.has(resolved.split('#')[0])) {
          links.add(resolved.split('#')[0]);
        }
      } catch {}
    }
    return [...links];
  }

  async function crawlPage(url, depth) {
    if (visitedPages.has(url) || visitedPages.size >= 50) return;
    visitedPages.add(url);

    const res = await fetchSafe(url);
    if (!res || !res.ok) return;

    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('html') && !ct.includes('text/plain')) return;

    let html;
    try { html = await res.text(); } catch { return; }

    const zipPath = url === targetUrl.split('#')[0] ? 'index.html' : urlToZipPath(url);
    archive.append(html, { name: zipPath });
    onProgress?.(`✓ Página: ${new URL(url).pathname || '/'}`);

    collectAssets(html, url);

    if (depth > 0) {
      const links = extractInternalLinks(html, url);
      for (const link of links.slice(0, 15)) {
        await crawlPage(link, depth - 1);
      }
    }
  }

  try {
    onProgress?.(`Conectando em: ${targetUrl}`);

    // ─── 1. Main page ───────────────────────────────────────────
    const mainRes = await fetchSafe(targetUrl);
    if (!mainRes || !mainRes.ok) {
      throw new Error(`Não foi possível acessar ${targetUrl} (HTTP ${mainRes?.status || 'timeout'})`);
    }

    const mainHtml = await mainRes.text();
    visitedPages.add(targetUrl.split('#')[0]);
    archive.append(mainHtml, { name: 'index.html' });
    onProgress?.('✓ index.html baixado');

    collectAssets(mainHtml, targetUrl);

    // ─── 2. Crawl internal pages (depth 2) ───────────────────────
    onProgress?.('Crawling páginas internas...');
    const initialLinks = extractInternalLinks(mainHtml, targetUrl);
    for (const link of initialLinks.slice(0, 30)) {
      await crawlPage(link, 1);
    }
    onProgress?.(`✓ ${visitedPages.size} páginas coletadas`);

    // ─── 3. Static utility files ─────────────────────────────────
    const staticFiles = [
      'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'manifest.json',
      'manifest.webmanifest', 'browserconfig.xml', '.well-known/security.txt',
      'humans.txt', 'ads.txt', 'app-ads.txt', 'sw.js', 'service-worker.js',
    ];
    for (const f of staticFiles) {
      const res = await fetchSafe(`${baseOrigin}/${f}`, { timeout: 6000 });
      if (!res?.ok) continue;
      try {
        const ct = res.headers.get('content-type') || '';
        const content = (ct.includes('image') || f.endsWith('.ico'))
          ? await res.buffer()
          : await res.text();
        if (content && content.length > 0) {
          archive.append(content, { name: f });
          onProgress?.(`✓ ${f}`);
        }
      } catch {}
    }

    // ─── 4. Download all collected assets ────────────────────────
    const assetEntries = [...assetsMap.entries()].slice(0, 250);
    onProgress?.(`Baixando ${assetEntries.length} assets (CSS, JS, imagens, fontes)...`);

    let downloaded = 0;
    const usedZipPaths = new Set(['index.html']);

    for (const [assetUrl, zipPath] of assetEntries) {
      // Avoid path collisions
      let finalPath = zipPath;
      let counter = 1;
      while (usedZipPaths.has(finalPath)) {
        const parts = zipPath.split('.');
        const ext = parts.pop();
        finalPath = `${parts.join('.')}_${counter++}.${ext}`;
      }
      usedZipPaths.add(finalPath);

      const res = await fetchSafe(assetUrl, { timeout: 8000 });
      if (!res?.ok) continue;

      try {
        const ct = res.headers.get('content-type') || '';
        const isBinary = ct.includes('image') || ct.includes('font') || ct.includes('octet-stream')
          || /\.(woff2?|ttf|eot|otf|ico|png|jpg|jpeg|gif|webp|svg|bmp|avif|mp4|webm|mp3|ogg)$/i.test(assetUrl);

        const content = isBinary ? await res.buffer() : await res.text();
        const size = Buffer.isBuffer(content) ? content.length : Buffer.byteLength(content, 'utf8');

        if (size > 0 && size < 20 * 1024 * 1024) {
          archive.append(content, { name: finalPath });
          downloaded++;
          if (downloaded % 25 === 0) onProgress?.(`✓ ${downloaded} assets baixados...`);
        }
      } catch {}
    }
    onProgress?.(`✓ ${downloaded} assets baixados`);

    // ─── 5. Source maps ──────────────────────────────────────────
    const jsEntries = assetEntries.filter(([url]) => /\.js$/i.test(url.split('?')[0]));
    let mapsFound = 0;
    for (const [jsUrl, jsPath] of jsEntries.slice(0, 40)) {
      const res = await fetchSafe(jsUrl + '.map', { timeout: 5000 });
      if (!res?.ok) continue;
      try {
        const text = await res.text();
        if (text && text.length > 10 && text.includes('"version"')) {
          const mapName = jsPath.split('/').pop();
          archive.append(text, { name: `sourcemaps/${mapName}.map` });
          mapsFound++;
        }
      } catch {}
    }
    if (mapsFound > 0) onProgress?.(`✓ ${mapsFound} source maps encontrados`);

    // ─── 6. Finalize ─────────────────────────────────────────────
    await archive.finalize();
    const sizeMB = (archive.pointer() / 1024 / 1024).toFixed(2);
    onProgress?.(`✓ ZIP finalizado: ${sizeMB} MB | ${visitedPages.size} páginas | ${downloaded} assets`);

  } catch (err) {
    try { archive.abort(); } catch {}
    throw new Error(`Scrape falhou: ${err.message}`);
  }
}

/** Full scrape with website-scraper (disk-based, not for serverless) */
async function scrapeSiteToZip(targetUrl, outputStream, onProgress) {
  // Delegate to lightScrape — more reliable in Node/serverless environments
  return lightScrape(targetUrl, outputStream, onProgress);
}

module.exports = { scrapeSiteToZip, lightScrape };
