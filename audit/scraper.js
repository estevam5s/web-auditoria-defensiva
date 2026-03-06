/*  ═══════════════════════════════════════════════════════════════════
    SITE SCRAPER — Downloads target site source code as ZIP
    Uses website-scraper + puppeteer for dynamic SPA content
    ═══════════════════════════════════════════════════════════════════ */

const path = require('path');
const fs = require('fs');
const archiver = require('archiver');
const os = require('os');

async function scrapeSiteToZip(targetUrl, outputStream, onProgress) {
  const tmpDir = path.join(os.tmpdir(), `supabase-guard-scrape-${Date.now()}`);

  onProgress?.('Preparando scraper...');

  try {
    // Dynamic import for ESM modules
    const scrapeModule = await import('website-scraper');
    const scrape = scrapeModule.default || scrapeModule;

    let PuppeteerPlugin;
    try {
      const puppeteerPluginModule = await import('website-scraper-puppeteer');
      PuppeteerPlugin = puppeteerPluginModule.default || puppeteerPluginModule;
    } catch (e) {
      onProgress?.('Puppeteer plugin não disponível, usando modo básico...');
      PuppeteerPlugin = null;
    }

    onProgress?.(`Iniciando download de: ${targetUrl}`);

    const options = {
      urls: [targetUrl],
      directory: tmpDir,
      recursive: true,
      maxRecursiveDepth: 3,
      maxDepth: 3,
      sources: [
        { selector: 'img', attr: 'src' },
        { selector: 'link[rel="stylesheet"]', attr: 'href' },
        { selector: 'script', attr: 'src' },
        { selector: 'a', attr: 'href' },
        { selector: 'link[rel="icon"]', attr: 'href' },
        { selector: 'source', attr: 'src' },
        { selector: 'video', attr: 'src' },
      ],
      subdirectories: [
        { directory: 'images', extensions: ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico'] },
        { directory: 'css', extensions: ['.css'] },
        { directory: 'js', extensions: ['.js', '.mjs'] },
        { directory: 'fonts', extensions: ['.woff', '.woff2', '.ttf', '.eot', '.otf'] },
        { directory: 'media', extensions: ['.mp4', '.webm', '.mp3', '.ogg'] },
      ],
      request: {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
      },
      urlFilter: (url) => {
        // Only download from same domain + CDN assets
        try {
          const base = new URL(targetUrl);
          const check = new URL(url);
          if (check.hostname === base.hostname) return true;
          // Allow common CDNs
          const cdns = ['cdn.', 'fonts.', 'static.', 'assets.', 'unpkg.com', 'cdnjs.', 'jsdelivr.'];
          return cdns.some(c => check.hostname.includes(c));
        } catch {
          return false;
        }
      },
      plugins: [],
    };

    // Add Puppeteer plugin if available (for SPA support)
    if (PuppeteerPlugin) {
      options.plugins.push(
        new PuppeteerPlugin({
          launchOptions: {
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
          },
          scrollToBottom: {
            timeout: 10000,
            viewportN: 10
          },
          blockNavigation: true,
        })
      );
      onProgress?.('Puppeteer ativo: suporte a SPA/SSR...');
    }

    onProgress?.('Baixando páginas e recursos...');
    
    await scrape(options);

    onProgress?.('Download concluído. Criando arquivo ZIP...');

    // Create ZIP from scraped directory
    return new Promise((resolve, reject) => {
      const archive = archiver('zip', { zlib: { level: 9 } });

      archive.on('error', (err) => reject(err));
      archive.on('end', () => {
        onProgress?.(`ZIP criado: ${(archive.pointer() / 1024 / 1024).toFixed(2)} MB`);
        // Cleanup temp dir
        cleanDir(tmpDir);
        resolve();
      });

      archive.pipe(outputStream);
      archive.directory(tmpDir, 'source-code');
      archive.finalize();
    });

  } catch (err) {
    cleanDir(tmpDir);
    throw new Error(`Scraping falhou: ${err.message}`);
  }
}

function cleanDir(dir) {
  try {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } catch {}
}

// Light-weight alternative: fetch only key assets without puppeteer
async function lightScrape(targetUrl, outputStream, onProgress) {
  const fetch = require('node-fetch');
  const archive = archiver('zip', { zlib: { level: 9 } });

  archive.pipe(outputStream);

  onProgress?.('Modo leve: baixando HTML e assets...');

  try {
    // 1. Fetch main HTML
    const mainRes = await fetch(targetUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      timeout: 15000,
    });
    const html = await mainRes.text();
    archive.append(html, { name: 'index.html' });
    onProgress?.('✓ index.html');

    // 2. Extract and fetch CSS
    const cssUrls = extractUrls(html, targetUrl, /<link[^>]*href=["']([^"']+\.css[^"']*)["']/gi);
    for (const [name, url] of cssUrls.slice(0, 20)) {
      try {
        const res = await fetch(url, { timeout: 8000 });
        if (res.ok) {
          archive.append(await res.text(), { name: `css/${name}` });
          onProgress?.(`✓ css/${name}`);
        }
      } catch {}
    }

    // 3. Extract and fetch JS
    const jsUrls = extractUrls(html, targetUrl, /<script[^>]*src=["']([^"']+\.js[^"']*)["']/gi);
    for (const [name, url] of jsUrls.slice(0, 30)) {
      try {
        const res = await fetch(url, { timeout: 8000 });
        if (res.ok) {
          archive.append(await res.text(), { name: `js/${name}` });
          onProgress?.(`✓ js/${name}`);
        }
      } catch {}
    }

    // 4. Fetch common paths
    const commonPaths = [
      'robots.txt', 'sitemap.xml', 'manifest.json', 'favicon.ico',
      'sw.js', 'service-worker.js', '.well-known/security.txt',
    ];
    for (const p of commonPaths) {
      try {
        const res = await fetch(`${targetUrl}/${p}`, { timeout: 5000 });
        if (res.ok) {
          const ct = res.headers.get('content-type') || '';
          const content = ct.includes('image') ? await res.buffer() : await res.text();
          if (content.length > 0 && content.length < 5 * 1024 * 1024) {
            archive.append(content, { name: p });
            onProgress?.(`✓ ${p}`);
          }
        }
      } catch {}
    }

    // 5. Try to find and fetch source maps
    for (const [name, url] of jsUrls.slice(0, 10)) {
      try {
        const mapUrl = url + '.map';
        const res = await fetch(mapUrl, { timeout: 8000 });
        if (res.ok) {
          archive.append(await res.text(), { name: `sourcemaps/${name}.map` });
          onProgress?.(`✓ sourcemap: ${name}.map`);
        }
      } catch {}
    }

    await archive.finalize();
    onProgress?.(`ZIP criado: ${(archive.pointer() / 1024 / 1024).toFixed(2)} MB`);

  } catch (err) {
    archive.abort();
    throw new Error(`Light scrape falhou: ${err.message}`);
  }
}

function extractUrls(html, baseUrl, regex) {
  const results = [];
  const seen = new Set();
  let match;
  while ((match = regex.exec(html)) !== null) {
    let src = match[1];
    if (src.startsWith('//')) src = 'https:' + src;
    else if (src.startsWith('/')) src = baseUrl + src;
    else if (!src.startsWith('http')) src = baseUrl + '/' + src;

    if (seen.has(src)) continue;
    seen.add(src);

    const name = src.split('/').pop().split('?')[0] || `asset_${results.length}`;
    results.push([name, src]);
  }
  return results;
}

module.exports = { scrapeSiteToZip, lightScrape };
