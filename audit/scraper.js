/*  ═══════════════════════════════════════════════════════════════════
    SITE SCRAPER — Downloads target site source code as a structured ZIP
    Folder layout:
      {domain}-source/
        README.md              ← metadata, instructions, findings summary
        manifest.json          ← crawl inventory (pages, assets, counts)
        security/
          audit-report.json    ← full audit results (if provided)
          findings.md          ← human-readable security summary
        pages/                 ← HTML pages (index.html at root)
        css/                   ← stylesheets
        js/                    ← scripts
        sourcemaps/            ← *.js.map files
        images/                ← raster/svg images
        fonts/                 ← web fonts
        media/                 ← audio/video
        assets/                ← other static assets
        static/                ← robots.txt, sitemap.xml, manifest.json…
    ═══════════════════════════════════════════════════════════════════ */

const fetch    = require('node-fetch');
const archiver = require('archiver');

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/**
 * Professional recursive site downloader.
 * @param {string}   targetUrl    - Full URL of site to scrape
 * @param {Stream}   outputStream - Writable stream for the ZIP
 * @param {Function} onProgress   - Progress callback (msg: string) => void
 * @param {Object}   auditData    - Optional: full audit results to embed in ZIP
 */
async function lightScrape(targetUrl, outputStream, onProgress, auditData = null) {
  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.pipe(outputStream);

  let base;
  try {
    base = new URL(targetUrl);
  } catch {
    throw new Error(`URL inválida: ${targetUrl}`);
  }

  const baseOrigin   = base.origin;
  const baseHostname = base.hostname;

  // Root folder name inside the ZIP (e.g. "meusite-com-source")
  const rootDir = baseHostname.replace(/[^a-zA-Z0-9.-]/g, '-').replace(/\.$/, '') + '-source';

  const visitedPages = new Set();
  const assetsMap    = new Map();   // resolvedUrl → zipPath (relative to rootDir)
  const pagesMeta    = [];          // { url, zipPath, statusCode }

  const FETCH_HEADERS = {
    'User-Agent':      DEFAULT_UA,
    'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8',
    'Accept-Encoding': 'identity',
  };

  // ── Helpers ──────────────────────────────────────────────────────

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

  function urlToPagePath(url) {
    try {
      const u = new URL(url);
      let p = u.pathname.replace(/^\//, '') || 'index.html';
      if (p.endsWith('/')) p += 'index.html';
      if (!p.match(/\.[a-zA-Z0-9]{1,6}$/)) p += '/index.html';
      return `pages/${p.replace(/[<>:"|?*\\]/g, '_')}`;
    } catch {
      return `pages/page_${Math.random().toString(36).slice(2)}.html`;
    }
  }

  function assetZipPath(resolvedUrl) {
    try {
      const url      = new URL(resolvedUrl);
      const filename = (url.pathname.split('/').pop() || `asset_${assetsMap.size}`).substring(0, 120);
      const ext      = filename.split('.').pop().toLowerCase();
      const dir =
        ext === 'css'                                                          ? 'css'
        : ['js', 'mjs', 'jsx', 'ts', 'tsx'].includes(ext)                     ? 'js'
        : ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'ico', 'bmp', 'avif'].includes(ext) ? 'images'
        : ['woff', 'woff2', 'ttf', 'eot', 'otf'].includes(ext)                ? 'fonts'
        : ['mp4', 'webm', 'ogg', 'mp3', 'wav'].includes(ext)                  ? 'media'
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
    const re    = /href=["']([^"'#][^"']*)["']/gi;
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
    if (!res) return;

    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('html') && !ct.includes('text/plain')) return;

    let html;
    try { html = await res.text(); } catch { return; }

    const isRoot  = url === targetUrl.split('#')[0];
    const zipPath = isRoot ? 'pages/index.html' : urlToPagePath(url);

    archive.append(html, { name: `${rootDir}/${zipPath}` });
    pagesMeta.push({ url, zipPath, status: res.status });
    onProgress?.(`✓ Página: ${new URL(url).pathname || '/'}`);

    collectAssets(html, url);

    if (depth > 0) {
      const links = extractInternalLinks(html, url);
      for (const link of links.slice(0, 15)) {
        await crawlPage(link, depth - 1);
      }
    }
  }

  // ── Unique zip path helper ────────────────────────────────────────
  const usedZipPaths = new Set();
  function uniquePath(base) {
    if (!usedZipPaths.has(base)) { usedZipPaths.add(base); return base; }
    const parts  = base.split('.');
    const ext    = parts.length > 1 ? `.${parts.pop()}` : '';
    const stem   = parts.join('.');
    let counter  = 1;
    while (usedZipPaths.has(`${stem}_${counter}${ext}`)) counter++;
    const unique = `${stem}_${counter}${ext}`;
    usedZipPaths.add(unique);
    return unique;
  }

  // ── BUILD README.md ──────────────────────────────────────────────
  function buildReadme(stats) {
    const now    = new Date().toISOString();
    const score  = auditData?.score ?? '—';
    const grade  = auditData?.grade?.grade ?? '—';
    const passed = auditData?.passed ?? '—';
    const failed = auditData?.failed ?? '—';
    const warns  = auditData?.warnings ?? '—';

    let secSection = '';
    if (auditData) {
      const criticals = (auditData.results || []).filter(r => r.status === 'FAIL' && r.severity === 'critical');
      const topFinds  = (auditData.results || []).filter(r => r.status === 'FAIL').slice(0, 10);
      secSection = `
## Resultados da Auditoria de Segurança

| Métrica          | Valor       |
|------------------|-------------|
| Score            | ${score}/100   |
| Grade            | ${grade}    |
| Verificações OK  | ${passed}   |
| Falhas           | ${failed}   |
| Alertas          | ${warns}    |
| Criticalidades   | ${criticals.length} |

### Falhas Detectadas
${topFinds.length === 0 ? '_Nenhuma falha encontrada._' : topFinds.map(r =>
  `- **[${r.severity?.toUpperCase() || 'FAIL'}]** ${r.check}: ${r.message}`
).join('\n')}

> Veja \`security/audit-report.json\` para o relatório completo.
> Veja \`security/findings.md\` para o resumo legível.
`;
    }

    return `# Código-Fonte Baixado — ${baseHostname}

> Gerado pelo **Supabase Guard v3.3.0** — Defensive Audit Console
> Data/Hora: ${now}
> URL alvo: ${targetUrl}

---

## Estrutura do Arquivo ZIP

\`\`\`
${rootDir}/
├── README.md              ← Este arquivo
├── manifest.json          ← Inventário completo do crawl
├── security/
│   ├── audit-report.json  ← Relatório completo de segurança
│   └── findings.md        ← Resumo legível dos achados
├── pages/
│   ├── index.html         ← Página principal
│   └── ...                ← Demais páginas HTML
├── css/                   ← Folhas de estilo
├── js/                    ← Scripts JavaScript
├── sourcemaps/            ← Source maps (*.js.map)
├── images/                ← Imagens (PNG, JPG, SVG, WebP…)
├── fonts/                 ← Fontes web (WOFF, WOFF2, TTF…)
├── media/                 ← Áudio e vídeo
├── assets/                ← Outros assets estáticos
└── static/                ← robots.txt, sitemap.xml, manifest.json…
\`\`\`

## Estatísticas do Crawl

| Item                  | Quantidade |
|-----------------------|-----------|
| Páginas HTML          | ${stats.pages}       |
| Assets (CSS/JS/img…)  | ${stats.assets}      |
| Source Maps           | ${stats.sourcemaps}  |
| Arquivos estáticos    | ${stats.static}      |
| Total de arquivos     | ${stats.total}       |
${secSection}
## Como Usar

1. Extraia o ZIP em uma pasta local
2. Abra \`pages/index.html\` no navegador para visualizar offline
3. Analise os arquivos em \`js/\` para encontrar lógica de negócio, endpoints, tokens
4. Revise \`css/\` e \`images/\` para entender a interface
5. Consulte \`security/findings.md\` para priorizar correções

## Aviso Legal

Este download foi gerado para fins **defensivos e de auditoria**. Use apenas
em projetos próprios ou com autorização explícita do proprietário.

---
*Supabase Guard — https://github.com/supabase-guard*
`;
  }

  // ── BUILD manifest.json ─────────────────────────────────────────
  function buildManifest(stats, downloadedAssets) {
    return JSON.stringify({
      tool:        'Supabase Guard v3.3.0',
      generatedAt: new Date().toISOString(),
      target: {
        url:      targetUrl,
        hostname: baseHostname,
        origin:   baseOrigin,
      },
      crawl: {
        pagesVisited: pagesMeta.length,
        assetsFound:  assetsMap.size,
        assetsDownloaded: stats.assets,
        sourceMaps:   stats.sourcemaps,
        staticFiles:  stats.static,
        totalFiles:   stats.total,
      },
      pages: pagesMeta.map(p => ({ url: p.url, file: p.zipPath, status: p.status })),
      assetTypes: {
        css:    downloadedAssets.filter(a => a.dir === 'css').length,
        js:     downloadedAssets.filter(a => a.dir === 'js').length,
        images: downloadedAssets.filter(a => a.dir === 'images').length,
        fonts:  downloadedAssets.filter(a => a.dir === 'fonts').length,
        media:  downloadedAssets.filter(a => a.dir === 'media').length,
        other:  downloadedAssets.filter(a => a.dir === 'assets').length,
      },
      audit: auditData ? {
        auditId: auditData.evidence?.auditId,
        score:   auditData.score,
        grade:   auditData.grade?.grade,
        passed:  auditData.passed,
        failed:  auditData.failed,
        warns:   auditData.warnings,
      } : null,
    }, null, 2);
  }

  // ── BUILD security/findings.md ───────────────────────────────────
  function buildFindingsMd() {
    if (!auditData) {
      return '# Security Findings\n\nNenhuma auditoria associada a este download.\n';
    }

    const results  = auditData.results || [];
    const fails    = results.filter(r => r.status === 'FAIL').sort((a, b) => {
      const sev = { critical: 0, high: 1, medium: 2, low: 3 };
      return (sev[a.severity] ?? 4) - (sev[b.severity] ?? 4);
    });
    const warns    = results.filter(r => r.status === 'WARN');
    const passes   = results.filter(r => r.status === 'PASS');
    const verdict  = auditData.productionReady;

    const sevIcon  = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

    let md = `# Resumo de Segurança — ${baseHostname}

> Auditoria realizada em: ${auditData.evidence?.timestamp || new Date().toISOString()}
> Score: **${auditData.score}/100** (${auditData.grade?.grade} — ${auditData.grade?.label})
`;

    if (verdict) {
      const icon = verdict.verdict === 'APTO' ? '✅' : verdict.verdict === 'APTO_COM_RESSALVAS' ? '⚠️' : '❌';
      md += `> Veredicto de Produção: **${icon} ${verdict.label}**\n`;
    }

    md += `
---

## ❌ Falhas (${fails.length})

`;
    if (fails.length === 0) {
      md += '_Nenhuma falha detectada._\n';
    } else {
      for (const r of fails) {
        const icon = sevIcon[r.severity] || '⚪';
        md += `### ${icon} ${r.check}\n`;
        md += `**Severidade:** ${(r.severity || 'unknown').toUpperCase()}  \n`;
        md += `**Resultado:** ${r.message}\n\n`;
      }
    }

    md += `## ⚠️ Alertas (${warns.length})\n\n`;
    if (warns.length === 0) {
      md += '_Nenhum alerta._\n';
    } else {
      for (const r of warns) {
        md += `- **${r.check}**: ${r.message}\n`;
      }
    }

    md += `\n## ✅ Aprovados (${passes.length})\n\n`;
    for (const r of passes) {
      md += `- ${r.check}\n`;
    }

    if (verdict?.blockers?.length > 0) {
      md += `\n## 🚫 Bloqueadores para Produção\n\n`;
      for (const b of verdict.blockers) {
        md += `- ${b}\n`;
      }
    }

    md += `\n---\n*Gerado pelo Supabase Guard v3.3.0*\n`;
    return md;
  }

  // ═══════════════════════════════════════════════════════════════════
  // MAIN CRAWL FLOW
  // ═══════════════════════════════════════════════════════════════════

  try {
    onProgress?.(`Conectando em: ${targetUrl}`);

    // ── 1. Main page ──────────────────────────────────────────────
    const mainRes = await fetchSafe(targetUrl);
    if (!mainRes || !mainRes.ok) {
      throw new Error(`Não foi possível acessar ${targetUrl} (HTTP ${mainRes?.status || 'timeout'})`);
    }

    const mainHtml = await mainRes.text();
    visitedPages.add(targetUrl.split('#')[0]);
    archive.append(mainHtml, { name: `${rootDir}/pages/index.html` });
    pagesMeta.push({ url: targetUrl, zipPath: 'pages/index.html', status: mainRes.status });
    onProgress?.('✓ pages/index.html');

    collectAssets(mainHtml, targetUrl);

    // ── 2. Crawl internal pages (depth 2) ─────────────────────────
    onProgress?.('Rastreando páginas internas...');
    const initialLinks = extractInternalLinks(mainHtml, targetUrl);
    for (const link of initialLinks.slice(0, 30)) {
      await crawlPage(link, 1);
    }
    onProgress?.(`✓ ${pagesMeta.length} páginas rastreadas`);

    // ── 3. Static utility files → static/ folder ─────────────────
    const staticFiles = [
      'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'sitemap_0.xml',
      'manifest.json', 'manifest.webmanifest', 'browserconfig.xml',
      '.well-known/security.txt', 'humans.txt', 'ads.txt', 'app-ads.txt',
      'sw.js', 'service-worker.js', 'workbox-*.js', 'favicon.ico',
      'apple-touch-icon.png', 'og-image.png', 'schema.json',
    ];
    let staticCount = 0;
    for (const f of staticFiles) {
      const res = await fetchSafe(`${baseOrigin}/${f}`, { timeout: 6000 });
      if (!res?.ok) continue;
      try {
        const ct = res.headers.get('content-type') || '';
        const isBin = ct.includes('image') || f.endsWith('.ico') || f.endsWith('.png');
        const content = isBin ? await res.buffer() : await res.text();
        if (content && content.length > 0) {
          archive.append(content, { name: `${rootDir}/static/${f}` });
          staticCount++;
          onProgress?.(`✓ static/${f}`);
        }
      } catch {}
    }

    // ── 4. Download all collected assets ──────────────────────────
    const assetEntries    = [...assetsMap.entries()].slice(0, 300);
    const downloadedAssets = [];
    onProgress?.(`Baixando ${assetEntries.length} assets (CSS, JS, imagens, fontes)...`);

    let assetCount = 0;
    for (const [assetUrl, rawZipPath] of assetEntries) {
      const uniqueZipPath = uniquePath(rawZipPath);
      const dir = uniqueZipPath.split('/')[0];

      const res = await fetchSafe(assetUrl, { timeout: 8000 });
      if (!res?.ok) continue;

      try {
        const ct     = res.headers.get('content-type') || '';
        const isBin  = ct.includes('image') || ct.includes('font') || ct.includes('octet-stream')
          || /\.(woff2?|ttf|eot|otf|ico|png|jpg|jpeg|gif|webp|svg|bmp|avif|mp4|webm|mp3|ogg|wav)$/i.test(assetUrl);
        const content = isBin ? await res.buffer() : await res.text();
        const size    = Buffer.isBuffer(content) ? content.length : Buffer.byteLength(content, 'utf8');

        if (size > 0 && size < 20 * 1024 * 1024) {
          archive.append(content, { name: `${rootDir}/${uniqueZipPath}` });
          assetCount++;
          downloadedAssets.push({ url: assetUrl, path: uniqueZipPath, dir, size });
          if (assetCount % 25 === 0) onProgress?.(`✓ ${assetCount} assets baixados...`);
        }
      } catch {}
    }
    onProgress?.(`✓ ${assetCount} assets baixados`);

    // ── 5. Source maps → sourcemaps/ folder ───────────────────────
    const jsEntries  = assetEntries.filter(([url]) => /\.js$/i.test(url.split('?')[0]));
    let mapsCount    = 0;
    for (const [jsUrl, jsPath] of jsEntries.slice(0, 40)) {
      const res = await fetchSafe(jsUrl + '.map', { timeout: 5000 });
      if (!res?.ok) continue;
      try {
        const text = await res.text();
        if (text && text.length > 10 && text.includes('"version"')) {
          const mapName = jsPath.split('/').pop() + '.map';
          archive.append(text, { name: `${rootDir}/sourcemaps/${mapName}` });
          mapsCount++;
        }
      } catch {}
    }
    if (mapsCount > 0) onProgress?.(`✓ ${mapsCount} source maps encontrados`);

    // ── 6. Security files ─────────────────────────────────────────
    if (auditData) {
      // Strip rawContent from details before embedding (keep it clean)
      const safeAudit = {
        ...auditData,
        results: (auditData.results || []).map(r => {
          if (!r.details?.rawContent) return r;
          const { rawContent, ...safeDetails } = r.details;
          return { ...r, details: safeDetails };
        }),
      };
      archive.append(JSON.stringify(safeAudit, null, 2), { name: `${rootDir}/security/audit-report.json` });
      onProgress?.('✓ security/audit-report.json');
    }
    archive.append(buildFindingsMd(), { name: `${rootDir}/security/findings.md` });

    // ── 7. Manifest + README ─────────────────────────────────────
    const stats = {
      pages:      pagesMeta.length,
      assets:     assetCount,
      sourcemaps: mapsCount,
      static:     staticCount,
      total:      pagesMeta.length + assetCount + mapsCount + staticCount + 2, // +README +manifest
    };
    archive.append(buildManifest(stats, downloadedAssets), { name: `${rootDir}/manifest.json` });
    archive.append(buildReadme(stats),                      { name: `${rootDir}/README.md` });

    // ── 8. Finalize ───────────────────────────────────────────────
    await archive.finalize();
    const sizeMB = (archive.pointer() / 1024 / 1024).toFixed(2);
    onProgress?.(`✓ ZIP finalizado: ${sizeMB} MB | ${stats.pages} páginas | ${stats.assets} assets | ${stats.total} arquivos`);

  } catch (err) {
    try { archive.abort(); } catch {}
    throw new Error(`Scrape falhou: ${err.message}`);
  }
}

module.exports = { lightScrape, scrapeSiteToZip: lightScrape };
