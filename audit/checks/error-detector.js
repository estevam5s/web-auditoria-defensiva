/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Error Detector
    Detects runtime errors, misconfigurations, broken resources,
    console errors, and code quality issues in production sites
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function deepErrorDetector(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);
  const errors = [];

  emit({ type: 'log', level: 'info', message: `[Error Detector] Iniciando detecção de erros...` });

  // ═══════════ 1. HTTP Status Errors ═══════════
  emit({ type: 'log', level: 'info', message: `[Error Detector] Verificando status HTTP de endpoints...` });
  
  const criticalEndpoints = [
    { path: '/', name: 'Homepage' },
    { path: '/favicon.ico', name: 'Favicon' },
    { path: '/robots.txt', name: 'Robots.txt' },
    { path: '/sitemap.xml', name: 'Sitemap' },
    { path: '/manifest.json', name: 'Manifest' },
    { path: '/.well-known/security.txt', name: 'Security.txt' },
    { path: '/api', name: 'API Root' },
    { path: '/api/health', name: 'Health Check' },
    { path: '/api/status', name: 'Status' },
  ];

  if (config.anonKey) {
    criticalEndpoints.push(
      { path: '/rest/v1/', name: 'REST API' },
      { path: '/auth/v1/settings', name: 'Auth Settings' },
      { path: '/storage/v1/bucket', name: 'Storage' },
      { path: '/realtime/v1', name: 'Realtime' }
    );
  }

  const statusErrors = [];
  for (const ep of criticalEndpoints) {
    const fetchHeaders = ep.path.includes('/rest/') || ep.path.includes('/auth/') || ep.path.includes('/storage/')
      ? headers : {};
    
    const res = await safeFetch(baseUrl + ep.path, { headers: fetchHeaders, timeout: 8000 });
    
    if (res.status >= 500) {
      statusErrors.push({
        endpoint: ep.path,
        name: ep.name,
        status: res.status,
        statusText: res.statusText,
        severity: 'high',
        hasStackTrace: res.text && (res.text.includes('Error:') || res.text.includes('at '))
      });
      emit({ type: 'log', level: 'warn', message: `[Error Detector] ⚠ ${ep.name} (${ep.path}) → ${res.status} ${res.statusText}` });
    } else if (res.error) {
      statusErrors.push({
        endpoint: ep.path,
        name: ep.name,
        error: res.error,
        severity: 'medium'
      });
    }
  }

  if (statusErrors.length > 0) {
    results.push({
      check: 'Errors — Server Errors (5xx)',
      status: 'FAIL',
      severity: statusErrors.some(e => e.severity === 'high') ? 'high' : 'medium',
      message: `${statusErrors.length} endpoint(s) retornando erro(s) de servidor.`,
      details: {
        errors: statusErrors,
        recommendation: 'Verifique os logs do servidor e corrija os endpoints que retornam erro 5xx.'
      }
    });
  }

  // ═══════════ 2. Broken Resources Detection ═══════════
  emit({ type: 'log', level: 'info', message: `[Error Detector] Detectando recursos quebrados (links, scripts, imagens)...` });
  
  const mainPage = await safeFetch(baseUrl, { timeout: 15000 });
  const brokenResources = [];

  if (mainPage.ok && mainPage.text) {
    // Extract all resource URLs
    const resources = [];
    
    // Scripts
    const scriptRegex = /<script[^>]*src=["']([^"']+)["']/gi;
    let match;
    while ((match = scriptRegex.exec(mainPage.text)) !== null) {
      resources.push({ url: match[1], type: 'script' });
    }
    
    // Stylesheets
    const cssRegex = /<link[^>]*href=["']([^"']+\.css[^"']*)["']/gi;
    while ((match = cssRegex.exec(mainPage.text)) !== null) {
      resources.push({ url: match[1], type: 'stylesheet' });
    }
    
    // Images
    const imgRegex = /<img[^>]*src=["']([^"']+)["']/gi;
    while ((match = imgRegex.exec(mainPage.text)) !== null) {
      resources.push({ url: match[1], type: 'image' });
    }
    
    // Links
    const linkRegex = /<a[^>]*href=["']([^"'#][^"']*)["']/gi;
    while ((match = linkRegex.exec(mainPage.text)) !== null) {
      const href = match[1];
      if (href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) continue;
      resources.push({ url: href, type: 'link' });
    }

    emit({ type: 'log', level: 'info', message: `[Error Detector] ${resources.length} recursos encontrados para verificação...` });
    
    // Normalize URLs
    const normalizedResources = resources.map(r => {
      let url = r.url;
      if (url.startsWith('//')) url = 'https:' + url;
      else if (url.startsWith('/')) url = baseUrl + url;
      else if (!url.startsWith('http')) url = baseUrl + '/' + url;
      return { ...r, fullUrl: url };
    });

    // Check each resource (batch for speed)
    const BATCH_SIZE = 10;
    let checked = 0;
    
    for (let i = 0; i < normalizedResources.length && i < 100; i += BATCH_SIZE) {
      const batch = normalizedResources.slice(i, i + BATCH_SIZE);
      const fetches = batch.map(r => 
        safeFetch(r.fullUrl, { method: 'HEAD', timeout: 5000 })
          .then(res => ({ ...r, status: res.status, error: res.error }))
      );
      
      const batchResults = await Promise.all(fetches);
      
      for (const r of batchResults) {
        checked++;
        if (r.status === 404 || r.status === 410 || r.status === 0) {
          brokenResources.push({
            url: r.url,
            type: r.type,
            status: r.status || 'unreachable',
            error: r.error
          });
          emit({ type: 'log', level: 'warn', message: `[Error Detector] ✗ Broken ${r.type}: ${r.url.substring(0, 80)}` });
        }
      }
      
      if (checked % 20 === 0) {
        emit({ type: 'log', level: 'info', message: `[Error Detector] ${checked}/${Math.min(normalizedResources.length, 100)} recursos verificados...` });
      }
    }
  }

  if (brokenResources.length > 0) {
    results.push({
      check: 'Errors — Broken Resources',
      status: 'WARN',
      severity: brokenResources.some(r => r.type === 'script') ? 'high' : 'medium',
      message: `${brokenResources.length} recurso(s) quebrado(s): ${brokenResources.filter(r=>r.type==='script').length} scripts, ${brokenResources.filter(r=>r.type==='link').length} links, ${brokenResources.filter(r=>r.type==='image').length} imagens.`,
      details: {
        broken: brokenResources.slice(0, 30),
        recommendation: 'Corrija ou remova os recursos quebrados. Scripts quebrados podem causar erros no frontend.'
      }
    });
  } else {
    results.push({
      check: 'Errors — Broken Resources',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum recurso quebrado detectado.',
      details: { checked: Math.min((mainPage.ok ? brokenResources.length : 0) + 100, 100) }
    });
  }

  // ═══════════ 3. JavaScript Error Detection ═══════════
  emit({ type: 'log', level: 'info', message: `[Error Detector] Detectando erros em código JavaScript...` });
  
  const jsErrors = [];
  
  if (mainPage.ok && mainPage.text) {
    // Extract inline scripts
    const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let scriptMatch;
    let scriptIndex = 0;
    
    while ((scriptMatch = inlineScriptRegex.exec(mainPage.text)) !== null) {
      scriptIndex++;
      const code = scriptMatch[1].trim();
      if (!code || code.length < 10) continue;
      
      const codeErrors = analyzeJavaScript(code, `inline-script-${scriptIndex}`);
      jsErrors.push(...codeErrors);
    }

    // Analyze external JS files
    const scriptUrls = [];
    const extScriptRegex = /<script[^>]*src=["']([^"']+)["']/gi;
    while ((match = extScriptRegex.exec(mainPage.text)) !== null) {
      let src = match[1];
      if (src.startsWith('//')) src = 'https:' + src;
      else if (src.startsWith('/')) src = baseUrl + src;
      else if (!src.startsWith('http')) src = baseUrl + '/' + src;
      scriptUrls.push(src);
    }

    const BATCH_SIZE = 5;
    for (let i = 0; i < scriptUrls.length && i < 30; i += BATCH_SIZE) {
      const batch = scriptUrls.slice(i, i + BATCH_SIZE);
      const fetches = batch.map(url => safeFetch(url, { timeout: 8000 }));
      const responses = await Promise.all(fetches);
      
      for (let j = 0; j < responses.length; j++) {
        if (responses[j].ok && responses[j].text) {
          const codeErrors = analyzeJavaScript(responses[j].text, batch[j]);
          jsErrors.push(...codeErrors);
        }
      }
    }
  }

  if (jsErrors.length > 0) {
    const critJs = jsErrors.filter(e => e.severity === 'high');
    const warnJs = jsErrors.filter(e => e.severity === 'medium');
    
    results.push({
      check: 'Errors — JavaScript Code Issues',
      status: critJs.length > 0 ? 'FAIL' : 'WARN',
      severity: critJs.length > 0 ? 'high' : 'medium',
      message: `${jsErrors.length} problema(s) em código JavaScript: ${critJs.length} erros, ${warnJs.length} avisos.`,
      details: {
        errors: jsErrors.slice(0, 30),
        recommendation: 'Corrija os erros de JavaScript para melhorar a estabilidade e segurança.'
      }
    });
  }

  // ═══════════ 4. SSL/TLS Check ═══════════
  emit({ type: 'log', level: 'info', message: `[Error Detector] Verificando configuração SSL/TLS...` });
  
  const sslErrors = [];
  
  // Check HTTPS redirect
  try {
    const httpUrl = baseUrl.replace('https://', 'http://');
    const httpRes = await safeFetch(httpUrl, { timeout: 5000 });
    
    if (httpRes.ok && !httpRes.url?.startsWith('https://')) {
      sslErrors.push({
        type: 'No HTTPS Redirect',
        severity: 'high',
        note: 'Site acessível via HTTP sem redirecionamento para HTTPS.'
      });
    }
  } catch (e) {
    // Fine - HTTP may not be available
  }
  
  // Check HSTS
  if (mainPage.headers?.['strict-transport-security']) {
    const hsts = mainPage.headers['strict-transport-security'];
    const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0');
    
    if (maxAge < 31536000) { // Less than 1 year
      sslErrors.push({
        type: 'Weak HSTS',
        severity: 'medium',
        note: `HSTS max-age=${maxAge} (recomendado: ≥31536000)`
      });
    }
    
    if (!hsts.includes('includeSubDomains')) {
      sslErrors.push({
        type: 'HSTS sem includeSubDomains',
        severity: 'low',
        note: 'Subdomínios não são protegidos pelo HSTS.'
      });
    }
  } else {
    sslErrors.push({
      type: 'HSTS Ausente',
      severity: 'high',
      note: 'Header Strict-Transport-Security não encontrado.'
    });
  }

  // Mixed content detection
  if (mainPage.ok && mainPage.text) {
    const mixedContent = [];
    const httpResourceRegex = /(?:src|href|action)=["'](http:\/\/[^"']+)["']/gi;
    let mixedMatch;
    
    while ((mixedMatch = httpResourceRegex.exec(mainPage.text)) !== null) {
      mixedContent.push(mixedMatch[1]);
    }
    
    if (mixedContent.length > 0) {
      sslErrors.push({
        type: 'Mixed Content',
        severity: 'medium',
        note: `${mixedContent.length} recurso(s) carregado(s) via HTTP em página HTTPS.`,
        resources: mixedContent.slice(0, 10)
      });
    }
  }

  if (sslErrors.length > 0) {
    results.push({
      check: 'Errors — SSL/TLS Configuration',
      status: sslErrors.some(e => e.severity === 'high') ? 'FAIL' : 'WARN',
      severity: sslErrors.some(e => e.severity === 'high') ? 'high' : 'medium',
      message: `${sslErrors.length} problema(s) na configuração SSL/TLS.`,
      details: {
        issues: sslErrors,
        recommendation: 'Configure HTTPS redirect, HSTS com max-age ≥ 1 ano, e remova mixed content.'
      }
    });
  }

  // ═══════════ 5. API Error Patterns ═══════════
  if (config.anonKey) {
    emit({ type: 'log', level: 'info', message: `[Error Detector] Testando padrões de erro da API...` });
    
    const apiErrors = [];
    
    // Test malformed requests
    const malformedTests = [
      { path: '/rest/v1/?select=*', name: 'Empty table query' },
      { path: '/rest/v1/nonexistent_table', name: 'Non-existent table' },
      { path: '/rest/v1/?select=1;DROP TABLE users', name: 'SQL Injection attempt' },
      { path: '/rest/v1/?select=*&or=(id.eq.1)', name: 'Malformed filter' },
      { path: '/auth/v1/token?grant_type=password', name: 'Empty auth' },
    ];
    
    for (const test of malformedTests) {
      const res = await safeFetch(baseUrl + test.path, {
        headers: { ...headers, 'Content-Type': 'application/json' },
        method: test.name.includes('auth') ? 'POST' : 'GET',
        body: test.name.includes('auth') ? JSON.stringify({}) : undefined,
        timeout: 5000
      });
      
      if (res.text) {
        // Check if error response leaks info
        const leakPatterns = [
          { pattern: /column|relation|table|schema/i, info: 'Database structure' },
          { pattern: /postgres|pg_|postgresql/i, info: 'Database engine' },
          { pattern: /stack trace|at\s+\w+/i, info: 'Stack trace' },
          { pattern: /internal server error/i, info: 'Internal error' },
          { pattern: /syntax error/i, info: 'SQL syntax error' },
        ];
        
        for (const lp of leakPatterns) {
          if (lp.pattern.test(res.text)) {
            apiErrors.push({
              test: test.name,
              path: test.path,
              status: res.status,
              infoLeak: lp.info,
              sample: res.text.substring(0, 200)
            });
          }
        }
      }
    }
    
    if (apiErrors.length > 0) {
      results.push({
        check: 'Errors — API Error Handling',
        status: 'WARN',
        severity: 'medium',
        message: `${apiErrors.length} resposta(s) de erro revelam informações internas.`,
        details: {
          errors: apiErrors,
          recommendation: 'Configure error handling personalizado para não expor detalhes internos em mensagens de erro.'
        }
      });
    }
  }

  // ═══════════ 6. Performance / Loading Issues ═══════════
  emit({ type: 'log', level: 'info', message: `[Error Detector] Verificando problemas de performance...` });
  
  const perfIssues = [];
  
  if (mainPage.ok && mainPage.text) {
    const htmlSize = mainPage.text.length;
    
    if (htmlSize > 500000) {
      perfIssues.push({
        type: 'HTML muito grande',
        value: `${(htmlSize / 1024).toFixed(0)} KB`,
        severity: 'medium',
        note: 'HTML acima de 500KB pode causar lentidão no carregamento.'
      });
    }
    
    // Count inline scripts/styles
    const inlineScripts = (mainPage.text.match(/<script[^>]*>[^<]{500,}<\/script>/g) || []).length;
    const inlineStyles = (mainPage.text.match(/<style[^>]*>[^<]{500,}<\/style>/g) || []).length;
    
    if (inlineScripts > 5) {
      perfIssues.push({
        type: 'Excesso de scripts inline',
        value: `${inlineScripts} scripts grandes inline`,
        severity: 'low',
        note: 'Muitos scripts inline grandes dificulta cache e aumenta o HTML.'
      });
    }
    
    // Check for render-blocking resources
    const renderBlockingScripts = (mainPage.text.match(/<script(?![^>]*(?:async|defer))[^>]*src/g) || []).length;
    if (renderBlockingScripts > 3) {
      perfIssues.push({
        type: 'Scripts bloqueando renderização',
        value: `${renderBlockingScripts} scripts sem async/defer`,
        severity: 'low',
        note: 'Use async ou defer em scripts para não bloquear a renderização.'
      });
    }
  }

  if (perfIssues.length > 0) {
    results.push({
      check: 'Errors — Performance Issues',
      status: 'WARN',
      severity: 'low',
      message: `${perfIssues.length} problema(s) de performance detectado(s).`,
      details: { issues: perfIssues }
    });
  }

  emit({ type: 'log', level: 'info', message: `[Error Detector] Detecção concluída. ${results.length} categorias de resultado.` });
  
  return results;
}

function analyzeJavaScript(code, source) {
  const errors = [];
  const shortSource = source.length > 60 ? '...' + source.substring(source.length - 60) : source;
  
  // Only analyze non-minified or lightly minified code
  const isMinified = code.length > 500 && (code.split('\n').length < code.length / 500);
  const isSourceMap = code.includes('//# sourceMappingURL=');
  
  // Check patterns
  const errorPatterns = [
    { regex: /throw\s+new\s+Error\s*\(\s*[`'"](.*?)[`'"]\s*\)/g, type: 'Throw Error', severity: 'low' },
    { regex: /console\.(error|warn)\s*\(\s*[`'"](.*?)[`'"]/g, type: 'Console Error/Warn', severity: 'low' },
    { regex: /\.catch\s*\(\s*(?:function\s*\(|(?:\w+)\s*=>)[\s\S]*?\)/g, type: 'Error Handler', severity: 'info' },
    { regex: /(?:eval|Function)\s*\(\s*[^)]*\)/g, type: 'Dangerous eval/Function', severity: 'high' },
    { regex: /document\.write\s*\(/g, type: 'document.write', severity: 'medium' },
    { regex: /innerHTML\s*=\s*(?!['"`]\s*['"`])/g, type: 'innerHTML Assignment', severity: 'medium' },
    { regex: /(?:window|document|location)\s*\[\s*[^'"`\]]+\]/g, type: 'Dynamic Property Access', severity: 'medium' },
    { regex: /new\s+XMLHttpRequest/g, type: 'Legacy XHR', severity: 'low' },
    { regex: /localStorage\.setItem\s*\(\s*['"`](?:token|key|secret|password|auth)/gi, type: 'Sensitive in localStorage', severity: 'high' },
    { regex: /atob\s*\(\s*['"`]|btoa\s*\(\s*['"`]/g, type: 'Base64 encode/decode', severity: 'low' },
    { regex: /(?:password|secret|key|token)\s*[:=]\s*['"`][^'"`]{3,}['"`]/gi, type: 'Hardcoded Secret', severity: 'high' },
    { regex: /debugger\s*;/g, type: 'Debugger Statement', severity: 'medium' },
    { regex: /\/\/\s*(?:TODO|FIXME|HACK|BUG|XXX|TEMP)[\s:]/gi, type: 'Code TODO/FIXME', severity: 'low' },
  ];

  for (const pattern of errorPatterns) {
    const matches = code.match(pattern.regex);
    if (matches && matches.length > 0) {
      errors.push({
        source: shortSource,
        type: pattern.type,
        severity: pattern.severity,
        count: matches.length,
        samples: matches.slice(0, 2).map(m => m.substring(0, 100)),
        isMinified
      });
    }
  }

  // Source map exposure
  if (isSourceMap) {
    const mapUrl = code.match(/\/\/[#@]\s*sourceMappingURL=(.+?)(?:\s|$)/);
    errors.push({
      source: shortSource,
      type: 'Source Map Exposed',
      severity: 'medium',
      note: 'Source maps em produção expõem código-fonte original.',
      mapUrl: mapUrl?.[1]
    });
  }

  return errors;
}

module.exports = { deepErrorDetector };
