/*  ═══════════════════════════════════════════════════════════════════
    PDF REPORT GENERATOR — Professional Cyber Security Audit Report
    Uses PDFKit to generate an elegant, branded PDF document
    ═══════════════════════════════════════════════════════════════════ */

const PDFDocument = require('pdfkit');

// ── Color Palette ────────────────────────────────────────────────
const COLORS = {
  bg:          '#0a0a12',
  bgLight:     '#12121e',
  bgCard:      '#181828',
  accent:      '#00ff41',
  accentDim:   '#00cc33',
  red:         '#ff0040',
  orange:      '#ff8c00',
  yellow:      '#e6e600',
  blue:        '#00bfff',
  purple:      '#a855f7',
  white:       '#f0f0f5',
  gray:        '#8888aa',
  grayDark:    '#555570',
  darkBorder:  '#2a2a44',
  critical:    '#ff0040',
  high:        '#ff6622',
  medium:      '#ff8c00',
  low:         '#e6e600',
  info:        '#00bfff',
  pass:        '#00ff41',
};

function severityColor(sev) {
  return COLORS[sev] || COLORS.gray;
}

function statusColor(status) {
  if (status === 'PASS') return COLORS.pass;
  if (status === 'FAIL') return COLORS.red;
  if (status === 'WARN') return COLORS.orange;
  if (status === 'ERROR') return COLORS.purple;
  return COLORS.blue;
}

// ═══════════════════════════════════════════════════════════════════
//  MAIN PDF GENERATION
// ═══════════════════════════════════════════════════════════════════
function generatePDFReport(auditData, outputStream) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 50, bottom: 50, left: 50, right: 50 },
      bufferPages: true,
      info: {
        Title: `Supabase Guard — Relatório de Auditoria de Segurança`,
        Author: 'Supabase Guard - Defensive Audit Console',
        Subject: `Auditoria: ${auditData.projectUrl}`,
        Keywords: 'security, audit, supabase, vulnerability, cybersecurity',
        Creator: 'Supabase Guard v2.0',
      }
    });

    doc.pipe(outputStream);

    try {
      drawCoverPage(doc, auditData);
      drawTableOfContents(doc, auditData);
      drawExecutiveSummary(doc, auditData);
      drawSecurityScore(doc, auditData);
      drawStackDetected(doc, auditData);
      drawWhatWeChecked(doc, auditData);
      drawVulnerabilityDetails(doc, auditData);
      drawHiddenRoutes(doc, auditData);
      drawSensitiveFiles(doc, auditData);
      drawInsights(doc, auditData);
      drawEvidence(doc, auditData);
      drawFooterOnAllPages(doc);

      doc.end();
      outputStream.on('finish', resolve);
      outputStream.on('error', reject);
    } catch (err) {
      doc.end();
      reject(err);
    }
  });
}

// ── Helper: New page with header ─────────────────────────────────
function newPage(doc, title) {
  doc.addPage();
  drawPageHeader(doc, title);
  return doc.y + 10;
}

function drawPageHeader(doc, title) {
  // Top border line
  doc.rect(50, 40, doc.page.width - 100, 2).fill(COLORS.accent);

  // Title
  doc.fontSize(16).font('Helvetica-Bold').fillColor(COLORS.accent)
     .text(title, 50, 52, { width: doc.page.width - 100 });

  // Thin line under title
  const y = doc.y + 5;
  doc.rect(50, y, doc.page.width - 100, 0.5).fill(COLORS.grayDark);
  doc.y = y + 15;
}

function checkPageSpace(doc, needed) {
  if (doc.y + needed > doc.page.height - 80) {
    doc.addPage();
    doc.y = 50;
    return true;
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════
//  1. COVER PAGE
// ═══════════════════════════════════════════════════════════════════
function drawCoverPage(doc, data) {
  // Dark background rectangle
  doc.rect(0, 0, doc.page.width, doc.page.height).fill('#08080e');

  // Decorative top stripe
  doc.rect(0, 0, doc.page.width, 6).fill(COLORS.accent);

  // Shield icon placeholder (text-based)
  doc.fontSize(80).fillColor(COLORS.accent)
     .text('🛡', 0, 140, { align: 'center' });

  // Title
  doc.fontSize(36).font('Helvetica-Bold').fillColor(COLORS.white)
     .text('SUPABASE', 0, 260, { align: 'center', characterSpacing: 8 });
  doc.fontSize(36).fillColor(COLORS.accent)
     .text('GUARD', 0, 300, { align: 'center', characterSpacing: 8 });

  // Subtitle
  doc.fontSize(12).font('Helvetica').fillColor(COLORS.gray)
     .text('DEFENSIVE AUDIT CONSOLE', 0, 350, { align: 'center', characterSpacing: 4 });

  // Line separator
  doc.rect(doc.page.width / 2 - 100, 385, 200, 1).fill(COLORS.accent);

  // Report type
  doc.fontSize(18).font('Helvetica-Bold').fillColor(COLORS.white)
     .text('Relatório de Incidências', 0, 410, { align: 'center' });
  doc.fontSize(18).fillColor(COLORS.white)
     .text('Cibernéticas', 0, 435, { align: 'center' });

  // Project info box
  const boxY = 490;
  doc.rect(doc.page.width / 2 - 170, boxY, 340, 120).lineWidth(0.5).stroke(COLORS.grayDark);

  doc.fontSize(10).font('Helvetica').fillColor(COLORS.gray)
     .text('ALVO', 0, boxY + 15, { align: 'center' });
  doc.fontSize(12).font('Helvetica-Bold').fillColor(COLORS.white)
     .text(data.projectUrl || 'N/A', 0, boxY + 32, { align: 'center' });

  doc.fontSize(10).font('Helvetica').fillColor(COLORS.gray)
     .text('DATA DA AUDITORIA', 0, boxY + 60, { align: 'center' });
  doc.fontSize(12).font('Helvetica-Bold').fillColor(COLORS.white)
     .text(formatDate(data.evidence?.timestamp), 0, boxY + 77, { align: 'center' });

  doc.fontSize(10).font('Helvetica').fillColor(COLORS.gray)
     .text('AUDIT ID', 0, boxY + 95, { align: 'center' });
  doc.fontSize(8).font('Helvetica').fillColor(COLORS.accent)
     .text(data.evidence?.auditId || 'N/A', 0, boxY + 108, { align: 'center' });

  // Score badge
  const score = data.score ?? 0;
  const grade = data.grade || {};
  doc.fontSize(10).fillColor(COLORS.gray)
     .text('SECURITY SCORE', 0, 650, { align: 'center' });
  doc.fontSize(48).font('Helvetica-Bold')
     .fillColor(grade.color || COLORS.accent)
     .text(`${score}`, 0, 668, { align: 'center' });
  doc.fontSize(16).fillColor(grade.color || COLORS.accent)
     .text(grade.grade || '-', 0, 720, { align: 'center' });

  // Footer
  doc.fontSize(8).font('Helvetica').fillColor(COLORS.grayDark)
     .text('DOCUMENTO CONFIDENCIAL — Gerado por Supabase Guard v2.0', 0, doc.page.height - 40, { align: 'center' });
  doc.fontSize(7).fillColor(COLORS.grayDark)
     .text(`SHA-256: ${data.evidence?.sha256 || 'N/A'}`, 0, doc.page.height - 28, { align: 'center' });
}

// ═══════════════════════════════════════════════════════════════════
//  2. TABLE OF CONTENTS
// ═══════════════════════════════════════════════════════════════════
function drawTableOfContents(doc, data) {
  newPage(doc, 'ÍNDICE');

  const items = [
    { num: '1', title: 'Sumário Executivo', desc: 'Visão geral da auditoria e resultados principais' },
    { num: '2', title: 'Security Score', desc: 'Score de segurança e classificação' },
    { num: '3', title: 'Stack Detectado', desc: 'Tecnologias identificadas no alvo' },
    { num: '4', title: 'O Que Verificamos', desc: 'Lista completa de verificações realizadas' },
    { num: '5', title: 'Vulnerabilidades Detalhadas', desc: 'Resultados categorizados por severidade' },
    { num: '6', title: 'Rotas Ocultas', desc: 'Endpoints e rotas descobertas' },
    { num: '7', title: 'Arquivos Sensíveis', desc: 'Documentos e credenciais expostas' },
    { num: '8', title: 'Insights & Recomendações', desc: 'Análise estratégica e ações recomendadas' },
    { num: '9', title: 'Evidência de Integridade', desc: 'Hash SHA-256 e ID de auditoria' },
  ];

  let y = doc.y + 20;
  for (const item of items) {
    doc.fontSize(14).font('Helvetica-Bold').fillColor(COLORS.accent)
       .text(item.num, 60, y);
    doc.fontSize(14).font('Helvetica-Bold').fillColor(COLORS.white)
       .text(item.title, 90, y);
    doc.fontSize(9).font('Helvetica').fillColor(COLORS.gray)
       .text(item.desc, 90, y + 18);

    // Dotted line
    y += 45;
    doc.rect(60, y - 5, doc.page.width - 120, 0.3).fill(COLORS.grayDark);
  }
}

// ═══════════════════════════════════════════════════════════════════
//  3. EXECUTIVE SUMMARY
// ═══════════════════════════════════════════════════════════════════
function drawExecutiveSummary(doc, data) {
  newPage(doc, '1. SUMÁRIO EXECUTIVO');

  const results = data.results || [];
  const critical = results.filter(r => r.severity === 'critical' && r.status === 'FAIL').length;
  const high = results.filter(r => r.severity === 'high' && r.status === 'FAIL').length;
  const medium = results.filter(r => r.severity === 'medium' && r.status === 'FAIL').length;
  const low = results.filter(r => r.severity === 'low' && r.status === 'FAIL').length;

  let y = doc.y;

  // Summary text
  doc.fontSize(10).font('Helvetica').fillColor(COLORS.white);
  doc.text(
    `A auditoria de segurança defensiva foi realizada no projeto Supabase "${data.projectUrl}" ` +
    `em ${formatDate(data.evidence?.timestamp)}. O scan analisou ${data.totalChecks || 0} ` +
    `controles de segurança em ${data.duration || 'N/A'}, cobrindo REST API, RPC, GraphQL, ` +
    `Storage, Edge Functions, Realtime, Auth, RLS, CORS, bundle exposure e análise profunda de dados.`,
    60, y, { width: doc.page.width - 120, lineGap: 4 }
  );

  y = doc.y + 20;

  // Stats boxes
  const boxW = (doc.page.width - 120) / 4;
  const boxes = [
    { label: 'Crítico', value: critical, color: COLORS.critical },
    { label: 'Alto', value: high, color: COLORS.high },
    { label: 'Médio', value: medium, color: COLORS.medium },
    { label: 'Baixo', value: low, color: COLORS.low },
  ];

  for (let i = 0; i < boxes.length; i++) {
    const bx = 60 + i * boxW;
    doc.rect(bx, y, boxW - 8, 50).lineWidth(0.5).stroke(COLORS.grayDark);
    doc.rect(bx, y, boxW - 8, 3).fill(boxes[i].color);
    doc.fontSize(22).font('Helvetica-Bold').fillColor(boxes[i].color)
       .text(String(boxes[i].value), bx + 10, y + 12, { width: boxW - 28 });
    doc.fontSize(8).font('Helvetica').fillColor(COLORS.gray)
       .text(boxes[i].label, bx + 10, y + 37, { width: boxW - 28 });
  }

  y += 70;

  // Overall stats
  const stats = [
    ['Total de verificações', `${data.totalChecks || 0}`],
    ['Aprovados', `${data.passed || 0}`],
    ['Falhas', `${data.failed || 0}`],
    ['Alertas', `${data.warnings || 0}`],
    ['Erros', `${data.errors || 0}`],
    ['Duração', `${data.duration || 'N/A'}`],
    ['Score', `${data.score || 0}/100 (${data.grade?.grade || '-'})`],
  ];

  doc.fontSize(11).font('Helvetica-Bold').fillColor(COLORS.accent)
     .text('Resumo Numérico', 60, y);
  y += 20;

  for (const [label, value] of stats) {
    doc.fontSize(9).font('Helvetica').fillColor(COLORS.gray)
       .text(label, 60, y, { continued: true, width: 200 });
    doc.font('Helvetica-Bold').fillColor(COLORS.white)
       .text(`  ${value}`, { width: 200 });
    y = doc.y + 3;
  }
}

// ═══════════════════════════════════════════════════════════════════
//  4. SECURITY SCORE
// ═══════════════════════════════════════════════════════════════════
function drawSecurityScore(doc, data) {
  newPage(doc, '2. SECURITY SCORE');

  let y = doc.y;
  const score = data.score ?? 0;
  const grade = data.grade || {};

  // Big score
  doc.fontSize(72).font('Helvetica-Bold')
     .fillColor(grade.color || COLORS.accent)
     .text(`${score}`, 60, y, { width: 200 });
  doc.fontSize(14).fillColor(COLORS.gray)
     .text('/100', 60, y + 68, { width: 200 });

  // Grade
  doc.fontSize(48).font('Helvetica-Bold')
     .fillColor(grade.color || COLORS.accent)
     .text(grade.grade || '-', 250, y + 10);
  doc.fontSize(14).fillColor(COLORS.white)
     .text(grade.label || '', 250, y + 60);

  y += 110;

  // Score bar
  const barWidth = doc.page.width - 120;
  doc.rect(60, y, barWidth, 12).fill(COLORS.grayDark);
  doc.rect(60, y, barWidth * (score / 100), 12).fill(grade.color || COLORS.accent);
  y += 30;

  // Score breakdown
  doc.fontSize(11).font('Helvetica-Bold').fillColor(COLORS.accent)
     .text('Distribuição por Severidade', 60, y);
  y += 20;

  const results = data.results || [];
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const sevLabels = { critical: 'Crítico', high: 'Alto', medium: 'Médio', low: 'Baixo', info: 'Info' };
  const sevPenalties = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };

  for (const sev of severities) {
    const fails = results.filter(r => r.severity === sev && (r.status === 'FAIL' || r.status === 'WARN'));
    const total = results.filter(r => r.severity === sev);
    const penalty = fails.length * sevPenalties[sev];

    doc.rect(60, y, 8, 8).fill(severityColor(sev));
    doc.fontSize(9).font('Helvetica-Bold').fillColor(COLORS.white)
       .text(`${sevLabels[sev]}`, 75, y, { width: 80 });
    doc.fontSize(9).font('Helvetica').fillColor(COLORS.gray)
       .text(`${total.length} checks, ${fails.length} falhas`, 160, y, { width: 180 });
    doc.fontSize(9).fillColor(COLORS.red)
       .text(penalty > 0 ? `-${penalty} pts` : '—', 350, y, { width: 80 });
    y += 16;
  }
}

// ═══════════════════════════════════════════════════════════════════
//  5. STACK DETECTED
// ═══════════════════════════════════════════════════════════════════
function drawStackDetected(doc, data) {
  newPage(doc, '3. STACK DETECTADO');

  let y = doc.y;

  // Find stack detection result
  const stackResult = (data.results || []).find(r => r.check === 'Stack Detection');
  const techs = stackResult?.details?.technologies || [];
  const categories = stackResult?.details?.categories || {};

  if (Object.keys(categories).length === 0) {
    doc.fontSize(10).font('Helvetica').fillColor(COLORS.gray)
       .text('Nenhuma tecnologia detectada ou módulo de detecção não executado.', 60, y);
    return;
  }

  for (const [category, items] of Object.entries(categories)) {
    checkPageSpace(doc, 60);
    y = doc.y;

    doc.fontSize(11).font('Helvetica-Bold').fillColor(COLORS.accent)
       .text(category, 60, y);
    y += 18;

    for (const item of items) {
      doc.rect(70, y + 3, 6, 6).fill(COLORS.blue);
      doc.fontSize(10).font('Helvetica').fillColor(COLORS.white)
         .text(item, 85, y, { width: doc.page.width - 140 });
      y += 16;
    }

    y += 8;
    doc.y = y;
  }

  // Total
  doc.fontSize(9).font('Helvetica').fillColor(COLORS.gray)
     .text(`Total: ${techs.length} tecnologia(s) detectada(s)`, 60, doc.y + 10);
}

// ═══════════════════════════════════════════════════════════════════
//  6. WHAT WE CHECKED
// ═══════════════════════════════════════════════════════════════════
function drawWhatWeChecked(doc, data) {
  newPage(doc, '4. O QUE VERIFICAMOS');

  const checkCategories = [
    {
      title: 'Verificações Base',
      checks: [
        'DNS & Conectividade — Acessibilidade, HTTPS, headers do servidor',
        'REST API — Exposição PostgREST, acesso a tabelas via anon key',
        'RPC Functions — Funções RPC expostas e sem autenticação',
        'GraphQL — Introspection habilitada e acesso a dados',
        'Storage — Buckets públicos, arquivos sensíveis, listagem',
        'Edge Functions — Descoberta e teste de autenticação',
        'Realtime — WebSocket acessível publicamente',
        'Auth — Configurações, signup, endpoints admin',
        '.env Exposure — Arquivos sensíveis em caminhos comuns',
        'RLS — Row Level Security ativo nas tabelas',
        'CORS — Configuração permissiva demais',
        'Service Key — Vazamento de service_role key',
        'JWT — Estrutura e configuração do token',
      ]
    },
    {
      title: 'Deep Analysis v1',
      checks: [
        'Source Code Analysis — 25+ padrões de secrets em código-fonte',
        'Hidden Routes — 200+ rotas em 9 categorias',
        'Vulnerability Scanner — XSS, CSRF, clickjacking, headers',
        'Sensitive Data — PII, dados financeiros, credenciais',
        'Error Detector — Erros 5xx, recursos quebrados, SSL',
      ]
    },
    {
      title: 'Deep Analysis v2',
      checks: [
        'Deep RLS — 60+ tabelas, write ops, IDOR detection',
        'REST/RPC Data Leak — 80+ tabelas, 50+ RPCs, content analysis',
        'Edge Function Role Control — JWT, webhooks, 100+ functions',
        'Bundle Key Scanner — 60+ key patterns (payment gateways, AI, cloud)',
        'Deep Storage — 50+ buckets, upload test, hidden bucket discovery',
        'Credential & PII — CPF, CNPJ, credit cards, emails, bank data',
        'Stack Detection — 60+ tecnologias fingerprinted',
      ]
    }
  ];

  for (const cat of checkCategories) {
    checkPageSpace(doc, 40 + cat.checks.length * 16);

    doc.fontSize(11).font('Helvetica-Bold').fillColor(COLORS.accent)
       .text(cat.title, 60, doc.y);
    doc.y += 5;

    for (const check of cat.checks) {
      checkPageSpace(doc, 18);
      const y = doc.y;
      doc.fontSize(8).fillColor(COLORS.pass).text('✓', 68, y);
      doc.fontSize(9).font('Helvetica').fillColor(COLORS.white)
         .text(check, 82, y, { width: doc.page.width - 140 });
      doc.y += 2;
    }

    doc.y += 10;
  }
}

// ═══════════════════════════════════════════════════════════════════
//  7. VULNERABILITY DETAILS
// ═══════════════════════════════════════════════════════════════════
function drawVulnerabilityDetails(doc, data) {
  newPage(doc, '5. VULNERABILIDADES DETALHADAS');

  const results = (data.results || []).filter(r => r.status === 'FAIL' || r.status === 'WARN');

  if (results.length === 0) {
    doc.fontSize(10).font('Helvetica').fillColor(COLORS.pass)
       .text('✓ Nenhuma vulnerabilidade encontrada.', 60, doc.y);
    return;
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  results.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  // Table header
  drawTableHeader(doc, ['Status', 'Severidade', 'Check', 'Descrição'], [50, 65, 130, 245]);

  for (const r of results) {
    checkPageSpace(doc, 35);
    const y = doc.y;

    // Alternating row background
    doc.rect(50, y, doc.page.width - 100, 28).fill('#0e0e18');

    doc.fontSize(8).font('Helvetica-Bold').fillColor(statusColor(r.status))
       .text(r.status, 55, y + 4, { width: 50 });
    doc.fontSize(8).font('Helvetica-Bold').fillColor(severityColor(r.severity))
       .text(r.severity.toUpperCase(), 108, y + 4, { width: 60 });
    doc.fontSize(8).font('Helvetica-Bold').fillColor(COLORS.white)
       .text(truncate(r.check, 30), 172, y + 4, { width: 125 });
    doc.fontSize(7).font('Helvetica').fillColor(COLORS.gray)
       .text(truncate(r.message, 80), 300, y + 2, { width: 240, height: 26 });

    doc.y = y + 30;
  }
}

function drawTableHeader(doc, headers, positions) {
  const y = doc.y;
  doc.rect(50, y, doc.page.width - 100, 20).fill(COLORS.accent);

  for (let i = 0; i < headers.length; i++) {
    doc.fontSize(8).font('Helvetica-Bold').fillColor('#000')
       .text(headers[i], positions[i] + 5, y + 5);
  }

  doc.y = y + 22;
}

// ═══════════════════════════════════════════════════════════════════
//  8. HIDDEN ROUTES TABLE
// ═══════════════════════════════════════════════════════════════════
function drawHiddenRoutes(doc, data) {
  newPage(doc, '6. ROTAS OCULTAS DESCOBERTAS');

  const routeResults = (data.results || []).filter(r =>
    r.check?.includes('Route') || r.check?.includes('Rota') || r.check?.includes('route') ||
    r.details?.routes || r.details?.discovered || r.details?.hiddenRoutes
  );

  // Also extract from any result that has route-like details
  const allRoutes = [];
  for (const r of data.results || []) {
    if (r.details?.routes && Array.isArray(r.details.routes)) {
      for (const route of r.details.routes) {
        allRoutes.push({
          path: route.path || route.url || route,
          status: route.status || route.statusCode || '—',
          type: route.category || route.type || '—',
        });
      }
    }
    if (r.details?.discovered && Array.isArray(r.details.discovered)) {
      for (const d of r.details.discovered) {
        allRoutes.push({
          path: d.path || d.url || d,
          status: d.status || d.statusCode || '—',
          type: d.category || d.type || '—',
        });
      }
    }
    if (r.details?.hiddenRoutes && Array.isArray(r.details.hiddenRoutes)) {
      for (const h of r.details.hiddenRoutes) {
        allRoutes.push({
          path: typeof h === 'string' ? h : h.path || h.url,
          status: h.status || '—',
          type: h.category || '—',
        });
      }
    }
  }

  // Also check for route data in detailed results
  for (const r of data.results || []) {
    if (r.details && typeof r.details === 'object') {
      for (const [key, val] of Object.entries(r.details)) {
        if (key.match(/route|path|endpoint|url/i) && typeof val === 'string' && val.startsWith('/')) {
          allRoutes.push({ path: val, status: '—', type: r.check });
        }
      }
    }
    // Check message for paths
    if (r.message && r.check?.includes('Route')) {
      const pathMatch = r.message.match(/(\/[a-zA-Z0-9_./-]+)/g);
      if (pathMatch) {
        for (const p of pathMatch) {
          allRoutes.push({ path: p, status: r.status, type: 'Discovered' });
        }
      }
    }
  }

  if (allRoutes.length === 0) {
    doc.fontSize(10).font('Helvetica').fillColor(COLORS.gray)
       .text('Nenhuma rota oculta foi descoberta durante a auditoria.', 60, doc.y);
    doc.fontSize(9).fillColor(COLORS.gray)
       .text('Isso pode indicar que o scan de rotas não foi executado ou que o site não possui ' +
             'endpoints expostos fora do padrão.', 60, doc.y + 5, { width: doc.page.width - 120 });
    return;
  }

  // Deduplicate
  const seen = new Set();
  const unique = allRoutes.filter(r => {
    const key = r.path;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  drawTableHeader(doc, ['Rota/Path', 'Status', 'Tipo'], [50, 330, 420]);

  for (const route of unique.slice(0, 60)) {
    checkPageSpace(doc, 20);
    const y = doc.y;

    doc.rect(50, y, doc.page.width - 100, 16).fill(y % 2 === 0 ? '#0e0e18' : '#11111c');

    doc.fontSize(7).font('Helvetica').fillColor(COLORS.white)
       .text(truncate(typeof route.path === 'string' ? route.path : JSON.stringify(route.path), 60), 55, y + 3, { width: 270 });
    doc.fontSize(7).fillColor(statusColor(String(route.status)))
       .text(String(route.status), 335, y + 3, { width: 80 });
    doc.fontSize(7).fillColor(COLORS.gray)
       .text(truncate(String(route.type), 25), 425, y + 3, { width: 110 });

    doc.y = y + 18;
  }

  doc.fontSize(8).fillColor(COLORS.gray)
     .text(`Total: ${unique.length} rota(s) descoberta(s)`, 60, doc.y + 5);
}

// ═══════════════════════════════════════════════════════════════════
//  9. SENSITIVE FILES
// ═══════════════════════════════════════════════════════════════════
function drawSensitiveFiles(doc, data) {
  newPage(doc, '7. ARQUIVOS SENSÍVEIS');

  const sensitiveResults = (data.results || []).filter(r =>
    r.check?.match(/sensit|file|storage|env|credential|pii|bundle|key/i) && r.status === 'FAIL'
  );

  const files = [];
  for (const r of sensitiveResults) {
    if (r.details?.files && Array.isArray(r.details.files)) {
      files.push(...r.details.files.map(f => ({
        name: typeof f === 'string' ? f : f.name || f.path || JSON.stringify(f),
        risk: r.severity,
        source: r.check
      })));
    }
    if (r.details?.findings && Array.isArray(r.details.findings)) {
      for (const f of r.details.findings) {
        files.push({
          name: f.type || f.name || 'Unknown',
          risk: f.severity || r.severity,
          source: f.source || r.check
        });
      }
    }
    if (r.details?.sensitiveFiles) {
      const sf = r.details.sensitiveFiles;
      if (Array.isArray(sf)) {
        files.push(...sf.map(f => ({
          name: typeof f === 'string' ? f : f.name || JSON.stringify(f),
          risk: r.severity,
          source: r.check
        })));
      }
    }
    // Fallback: use the result itself
    if (files.length === 0 && r.status === 'FAIL') {
      files.push({
        name: r.check,
        risk: r.severity,
        source: truncate(r.message, 60)
      });
    }
  }

  if (files.length === 0) {
    doc.fontSize(10).font('Helvetica').fillColor(COLORS.pass)
       .text('✓ Nenhum arquivo sensível exposto detectado.', 60, doc.y);
    return;
  }

  drawTableHeader(doc, ['Arquivo / Tipo', 'Risco', 'Fonte'], [50, 300, 380]);

  for (const file of files.slice(0, 50)) {
    checkPageSpace(doc, 20);
    const y = doc.y;

    doc.rect(50, y, doc.page.width - 100, 16).fill('#0e0e18');

    doc.fontSize(7).font('Helvetica').fillColor(COLORS.white)
       .text(truncate(file.name, 55), 55, y + 3, { width: 240 });
    doc.fontSize(7).font('Helvetica-Bold').fillColor(severityColor(file.risk))
       .text((file.risk || '—').toUpperCase(), 305, y + 3, { width: 70 });
    doc.fontSize(7).font('Helvetica').fillColor(COLORS.gray)
       .text(truncate(file.source, 30), 385, y + 3, { width: 150 });

    doc.y = y + 18;
  }

  doc.fontSize(8).fillColor(COLORS.gray)
     .text(`Total: ${files.length} arquivo(s)/tipo(s) sensível(is)`, 60, doc.y + 5);
}

// ═══════════════════════════════════════════════════════════════════
//  10. INSIGHTS & RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════
function drawInsights(doc, data) {
  newPage(doc, '8. INSIGHTS & RECOMENDAÇÕES');

  const results = data.results || [];
  const insights = generateInsights(data);

  for (const insight of insights) {
    checkPageSpace(doc, 60);
    const y = doc.y;

    // Insight card
    doc.rect(55, y, 4, 40).fill(insight.color);
    doc.fontSize(10).font('Helvetica-Bold').fillColor(insight.color)
       .text(insight.title, 68, y + 2, { width: doc.page.width - 130 });
    doc.fontSize(8).font('Helvetica').fillColor(COLORS.white)
       .text(insight.description, 68, y + 16, { width: doc.page.width - 130, lineGap: 2 });

    doc.y = y + 50;
  }
}

function generateInsights(data) {
  const results = data.results || [];
  const insights = [];
  const score = data.score ?? 0;
  const critical = results.filter(r => r.severity === 'critical' && r.status === 'FAIL');
  const high = results.filter(r => r.severity === 'high' && r.status === 'FAIL');

  // Score-based insights
  if (score < 30) {
    insights.push({
      title: '🚨 ALERTA MÁXIMO — Score Abaixo de 30',
      description: 'O projeto apresenta vulnerabilidades graves que requerem ação imediata. ' +
                   'Recomenda-se desabilitar o acesso público até que as correções sejam aplicadas.',
      color: COLORS.critical
    });
  } else if (score < 60) {
    insights.push({
      title: '⚠️ Risco Elevado — Correções Urgentes Necessárias',
      description: 'Múltiplas vulnerabilidades foram encontradas. Priorize correções de severidade crítica e alta.',
      color: COLORS.orange
    });
  } else if (score >= 90) {
    insights.push({
      title: '✅ Excelente Postura de Segurança',
      description: 'O projeto demonstra boas práticas de segurança. Continue monitorando regularmente.',
      color: COLORS.pass
    });
  }

  // RLS insights
  const rlsFails = results.filter(r => r.check?.match(/rls/i) && r.status === 'FAIL');
  if (rlsFails.length > 0) {
    insights.push({
      title: '🔒 Row Level Security (RLS)',
      description: `${rlsFails.length} tabelas sem RLS adequado. Qualquer usuário com a anon key pode ler/escrever dados. ` +
                   'Configure políticas RLS no Supabase Dashboard: Authentication > Policies.',
      color: COLORS.red
    });
  }

  // Credential exposure
  const credFails = results.filter(r =>
    r.check?.match(/credential|key|token|bundle|service/i) && r.status === 'FAIL'
  );
  if (credFails.length > 0) {
    insights.push({
      title: '🔑 Credenciais Expostas',
      description: `${credFails.length} credencial(is) detectada(s) em superfícies públicas. ` +
                   'Rotacione todas as chaves imediatamente e mova segredos para variáveis de ambiente do servidor.',
      color: COLORS.critical
    });
  }

  // PII/Data exposure
  const piiFails = results.filter(r =>
    r.check?.match(/pii|document|email|cpf|cnpj|dado|data/i) && r.status === 'FAIL'
  );
  if (piiFails.length > 0) {
    insights.push({
      title: '📋 Dados Pessoais Expostos (LGPD/GDPR)',
      description: `${piiFails.length} tipo(s) de dados pessoais encontrados expostos. ` +
                   'Isso pode configurar violação de LGPD/GDPR. Implemente mascaramento de dados e RLS.',
      color: COLORS.orange
    });
  }

  // Storage
  const storageFails = results.filter(r => r.check?.match(/storage/i) && r.status === 'FAIL');
  if (storageFails.length > 0) {
    insights.push({
      title: '📦 Storage Público Desprotegido',
      description: 'Buckets de storage permitem leitura ou listagem pública. ' +
                   'Configure políticas de acesso no Supabase Dashboard: Storage > Policies.',
      color: COLORS.orange
    });
  }

  // Edge Functions
  const edgeFails = results.filter(r => r.check?.match(/edge|function/i) && r.status === 'FAIL');
  if (edgeFails.length > 0) {
    insights.push({
      title: '⚡ Edge Functions Sem Controle de Role',
      description: 'Edge Functions acessíveis sem autenticação. Adicione verificação de JWT e role checking.',
      color: COLORS.orange
    });
  }

  // General best practices
  insights.push({
    title: '📋 Próximos Passos Recomendados',
    description: '1. Corrija todas as vulnerabilidades CRITICAL imediatamente\n' +
                 '2. Revise e aplique RLS em todas as tabelas\n' +
                 '3. Rotacione chaves e tokens expostos\n' +
                 '4. Configure CORS restritivo\n' +
                 '5. Execute esta auditoria novamente após as correções\n' +
                 '6. Implemente monitoramento contínuo',
    color: COLORS.blue
  });

  return insights;
}

// ═══════════════════════════════════════════════════════════════════
//  11. EVIDENCE
// ═══════════════════════════════════════════════════════════════════
function drawEvidence(doc, data) {
  newPage(doc, '9. EVIDÊNCIA DE INTEGRIDADE');

  let y = doc.y;

  doc.fontSize(10).font('Helvetica').fillColor(COLORS.white)
     .text('Este relatório foi gerado automaticamente pelo Supabase Guard e assinado ' +
           'com SHA-256 para garantir integridade. O hash abaixo pode ser verificado contra ' +
           'o relatório JSON para confirmar que os dados não foram alterados.', 60, y, {
       width: doc.page.width - 120, lineGap: 3
     });

  y = doc.y + 20;

  const evidence = [
    ['Audit ID', data.evidence?.auditId || 'N/A'],
    ['SHA-256 Hash', data.evidence?.sha256 || 'N/A'],
    ['Timestamp', data.evidence?.timestamp || 'N/A'],
    ['Projeto', data.projectUrl || 'N/A'],
    ['Score Final', `${data.score || 0}/100 (${data.grade?.grade || '-'})`],
    ['Duração Total', data.duration || 'N/A'],
    ['Total de Checks', `${data.totalChecks || 0}`],
    ['Engine', 'Supabase Guard v2.0 — Node.js + Express'],
  ];

  for (const [label, value] of evidence) {
    checkPageSpace(doc, 25);
    y = doc.y;

    doc.rect(60, y, doc.page.width - 120, 22).fill('#0e0e18');
    doc.fontSize(8).font('Helvetica-Bold').fillColor(COLORS.gray)
       .text(label, 70, y + 5, { width: 120 });
    doc.fontSize(8).font('Helvetica').fillColor(COLORS.accent)
       .text(value, 200, y + 5, { width: doc.page.width - 270 });

    doc.y = y + 24;
  }

  doc.y += 20;
  doc.fontSize(8).font('Helvetica').fillColor(COLORS.grayDark)
     .text('Este documento é confidencial e destinado apenas ao proprietário do projeto auditado.', 60, doc.y, {
       width: doc.page.width - 120, align: 'center'
     });
}

// ── Footer on all pages ──────────────────────────────────────────
function drawFooterOnAllPages(doc) {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);

    // Bottom line
    doc.rect(50, doc.page.height - 35, doc.page.width - 100, 0.5).fill(COLORS.grayDark);

    // Page number
    doc.fontSize(7).font('Helvetica').fillColor(COLORS.grayDark)
       .text(
         `Supabase Guard — Relatório de Auditoria de Segurança  |  Página ${i + 1} de ${range.count}`,
         50, doc.page.height - 25,
         { width: doc.page.width - 100, align: 'center' }
       );
  }
}

// ── Utilities ────────────────────────────────────────────────────
function formatDate(iso) {
  if (!iso) return new Date().toLocaleString('pt-BR');
  try {
    return new Date(iso).toLocaleString('pt-BR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch {
    return iso;
  }
}

function truncate(str, max) {
  if (!str) return '';
  str = String(str);
  return str.length > max ? str.substring(0, max - 3) + '...' : str;
}

module.exports = { generatePDFReport };
