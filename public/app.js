/* ═══════════════════════════════════════════════════════════════════
   SUPABASE GUARD — Frontend Application Logic v2.0
   Handles audit execution, SSE streaming, report generation,
   PDF/HTML reports, charts, and site scraper
   ═══════════════════════════════════════════════════════════════════ */

let auditResults = null;
let logLines = [];
let isScanning = false;

// ── DOM Elements ─────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Start Audit ──────────────────────────────────────────────────
async function startAudit() {
  if (isScanning) return;

  const url = $('#projectUrl').value.trim();
  if (!url) {
    appendLog('error', 'ERROR', 'Insira a URL do projeto Supabase.');
    return;
  }

  isScanning = true;
  auditResults = null;
  logLines = [];

  // UI state
  const btn = $('#btnAudit');
  btn.disabled = true;
  btn.classList.add('scanning');
  btn.innerHTML = `<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Escaneando...`;

  setStatus('scanning', 'Scanning');
  $('#consoleUrl').textContent = `scan://${url.replace(/https?:\/\//, '')}`;
  clearConsole();

  // Hide previous results
  $('#scoreSection').style.display = 'none';
  $('#resultsSection').style.display = 'none';
  $('#evidenceSection').style.display = 'none';

  // Show progress
  $('#progressContainer').style.display = 'block';
  updateProgress(0, 0);

  appendLog('info', 'INIT', `Iniciando auditoria em: ${url}`);
  appendLog('info', 'MODE', 'Role: GUEST (anon key)');

  // Gather options
  const anonKey = $('#anonKey')?.value?.trim() || '';
  const options = {
    checkREST: $('#chkREST')?.checked ?? true,
    checkRPC: $('#chkRPC')?.checked ?? true,
    checkGraphQL: $('#chkGraphQL')?.checked ?? true,
    checkStorage: $('#chkStorage')?.checked ?? true,
    checkEdgeFunctions: $('#chkEdge')?.checked ?? true,
    checkRealtime: $('#chkRealtime')?.checked ?? true,
    checkAuth: $('#chkAuth')?.checked ?? true,
    checkEnvExposure: $('#chkEnv')?.checked ?? true,
    checkRLS: $('#chkRLS')?.checked ?? true,
    checkCORS: $('#chkCORS')?.checked ?? true,
    // Deep Analysis
    checkDeepSource: $('#chkDeepSource')?.checked ?? true,
    checkDeepRoutes: $('#chkDeepRoutes')?.checked ?? true,
    checkDeepVuln: $('#chkDeepVuln')?.checked ?? true,
    checkDeepSensitive: $('#chkDeepSensitive')?.checked ?? true,
    checkDeepErrors: $('#chkDeepErrors')?.checked ?? true,
    // Deep Analysis v2
    checkDeepRLS: $('#chkDeepRLS')?.checked ?? true,
    checkDeepRESTRPC: $('#chkDeepRESTRPC')?.checked ?? true,
    checkDeepEdge: $('#chkDeepEdge')?.checked ?? true,
    checkDeepBundleKeys: $('#chkDeepBundleKeys')?.checked ?? true,
    checkDeepStorage: $('#chkDeepStorage')?.checked ?? true,
    checkDeepCredPII: $('#chkDeepCredPII')?.checked ?? true,
    userMode: document.querySelector('input[name="roleMode"]:checked')?.value === 'both'
  };

  try {
    const response = await fetch('/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, anonKey, options })
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const event = JSON.parse(line.slice(6));
            handleEvent(event);
          } catch {}
        }
      }
    }

    // Process remaining buffer
    if (buffer.startsWith('data: ')) {
      try {
        const event = JSON.parse(buffer.slice(6));
        handleEvent(event);
      } catch {}
    }

  } catch (err) {
    appendLog('error', 'ERROR', `Falha na conexão: ${err.message}`);
    setStatus('error', 'Error');
  }

  // Reset button
  isScanning = false;
  btn.disabled = false;
  btn.classList.remove('scanning');
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Iniciar Auditoria`;
}

// ── Handle SSE Events ────────────────────────────────────────────
function handleEvent(event) {
  switch (event.type) {
    case 'start':
      appendLog('info', 'START', event.message);
      break;

    case 'info':
      appendLog('info', 'INFO', event.message);
      break;

    case 'progress':
      appendLog('progress', 'SCAN', event.message);
      if (event.step && event.total) {
        updateProgress(event.step, event.total);
      }
      break;

    case 'result':
      handleResult(event.data);
      break;

    case 'complete':
      handleComplete(event.results);
      break;

    case 'error':
      appendLog('error', 'ERROR', event.message);
      setStatus('error', 'Error');
      break;

    case 'log':
      const logLevel = event.level === 'warn' ? 'warn' : 'info';
      appendLog(logLevel, event.level === 'warn' ? 'WARN' : 'LOG', event.message);
      break;
  }
}

// ── Handle Individual Result ─────────────────────────────────────
function handleResult(result) {
  const typeMap = {
    'PASS': 'pass',
    'FAIL': 'fail',
    'WARN': 'warn',
    'ERROR': 'error',
    'INFO': 'info'
  };

  const prefix = result.status || 'INFO';
  const cssClass = typeMap[prefix] || 'info';

  appendLog(cssClass, prefix, `[${result.check}] ${result.message}`);
}

// ── Handle Audit Complete ────────────────────────────────────────
function handleComplete(results) {
  auditResults = results;

  appendLog('info', '─────', '─────────────────────────────────────');
  appendLog('info', 'DONE', `Auditoria concluída em ${results.duration}`);
  appendLog('info', 'SCORE', `${results.score}/100 (${results.grade.grade} — ${results.grade.label})`);
  appendLog('info', 'HASH', `SHA-256: ${results.evidence.sha256}`);
  appendLog('info', 'ID', `Audit ID: ${results.evidence.auditId}`);

  setStatus('complete', 'Complete');
  updateProgress(results.totalChecks, results.totalChecks);

  // Show results UI
  showScoreCard(results);
  showResultsList(results.results);
  showEvidence(results);
}

// ── Score Card ───────────────────────────────────────────────────
function showScoreCard(results) {
  const section = $('#scoreSection');
  section.style.display = 'block';

  // Animate score circle
  const arc = $('#scoreArc');
  const circumference = 2 * Math.PI * 54; // r=54
  const offset = circumference - (results.score / 100) * circumference;
  
  arc.style.stroke = results.grade.color;
  setTimeout(() => {
    arc.style.transition = 'stroke-dashoffset 1.5s ease';
    arc.style.strokeDashoffset = offset;
  }, 100);

  // Animate number
  animateNumber($('#scoreNumber'), 0, results.score, 1500);

  const gradeEl = $('#scoreGrade');
  gradeEl.textContent = results.grade.grade;
  gradeEl.style.color = results.grade.color;

  $('#scoreTitle').textContent = `Security Score — ${results.grade.label}`;
  $('#scoreTitle').style.color = results.grade.color;

  $('#statPass').textContent = results.passed;
  $('#statFail').textContent = results.failed;
  $('#statWarn').textContent = results.warnings;
  $('#statInfo').textContent = results.info + results.errors;

  $('#scoreMeta').textContent = 
    `Projeto: ${results.projectUrl} | Duração: ${results.duration} | ${results.totalChecks} verificações | ${new Date().toLocaleString('pt-BR')}`;

  // Scroll to score
  section.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// ── Results List ─────────────────────────────────────────────────
function showResultsList(results) {
  const section = $('#resultsSection');
  section.style.display = 'block';

  const list = $('#resultsList');
  list.innerHTML = '';

  // Sort: critical first, then by status
  const sorted = [...results].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const statusOrder = { FAIL: 0, WARN: 1, ERROR: 2, INFO: 3, PASS: 4 };
    
    const aSev = severityOrder[a.severity] ?? 5;
    const bSev = severityOrder[b.severity] ?? 5;
    if (aSev !== bSev) return aSev - bSev;
    
    const aStat = statusOrder[a.status] ?? 5;
    const bStat = statusOrder[b.status] ?? 5;
    return aStat - bStat;
  });

  for (const result of sorted) {
    const item = document.createElement('div');
    item.className = `result-item severity-${result.severity}`;
    item.dataset.status = result.status;

    item.innerHTML = `
      <div class="result-header">
        <span class="result-check">${escapeHtml(result.check)}</span>
        <div class="result-badges">
          <span class="result-status ${result.status}">${result.status}</span>
          <span class="result-severity">${result.severity}</span>
        </div>
      </div>
      <div class="result-message">${escapeHtml(result.message)}</div>
      ${result.details ? `
        <div class="result-details">
          <pre>${escapeHtml(JSON.stringify(result.details, null, 2))}</pre>
        </div>
      ` : ''}
    `;

    item.addEventListener('click', () => {
      const details = item.querySelector('.result-details');
      if (details) details.classList.toggle('open');
    });

    list.appendChild(item);
  }
}

// ── Evidence Section ─────────────────────────────────────────────
function showEvidence(results) {
  const section = $('#evidenceSection');
  section.style.display = 'block';

  const details = $('#evidenceDetails');
  details.innerHTML = `
    <div class="evidence-line"><span class="evidence-key">Audit ID:</span> ${results.evidence.auditId}</div>
    <div class="evidence-line"><span class="evidence-key">SHA-256:</span> ${results.evidence.sha256}</div>
    <div class="evidence-line"><span class="evidence-key">Timestamp:</span> ${results.evidence.timestamp}</div>
    <div class="evidence-line"><span class="evidence-key">Projeto:</span> ${results.projectUrl}</div>
    <div class="evidence-line"><span class="evidence-key">Score:</span> ${results.score}/100 (${results.grade.grade})</div>
    <div class="evidence-line"><span class="evidence-key">Duração:</span> ${results.duration}</div>
    <div class="evidence-line"><span class="evidence-key">Verificações:</span> ${results.totalChecks}</div>
  `;
}

// ── Filter Results ───────────────────────────────────────────────
function filterResults(status) {
  $$('.filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  $$('.result-item').forEach(item => {
    if (status === 'all' || item.dataset.status === status) {
      item.style.display = '';
    } else {
      item.style.display = 'none';
    }
  });
}

// ── Console Helpers ──────────────────────────────────────────────
function appendLog(type, prefix, message) {
  const output = $('#consoleOutput');
  
  // Remove cursor
  const cursor = output.querySelector('.console-cursor');
  if (cursor) cursor.remove();

  const line = document.createElement('div');
  line.className = `console-line ${type}`;
  line.innerHTML = `<span class="line-prefix">[${escapeHtml(prefix)}]</span><span>${escapeHtml(message)}</span>`;
  output.appendChild(line);

  // Add cursor back
  const newCursor = document.createElement('div');
  newCursor.className = 'console-cursor';
  newCursor.textContent = '█';
  output.appendChild(newCursor);

  // Auto scroll
  output.scrollTop = output.scrollHeight;

  // Store for copy
  logLines.push(`[${prefix}] ${message}`);
}

function clearConsole() {
  const output = $('#consoleOutput');
  output.innerHTML = '<div class="console-cursor">█</div>';
  logLines = [];
}

function setStatus(state, text) {
  const dot = $('#statusIndicator .status-dot');
  dot.className = `status-dot ${state}`;
  $('#statusText').textContent = text;
}

function updateProgress(current, total) {
  if (total === 0) return;
  const pct = Math.round((current / total) * 100);
  $('#progressBar').style.width = `${pct}%`;
  $('#progressText').textContent = `${pct}%`;
}

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  const update = (now) => {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

// ── Copy Logs ────────────────────────────────────────────────────
function copyLogs() {
  const text = logLines.join('\n');
  navigator.clipboard.writeText(text).then(() => {
    const btn = $('.console-controls .btn-icon');
    btn.style.color = 'var(--accent)';
    setTimeout(() => btn.style.color = '', 1500);
  });
}

// ── Download Report JSON ─────────────────────────────────────────
function downloadReport() {
  if (!auditResults) return;

  const blob = new Blob([JSON.stringify(auditResults, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `supabase-audit-${auditResults.evidence.auditId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Download PDF Report ──────────────────────────────────────────
async function downloadReportPDF() {
  if (!auditResults) return;

  appendLog('info', 'PDF', 'Gerando relatório PDF profissional...');

  try {
    const response = await fetch('/api/report/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auditData: auditResults })
    });

    if (!response.ok) throw new Error('Falha ao gerar PDF');

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `supabase-guard-report-${auditResults.evidence.auditId}.pdf`;
    a.click();
    URL.revokeObjectURL(url);

    appendLog('info', 'PDF', '✓ Relatório PDF baixado com sucesso!');
  } catch (err) {
    appendLog('error', 'PDF', `Erro: ${err.message}`);
  }
}

// ── Download HTML Report ─────────────────────────────────────────
async function downloadReportHTML() {
  if (!auditResults) return;

  appendLog('info', 'HTML', 'Gerando relatório HTML com gráficos...');

  try {
    const response = await fetch('/api/report/html', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auditData: auditResults })
    });

    if (!response.ok) throw new Error('Falha ao gerar HTML');

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `supabase-guard-report-${auditResults.evidence.auditId}.html`;
    a.click();
    URL.revokeObjectURL(url);

    appendLog('info', 'HTML', '✓ Relatório HTML baixado com sucesso!');
  } catch (err) {
    appendLog('error', 'HTML', `Erro: ${err.message}`);
  }
}

// ── View HTML Report in Browser ──────────────────────────────────
async function viewReportHTML() {
  if (!auditResults) return;

  try {
    const response = await fetch('/api/report/html/view', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auditData: auditResults })
    });

    if (!response.ok) throw new Error('Falha');

    const html = await response.text();
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
  } catch (err) {
    appendLog('error', 'VIEW', `Erro: ${err.message}`);
  }
}

// ── Download Site Source Code (ZIP) ──────────────────────────────
async function downloadSourceCode() {
  const url = $('#projectUrl').value.trim();
  if (!url) {
    appendLog('error', 'SCRAPE', 'Insira a URL do projeto primeiro.');
    return;
  }

  appendLog('info', 'SCRAPE', 'Iniciando download do código-fonte...');
  const btn = $('#btnScrape');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Baixando...';
  }

  try {
    const response = await fetch('/api/scrape', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error('Falha no download');

    const blob = await response.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `source-code-${url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-')}.zip`;
    a.click();
    URL.revokeObjectURL(blobUrl);

    appendLog('info', 'SCRAPE', `✓ Código-fonte baixado! (${(blob.size / 1024 / 1024).toFixed(2)} MB)`);
  } catch (err) {
    appendLog('error', 'SCRAPE', `Erro: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '📥 Download Código-Fonte (ZIP)';
    }
  }
}

// ── View Audit Info Page ─────────────────────────────────────────
function viewAuditPage() {
  if (!auditResults?.evidence?.auditId) return;
  window.open(`/audit/${auditResults.evidence.auditId}`, '_blank');
}

// ── Modals ───────────────────────────────────────────────────────
function showTerms() {
  $('#modalBody').innerHTML = `
    <h2>Termos de Uso e Limitação de Responsabilidade</h2>
    <p>Ao utilizar o Supabase Guard, você concorda com os seguintes termos:</p>
    <ul>
      <li><strong>Uso Ético:</strong> Esta ferramenta destina-se exclusivamente a auditorias defensivas de segurança em projetos que você possui ou tem autorização explícita para testar.</li>
      <li><strong>Sem Garantias:</strong> Os resultados são fornecidos "como estão", sem garantia de completude. A ausência de vulnerabilidades detectadas não garante segurança total.</li>
      <li><strong>Responsabilidade:</strong> O uso indevido desta ferramenta para acessar sistemas sem autorização é ilegal. O usuário é inteiramente responsável pelo uso da ferramenta.</li>
      <li><strong>Dados:</strong> As URLs e chaves fornecidas são processadas em tempo real e não são armazenadas permanentemente no servidor.</li>
      <li><strong>Rate Limiting:</strong> A ferramenta faz múltiplas requisições ao projeto alvo. Use com moderação para não sobrecarregar servidores.</li>
      <li><strong>Evidência:</strong> O hash SHA-256 do relatório serve como prova de integridade, não como prova legal.</li>
    </ul>
    <p><strong>Ao clicar em "Iniciar Auditoria", você declara ter autorização para testar o projeto informado.</strong></p>
  `;
  $('#modalOverlay').style.display = 'flex';
}

function showHowItWorks() {
  $('#modalBody').innerHTML = `
    <h2>Como a Auditoria Funciona</h2>
    <p>O Supabase Guard executa uma série de verificações de segurança não-intrusivas no seu projeto Supabase:</p>
    
    <h3 style="color: var(--text-secondary); margin-top: 1rem;">Verificações Base</h3>
    <ul>
      <li><strong>DNS & Connectivity:</strong> Verifica acessibilidade, HTTPS e headers do servidor.</li>
      <li><strong>REST API:</strong> Testa se PostgREST está exposto e se tabelas são acessíveis via <code>anon</code> key.</li>
      <li><strong>RPC Functions:</strong> Enumera funções RPC comuns que podem estar expostas.</li>
      <li><strong>GraphQL:</strong> Testa se pg_graphql permite introspection e acesso a dados.</li>
      <li><strong>Storage:</strong> Verifica buckets públicos, arquivos sensíveis e listagem sem auth.</li>
      <li><strong>Edge Functions:</strong> Descobre Edge Functions e testa se requerem autenticação.</li>
      <li><strong>Realtime:</strong> Verifica se WebSocket Realtime está acessível publicamente.</li>
      <li><strong>Auth:</strong> Analisa configurações de autenticação, signup, OTP e endpoints admin.</li>
      <li><strong>.env Exposure:</strong> Busca arquivos sensíveis (.env, config, etc.) em caminhos comuns.</li>
      <li><strong>RLS:</strong> Testa se Row Level Security está ativo nas tabelas detectadas.</li>
      <li><strong>CORS:</strong> Verifica se a configuração CORS é permissiva demais.</li>
      <li><strong>Service Key:</strong> Detecta vazamento de <code>service_role</code> key em recursos públicos.</li>
      <li><strong>JWT:</strong> Analisa a estrutura e configuração do token JWT.</li>
    </ul>

    <h3 style="color: var(--accent); margin-top: 1rem;">🔬 Deep Analysis Modules</h3>
    <ul>
      <li><strong>🔍 Source Code Analysis:</strong> Escaneia código-fonte (HTML, JS, CSS) buscando 25+ padrões de secrets (AWS, Stripe, JWT, passwords, API keys), 18+ padrões inseguros (eval, innerHTML, SQL injection), source maps e stack traces.</li>
      <li><strong>🗺️ Hidden Route Discovery:</strong> Testa 200+ rotas comuns em 9 categorias (admin, API, debug, auth, git, config, backup, Next.js, WordPress). Detecta rotas ocultas, quebradas e extrai rotas de código JS.</li>
      <li><strong>🛡️ Vulnerability Scanner:</strong> Testa XSS refletido, open redirect, CSRF, clickjacking, headers de segurança, métodos HTTP perigosos, information disclosure, cookies inseguros, rate limiting e fingerprinting de tecnologias.</li>
      <li><strong>🔐 Sensitive Data Detector:</strong> Detecta PII (CPF, CNPJ, SSN, emails, telefones), dados financeiros (cartões de crédito, Stripe keys), credenciais, URLs internas, campos sensíveis em respostas API e arquivos sensíveis em storage.</li>
      <li><strong>🐛 Error Detector:</strong> Detecta erros 5xx, recursos quebrados (scripts, links, imagens), erros em código JavaScript (eval, innerHTML, debugger, secrets hardcoded), problemas SSL/TLS, mixed content e vazamento de informações em erros da API.</li>
    </ul>

    <p style="margin-top: 1rem;"><strong>Todas as verificações são feitas como GUEST (usando anon key ou sem autenticação), simulando o que um atacante externo poderia descobrir.</strong></p>
    <p>Os resultados são assinados com SHA-256 para garantir integridade. Logs em tempo real mostram o progresso de cada módulo.</p>
  `;
  $('#modalOverlay').style.display = 'flex';
}

function closeModal() {
  $('#modalOverlay').style.display = 'none';
}

// ── Utilities ────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Keyboard shortcuts ──────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && e.target.id === 'projectUrl') {
    startAudit();
  }
  if (e.key === 'Escape') {
    closeModal();
  }
});

// ── Add CSS for spin animation ──────────────────────────────────
const style = document.createElement('style');
style.textContent = `
  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  .spin { animation: spin 1s linear infinite; }
`;
document.head.appendChild(style);

// ═══════════════════════════════════════════════════════════════════
// AI Chat Functions
// ═══════════════════════════════════════════════════════════════════

let currentAuditId = null;

function showAIChat() {
  $('#aiChatSection').style.display = 'block';
  $('#aiChatSection').scrollIntoView({ behavior: 'smooth' });
  
  // Also show floating button
  $('#floatingAIBtn').classList.add('show');
}

async function sendAIQuestion(question) {
  const input = $('#aiQuestion');
  const questionText = question || input.value.trim();
  
  if (!questionText) return;
  
  if (!currentAuditId && !auditResults) {
    appendLog('error', 'ERROR', 'Execute uma auditoria primeiro.');
    return;
  }
  
  // Add user message to chat
  addAIMessage('user', questionText);
  input.value = '';
  
  // Show typing indicator
  showAITyping();
  
  // Send to API
  try {
    const response = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        auditId: currentAuditId,
        question: questionText
      })
    });
    
    removeAITyping();
    
    if (!response.ok) {
      const error = await response.json();
      addAIMessage('bot', `Erro: ${error.error || 'Falha ao conectar com a IA'}`);
      return;
    }
    
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let botResponse = '';
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      const chunk = decoder.decode(value);
      const lines = chunk.split('\n');
      
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === 'chunk' && data.content) {
              botResponse += data.content;
              updateBotMessage(botResponse);
            } else if (data.type === 'error') {
              addAIMessage('bot', `Erro: ${data.message}`);
              return;
            }
          } catch {}
        }
      }
    }
    
    if (botResponse) {
      updateBotMessage(botResponse);
    } else {
      addAIMessage('bot', 'Desculpe, não consegui gerar uma resposta. Tente novamente.');
    }
  } catch (error) {
    removeAITyping();
    addAIMessage('bot', `Erro de conexão: ${error.message}`);
  }
}

function addAIMessage(role, content) {
  const messages = $('#aiMessages');
  const div = document.createElement('div');
  div.className = `ai-message ai-message-${role}`;
  div.innerHTML = `
    <div class="ai-avatar">
      ${role === 'bot' 
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/><circle cx="12" cy="12" r="3"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
      }
    </div>
    <div class="ai-message-content">
      ${formatAIMessage(content)}
    </div>
  `;
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

let botMessageElement = null;

function showAITyping() {
  const messages = $('#aiMessages');
  botMessageElement = document.createElement('div');
  botMessageElement.className = 'ai-message ai-message-bot';
  botMessageElement.id = 'botTyping';
  botMessageElement.innerHTML = `
    <div class="ai-avatar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/><circle cx="12" cy="12" r="3"/></svg>
    </div>
    <div class="ai-typing">
      <span></span><span></span><span></span>
    </div>
  `;
  messages.appendChild(botMessageElement);
  messages.scrollTop = messages.scrollHeight;
}

function removeAITyping() {
  const typing = $('#botTyping');
  if (typing) typing.remove();
}

function updateBotMessage(content) {
  if (botMessageElement) {
    botMessageElement.innerHTML = `
      <div class="ai-avatar">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/><circle cx="12" cy="12" r="3"/></svg>
      </div>
      <div class="ai-message-content">
        ${formatAIMessage(content)}
      </div>
    `;
    $('#aiMessages').scrollTop = $('#aiMessages').scrollHeight;
  }
}

function formatAIMessage(text) {
  if (!text) return '';
  
  // Escape HTML
  text = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  
  // Format code blocks
  text = text.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  
  // Format inline code
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // Format bold
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  
  // Format line breaks
  text = text.replace(/\n\n/g, '</p><p>');
  text = text.replace(/\n/g, '<br>');
  
  // Format lists
  text = text.replace(/^- (.+)$/gm, '<li>$1</li>');
  text = text.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
  
  return `<p>${text}</p>`;
}

// Override showResults to set audit ID
const originalShowResults = typeof showResults === 'function' ? showResults : null;

function showResults(results, score, grade, duration, evidence) {
  if (originalShowResults) {
    originalShowResults(results, score, grade, duration, evidence);
  }
  
  // Store audit ID for AI chat
  if (evidence && evidence.auditId) {
    currentAuditId = evidence.auditId;
    console.log('AI Chat enabled with Audit ID:', currentAuditId);
  }
  
  // Show AI Chat section
  showAIChat();
  
  // Clear previous chat
  const messages = $('#aiMessages');
  messages.innerHTML = `
    <div class="ai-message ai-message-bot">
      <div class="ai-avatar">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
          <path d="M12 2a10 10 0 1 0 10 10H12V2z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      </div>
      <div class="ai-message-content">
        <p>Auditoria concluída! Agora você pode conversar comigo sobre os resultados.</p>
        <p>Posso analisar:</p>
        <ul>
          <li>🔴 <strong>Vulnerabilidades críticas</strong> encontradas</li>
          <li>🔑 <strong>Chaves e tokens</strong> expostos no site</li>
          <li>🛠️ <strong>Como corrigir</strong> cada problema</li>
          <li>📊 <strong>Detalhes técnicos</strong> da exposição</li>
        </ul>
        <p><em>Exemplo: "Quais são as chaves de API expostas?"</em></p>
      </div>
    </div>
  `;
}
