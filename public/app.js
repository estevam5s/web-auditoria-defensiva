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
  matrixSetScanning(true);

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

  // Parse custom headers JSON
  let customHeaders = {};
  try {
    const raw = $('#customHeaders')?.value?.trim();
    if (raw) customHeaders = JSON.parse(raw);
  } catch { /* ignore invalid JSON */ }

  // Parse custom wordlist
  const customWordlist = ($('#customWordlist')?.value || '')
    .split('\n')
    .map(s => s.trim())
    .filter(s => s.startsWith('/'));

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
    userMode: document.querySelector('input[name="roleMode"]:checked')?.value === 'both',
    // Advanced options
    crawlDepth: parseInt($('#crawlDepth')?.value || '2'),
    requestTimeout: parseInt($('#reqTimeout')?.value || '10000'),
    requestDelay: parseInt($('#reqDelay')?.value || '0'),
    bearerToken: $('#bearerToken')?.value?.trim() || '',
    customHeaders,
    customWordlist,
    checkDDoS: $('#chkDDoS')?.checked ?? true,
    checkBruteForce: $('#chkBruteForce')?.checked ?? true,
    checkSecurityHeaders: $('#chkSecurityHeaders')?.checked ?? true,
    checkSSL: $('#chkSSL')?.checked ?? true,
    checkGitExposure: $('#chkGitExposure')?.checked ?? true,
    checkOpenRedirect: $('#chkOpenRedirect')?.checked ?? true,
    crawlSubdomains: $('#chkSubdomains')?.checked ?? false,
    checkScreenshot: $('#chkScreenshot')?.checked ?? false,
    passiveMode: $('#chkPassive')?.checked ?? false,
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
  matrixSetScanning(false);
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
  currentAuditId = results.evidence?.auditId;

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

  // Reveal checklist and ISO buttons now that we have an auditId
  const btnChecklist = $('#btnChecklist');
  const btnExport = $('#btnChecklistExport');
  const btnISO = $('#btnISO');
  if (btnChecklist) btnChecklist.style.display = '';
  if (btnExport) btnExport.style.display = '';
  if (btnISO) btnISO.style.display = '';
}

// ── ISO Compliance Page ──────────────────────────────────────────
function openISO() {
  const id = currentAuditId || auditResults?.evidence?.auditId;
  if (!id) { alert('Execute uma auditoria primeiro para gerar o relatório ISO.'); return; }
  window.open(`/iso/${id}`, '_blank');
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

  // Add fix prompt button below score
  let fixBtn = $('#btnFixPromptScore');
  if (!fixBtn) {
    fixBtn = document.createElement('div');
    fixBtn.id = 'fixPromptScoreContainer';
    fixBtn.style.cssText = 'margin-top:20px;text-align:center;';
    fixBtn.innerHTML = `
      <button id="btnFixPromptScore" onclick="generateFixPromptDirect()" style="background:linear-gradient(135deg,#ff0040,#c0001e);color:#fff;border:none;border-radius:10px;padding:14px 28px;font-size:15px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:10px;letter-spacing:.5px;box-shadow:0 0 20px rgba(255,0,64,.4);transition:opacity .2s,transform .2s;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
        Gerar Plano de Correção com IA (Score 100/100)
      </button>
      <p style="margin:8px 0 0;color:#888;font-size:12px;">A IA analisa todas as falhas e gera um plano completo com SQL, configurações e passos para corrigir o site.</p>
    `;
    section.appendChild(fixBtn);
  }

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

async function downloadChecklistHTML() {
  const id = currentAuditId || auditResults?.evidence?.auditId;
  if (!id) { alert('Execute uma auditoria primeiro.'); return; }
  const btn = $('#btnChecklistExport');
  if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; }
  try {
    const resp = await fetch(`/api/checklist/${id}/export`);
    if (!resp.ok) { const d = await resp.json(); throw new Error(d.error || 'Erro ao exportar'); }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `checklist-security-${id.substring(0, 8)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert('Erro ao exportar checklist: ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.style.opacity = ''; }
  }
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

// ═══════════════════════════════════════════════════════════════════
// AI FIX PROMPT GENERATOR
// ═══════════════════════════════════════════════════════════════════

// Standalone fix prompt generator — shows modal directly, no AI chat messages
async function generateFixPromptDirect() {
  if (!auditResults) {
    alert('Execute uma auditoria primeiro.');
    return;
  }

  const btn = $('#btnFixPromptScore');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Gerando plano de correção...`;
  }

  // Show loading spinner (separate id to avoid conflict with modal overlay)
  const loadingOverlay = document.createElement('div');
  loadingOverlay.id = 'fixPromptLoadingOverlay';
  loadingOverlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:9000;';
  loadingOverlay.innerHTML = `
    <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="#ff0040" stroke-width="2" width="48" height="48"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg>
    <p style="color:#fff;margin-top:16px;font-size:16px;font-weight:600;">A IA está gerando seu plano de correção...</p>
    <p style="color:#888;margin-top:6px;font-size:13px;">Analisando vulnerabilidades e gerando SQL, configs e passos detalhados</p>
  `;
  document.body.appendChild(loadingOverlay);

  try {
    const response = await fetch('/api/ai/fix-prompt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auditId: currentAuditId, auditData: auditResults })
    });

    const data = await response.json();

    if (data.success && data.prompt) {
      showFixPromptModal(data.prompt, auditResults.score, data.criticalCount);
    } else {
      alert(`Erro ao gerar plano: ${data.error || 'Tente novamente.'}`);
    }
  } catch (error) {
    alert(`Erro de conexão: ${error.message}`);
  } finally {
    const ov = $('#fixPromptLoadingOverlay');
    if (ov) ov.remove();
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg> Gerar Plano de Correção com IA (Score 100/100)`;
    }
  }
}

async function generateAIFixPrompt() {
  if (!auditResults) {
    appendLog('error', 'ERROR', 'Execute uma auditoria primeiro.');
    return;
  }

  const btn = $('#btnFixPrompt');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Gerando...`;
  }

  addAIMessage('user', 'Gere um prompt de correção completo para este site atingir pontuação 100/100.');
  showAITyping();

  try {
    const response = await fetch('/api/ai/fix-prompt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auditId: currentAuditId, auditData: auditResults })
    });

    removeAITyping();

    if (!response.ok) {
      const error = await response.json();
      addAIMessage('bot', `Erro ao gerar prompt: ${error.error}`);
      return;
    }

    const data = await response.json();

    if (data.success && data.prompt) {
      addAIMessage('bot', data.prompt);
      showFixPromptModal(data.prompt, auditResults.score, data.criticalCount);
    } else {
      addAIMessage('bot', `Erro: ${data.error || 'Falha ao gerar prompt de correção.'}`);
    }
  } catch (error) {
    removeAITyping();
    addAIMessage('bot', `Erro de conexão: ${error.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg> Gerar Prompt de Correção`;
    }
  }
}

function showFixPromptModal(prompt, currentScore, criticalCount) {
  const existing = document.getElementById('fixPromptOverlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'fixPromptOverlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.88);backdrop-filter:blur(8px);z-index:10000;display:flex;align-items:center;justify-content:center;padding:1rem;';

  const promptText = (prompt || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  overlay.innerHTML = `
    <div style="background:#0d0d14;border:1px solid #1a1a2e;border-radius:12px;width:100%;max-width:860px;max-height:92vh;display:flex;flex-direction:column;box-shadow:0 0 60px rgba(0,255,65,0.15);">
      <div style="display:flex;align-items:center;justify-content:space-between;padding:1.25rem 1.5rem;border-bottom:1px solid #1a1a2e;">
        <div>
          <div style="font-size:1.05rem;font-weight:700;color:#00ff41;letter-spacing:1px;">PROMPT DE CORREÇÃO GERADO PELA IA</div>
          <div style="font-size:0.75rem;color:#8888aa;margin-top:0.2rem;">
            Score atual: <strong style="color:#ff4444">${currentScore || '?'}/100</strong>
            &nbsp;•&nbsp; ${criticalCount || 0} falha(s) crítica(s)
            &nbsp;•&nbsp; Meta: <strong style="color:#00ff41">100/100</strong>
          </div>
        </div>
        <button onclick="document.getElementById('fixPromptOverlay').remove()" style="background:none;border:none;color:#8888aa;cursor:pointer;font-size:1.4rem;line-height:1;padding:0.25rem;">✕</button>
      </div>
      <div style="padding:0.75rem 1.5rem;background:#0a0a0f;border-bottom:1px solid #1a1a2e;display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center;">
        <button onclick="copyFixPrompt()" style="background:#00ff41;color:#000;border:none;border-radius:6px;padding:0.45rem 1rem;font-size:0.8rem;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:0.4rem;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          Copiar Prompt Completo
        </button>
        <button onclick="downloadFixPrompt()" style="background:transparent;color:#00ff41;border:1px solid #00ff41;border-radius:6px;padding:0.45rem 1rem;font-size:0.8rem;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:0.4rem;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Baixar .md
        </button>
        <div style="margin-left:auto;font-size:0.72rem;color:#555570;">Cole em qualquer IA para corrigir automaticamente</div>
      </div>
      <div style="overflow-y:auto;padding:1.25rem 1.5rem;flex:1;">
        <pre id="fixPromptContent" style="background:#080810;border:1px solid #1a1a2e;border-radius:8px;padding:1.25rem;font-family:monospace;font-size:0.77rem;line-height:1.65;color:#c8c8d8;white-space:pre-wrap;word-break:break-word;overflow-y:auto;max-height:52vh;">${promptText}</pre>
      </div>
      <div style="padding:0.65rem 1.5rem;border-top:1px solid #1a1a2e;background:#0a0a0f;border-radius:0 0 12px 12px;text-align:center;">
        <span style="font-size:0.71rem;color:#555570;">Gerado por Supabase Guard AI &nbsp;•&nbsp; Llama 3.3 70B &nbsp;•&nbsp; Cole em Claude, ChatGPT ou Gemini</span>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  window._lastFixPrompt = prompt;
}

function copyFixPrompt() {
  const text = window._lastFixPrompt || document.getElementById('fixPromptContent')?.innerText || '';
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('#fixPromptOverlay button[onclick="copyFixPrompt()"]');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = '&#10003; Copiado!';
      btn.style.background = '#00cc33';
      setTimeout(() => { btn.innerHTML = orig; btn.style.background = '#00ff41'; }, 2000);
    }
  });
}

function downloadFixPrompt() {
  const text = window._lastFixPrompt || '';
  const url = auditResults?.projectUrl || 'site';
  const filename = `fix-prompt-${url.replace(/https?:\/\//, '').replace(/[^a-z0-9]/gi, '-')}.md`;
  const blob = new Blob([text], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
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
      <li><strong>Storage:</strong> Verifica buckets públicos e permissões de upload.</li>
      <li><strong>Edge Functions:</strong> Testa autenticação e permissões de funções serverless.</li>
      <li><strong>Realtime:</strong> Verifica canais WebSocket públicos.</li>
      <li><strong>Auth:</strong> Analisa endpoints de autenticação e configurações.</li>
    </ul>

    <h3 style="color: var(--text-secondary); margin-top: 1rem;">Verificações Avançadas v3</h3>
    <ul>
      <li><strong>DDoS/DoS Resilience:</strong> Testa rate limiting, CDN/WAF, latência e detecção de ataques em tempo real.</li>
      <li><strong>Brute Force Check:</strong> Testa vulnerabilidade a ataques de força bruta em login e signup.</li>
      <li><strong>SSL/TLS Analysis:</strong> Analisa certificados, versões TLS e cipher suites.</li>
      <li><strong>Security Headers:</strong> Verifica HSTS, CSP, X-Frame-Options e outros headers de segurança.</li>
    </ul>
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

function showPrivacy() {
  $('#modalBody').innerHTML = `
    <h2>Política de Privacidade</h2>
    <p>O Supabase Guard está comprometido em proteger sua privacidade.</p>
    
    <h3 style="color: var(--text-secondary); margin-top: 1rem;">Dados que Coletamos</h3>
    <ul>
      <li><strong>URL do Projeto:</strong> Necessária para realizar a auditoria de segurança.</li>
      <li><strong>Chave Anônima (opcional):</strong> Para testes de acesso autenticado.</li>
      <li><strong>Resultados da Auditoria:</strong> Armazenados localmente e opcionalmente no Supabase para histórico.</li>
    </ul>

    <h3 style="color: var(--text-secondary); margin-top: 1rem;">O que NÃO Fazemos</h3>
    <ul>
      <li>Não armazenamos senhas ou tokens de autenticação.</li>
      <li>Não compartilhamos seus dados com terceiros.</li>
      <li>Não usamos cookies de rastreamento.</li>
      <li>Não enviamos seus dados para serviços externos (exceto Supabase configurado pelo usuário).</li>
    </ul>

    <h3 style="color: var(--text-secondary); margin-top: 1rem;">Armazenamento</h3>
    <ul>
      <li>Resultados podem ser salvos no seu próprio banco Supabase (se configurado).</li>
      <li>Histórico local é armazenado no navegador (localStorage).</li>
      <li>Você pode solicitar exclusão dos dados a qualquer momento.</li>
    </ul>

    <p style="margin-top: 1rem;"><strong>Última atualização:</strong> Março 2026</p>
  `;
  $('#modalOverlay').style.display = 'flex';
}

function showContact() {
  $('#modalBody').innerHTML = `
    <h2>Fale Conosco</h2>
    <p>Temos prazer em ajudar! Entre em contato para:</p>
    
    <ul>
      <li><strong>Dúvidas:</strong> Questões sobre como usar a ferramenta.</li>
      <li><strong>Sugestões:</strong> Funcionalidades que você gostaria de ver.</li>
      <li><strong>Relatórios de Bugs:</strong> Problemas encontrados durante o uso.</li>
      <li><strong>Parcerias:</strong> Oportunidades de colaboração.</li>
    </ul>

    <h3 style="color: var(--text-secondary); margin-top: 1rem;">Informações de Contato</h3>
    <ul>
      <li><strong>Email:</strong> suporte@supabaseguard.local</li>
      <li><strong>GitHub:</strong> github.com/supabaseguard</li>
      <li><strong>Versão:</strong> 3.1.0</li>
      <li><strong>Engine:</strong> Node.js + Express</li>
    </ul>

    <p style="margin-top: 1rem;">Obrigado por usar o Supabase Guard!</p>
    <p style="color: var(--accent); font-weight: bold;">🛡️ Mantemos seus projetos seguros!</p>
  `;
  $('#modalOverlay').style.display = 'flex';
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

function openChecklist() {
  const id = currentAuditId || auditResults?.evidence?.auditId;
  if (!id) {
    alert('Execute uma auditoria primeiro para gerar o checklist.');
    return;
  }
  window.open(`/checklist/${id}`, '_blank');
}

async function sendAIQuestion(question) {
  const input = $('#aiQuestion');
  const questionText = question || input.value.trim();
  
  if (!questionText) return;
  
  if (!currentAuditId && !auditResults) {
    appendLog('error', 'ERROR', 'Execute uma auditoria primeiro.');
    return;
  }
  
  console.log('Sending question:', questionText);
  console.log('Audit ID:', currentAuditId);
  console.log('Has auditData:', !!auditResults);
  
  // Add user message to chat
  addAIMessage('user', questionText);
  input.value = '';
  
  // Show typing indicator
  showAITyping();
  
  // Send to API - use simple endpoint (non-streaming)
  try {
    const response = await fetch('/api/ai/chat/simple', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        auditId: currentAuditId,
        auditData: auditResults,
        question: questionText
      })
    });
    
    console.log('Response status:', response.status);
    
    removeAITyping();
    
    if (!response.ok) {
      const error = await response.json();
      addAIMessage('bot', `Erro: ${error.error || 'Falha ao conectar com a IA'}`);
      return;
    }
    
    const data = await response.json();
    console.log('Response data:', data);
    
    if (data.success && data.response) {
      addAIMessage('bot', data.response);
    } else if (data.error) {
      addAIMessage('bot', `Erro: ${data.error}`);
    } else {
      addAIMessage('bot', 'Desculpe, não consegui gerar uma resposta.');
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
        <div style="margin-top:12px;">
          <button id="btnFixPrompt" onclick="generateAIFixPrompt()" style="background:linear-gradient(135deg,#ff0040,#c0001e);color:#fff;border:none;border-radius:8px;padding:10px 18px;font-size:13px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:8px;letter-spacing:.5px;box-shadow:0 0 12px rgba(255,0,64,.35);transition:opacity .2s;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            Gerar Prompt de Correção (Score 100/100)
          </button>
        </div>
      </div>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════
// Audit History Functions
// ═══════════════════════════════════════════════════════════════════

let auditHistoryData = null;

function toggleHistory() {
  const section = $('#historySection');
  if (section.style.display === 'none' || !section.style.display) {
    section.style.display = 'block';
    loadAuditHistory();
    section.scrollIntoView({ behavior: 'smooth' });
  } else {
    section.style.display = 'none';
  }
}

async function loadAuditHistory() {
  const loading = $('#historyLoading');
  const empty = $('#historyEmpty');
  const list = $('#historyList');
  
  loading.style.display = 'flex';
  empty.style.display = 'none';
  
  try {
    const response = await fetch('/api/audits/history');
    const data = await response.json();
    
    auditHistoryData = data;
    
    $('#localAuditsCount').textContent = data.localCount || 0;
    $('#supabaseAuditsCount').textContent = data.supabaseCount || 0;
    $('#totalAuditsCount').textContent = data.totalCount || 0;
    
    loading.style.display = 'none';
    
    if (data.audits && data.audits.length > 0) {
      renderAuditList(data.audits);
    } else {
      empty.style.display = 'block';
    }
  } catch (err) {
    loading.style.display = 'none';
    empty.style.display = 'block';
    appendLog('error', 'HISTORY', `Erro ao carregar histórico: ${err.message}`);
  }
}

function renderAuditList(audits) {
  const list = $('#historyList');
  list.innerHTML = '';
  
  for (const audit of audits) {
    const item = document.createElement('div');
    item.className = 'history-item';
    
    const gradeColor = getGradeColor(audit.grade?.grade || 'F');
    const sourceIcon = audit.source === 'supabase' ? '☁️' : '💾';
    const sourceLabel = audit.source === 'supabase' ? 'Supabase' : 'Local';
    
    item.innerHTML = `
      <div class="history-item-header">
        <span class="history-source">${sourceIcon} ${sourceLabel}</span>
        <span class="history-grade" style="color: ${gradeColor}">${audit.grade?.grade || 'F'}</span>
      </div>
      <div class="history-item-url">${escapeHtml(audit.projectUrl || 'N/A')}</div>
      <div class="history-item-meta">
        <span>Score: <strong style="color: ${gradeColor}">${audit.score || 0}</strong>/100</span>
        <span>Checks: ${audit.totalChecks || 0}</span>
        <span>Pass: ${audit.passed || 0}</span>
        <span class="history-fail">Fail: ${audit.failed || 0}</span>
        <span class="history-warn">Warn: ${audit.warnings || 0}</span>
      </div>
      <div class="history-item-time">
        ${formatDate(audit.timestamp)}
        ${audit.duration ? `• ${audit.duration}` : ''}
        ${audit.userRegion && audit.userRegion !== 'Unknown' ? `• ${audit.userRegion}` : ''}
        ${audit.userMachine && audit.userMachine !== 'Unknown' ? `• ${audit.userMachine}` : ''}
      </div>
      <div class="history-item-actions">
        ${audit.source === 'supabase' ? 
          `<button class="btn-sm" onclick="viewSupabaseAudit('${audit.auditId}')">📊 Ver Detalhes</button>` : 
          `<button class="btn-sm" onclick="viewAuditById('${audit.auditId}')">👁️ Ver</button>`
        }
        <button class="btn-sm btn-secondary" onclick="loadAuditForCompare('${audit.source}', '${audit.auditId}')">🔄 Usar</button>
      </div>
    `;
    
    list.appendChild(item);
  }
}

function getGradeColor(grade) {
  const colors = {
    'A': '#00ff41',
    'B': '#7fff00',
    'C': '#ffff00',
    'D': '#ff8c00',
    'F': '#ff0040'
  };
  return colors[grade] || '#ff0040';
}

function formatDate(timestamp) {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp);
  return date.toLocaleString('pt-BR', { 
    day: '2-digit', 
    month: '2-digit', 
    year: 'numeric', 
    hour: '2-digit', 
    minute: '2-digit' 
  });
}

async function viewSupabaseAudit(auditId) {
  const details = $('#supabaseDetails');
  const info = $('#supabaseAuditInfo');
  const vulns = $('#supabaseVulnerabilities');
  
  details.style.display = 'block';
  info.innerHTML = '<div class="spinner"></div> Carregando...';
  vulns.innerHTML = '';
  
  try {
    const response = await fetch(`/api/audits/db/full/${auditId}`);
    const data = await response.json();
    
    if (!data.success) {
      info.innerHTML = `<p style="color: #ff0040">Erro: ${data.error}</p>`;
      return;
    }
    
    const audit = data.audit;
    const gradeColor = getGradeColor(audit.grade);
    
    info.innerHTML = `
      <div class="supabase-audit-card">
        <div class="supabase-audit-header">
          <div class="supabase-score" style="border-color: ${gradeColor}">
            <span class="score-value" style="color: ${gradeColor}">${audit.score}</span>
            <span class="score-label">${audit.grade}</span>
          </div>
          <div class="supabase-info">
            <h4>${escapeHtml(audit.projectUrl)}</h4>
            <p>ID: ${audit.auditId}</p>
            <p>Ref: ${audit.projectRef || 'N/A'}</p>
          </div>
        </div>
        
        <div class="supabase-stats">
          <div class="stat"><span class="stat-pass">${audit.passed}</span> Pass</div>
          <div class="stat"><span class="stat-fail">${audit.failed}</span> Fail</div>
          <div class="stat"><span class="stat-warn">${audit.warnings}</span> Warn</div>
          <div class="stat"><span>${audit.totalChecks}</span> Total</div>
        </div>
        
        <div class="supabase-user-info">
          <h5>Informações do Usuário</h5>
          <p>IP: ${audit.user?.ip || 'N/A'}</p>
          <p>Machine: ${audit.user?.machine || 'N/A'} | OS: ${audit.user?.os || 'N/A'}</p>
          <p>Browser: ${audit.user?.browser || 'N/A'} | Region: ${audit.user?.region || 'N/A'}</p>
        </div>
        
        <div class="supabase-evidence">
          <h5>Evidência Assinada</h5>
          <p>SHA-256: <code>${audit.evidence?.sha256 || 'N/A'}</code></p>
          <p>Timestamp: ${formatDate(audit.evidence?.timestamp)}</p>
          <p>Criado em: ${formatDate(audit.createdAt)}</p>
        </div>
        
        <div class="supabase-results-summary">
          <h5>Resultados (${audit.results?.length || 0})</h5>
          <div class="results-summary-list">
            ${(audit.results || []).slice(0, 10).map(r => `
              <div class="result-summary-item ${r.status.toLowerCase()}">
                <span class="result-check">${escapeHtml(r.check_name)}</span>
                <span class="result-status ${r.status}">${r.status}</span>
                <span class="result-severity ${r.severity}">${r.severity}</span>
              </div>
            `).join('')}
            ${audit.results?.length > 10 ? `<p class="more-results">... e mais ${audit.results.length - 10} resultados</p>` : ''}
          </div>
        </div>
      </div>
    `;
    
    if (audit.vulnerabilities && audit.vulnerabilities.length > 0) {
      vulns.innerHTML = `
        <h5>Vulnerabilidades Críticas/Altas (${audit.vulnerabilities.length})</h5>
        <div class="vuln-list">
          ${audit.vulnerabilities.map(v => `
            <div class="vuln-item ${v.severity}">
              <div class="vuln-header">
                <span class="vuln-severity ${v.severity}">${v.severity.toUpperCase()}</span>
                <span class="vuln-category">${escapeHtml(v.category)}</span>
              </div>
              <div class="vuln-title">${escapeHtml(v.title)}</div>
              <div class="vuln-desc">${escapeHtml(v.description)}</div>
            </div>
          `).join('')}
        </div>
      `;
    } else {
      vulns.innerHTML = '<p class="no-vulns">Nenhuma vulnerabilidade crítica/alta encontrada.</p>';
    }
    
    details.scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    info.innerHTML = `<p style="color: #ff0040">Erro: ${err.message}</p>`;
  }
}

function viewAuditById(auditId) {
  window.open(`/audit/${auditId}`, '_blank');
}

async function loadAuditForCompare(source, auditId) {
  try {
    let data;
    
    if (source === 'supabase') {
      const response = await fetch(`/api/audits/db/full/${auditId}`);
      const result = await response.json();
      if (!result.success) {
        appendLog('error', 'HISTORY', `Erro:        return;
      ${result.error}`);
 }
      
      const audit = result.audit;
      data = {
        projectUrl: audit.projectUrl,
        projectRef: audit.projectRef,
        score: audit.score,
        grade: { grade: audit.grade, label: audit.gradeLabel },
        totalChecks: audit.totalChecks,
        passed: audit.passed,
        failed: audit.failed,
        warnings: audit.warnings,
        errors: audit.errors,
        info: audit.info,
        duration: audit.duration,
        results: audit.results.map(r => ({
          check: r.check_name,
          status: r.status,
          severity: r.severity,
          message: r.message,
          details: r.details_json
        })),
        evidence: audit.evidence
      };
    } else {
      const response = await fetch(`/api/audit/${auditId}`);
      data = await response.json();
    }
    
    if (data && data.evidence?.auditId) {
      auditResults = data;
      $('#projectUrl').value = data.projectUrl;
      showScoreCard(data);
      showResultsList(data.results);
      showEvidence(data);
      appendLog('info', 'HISTORY', `Auditoria carregada: ${data.projectUrl}`);
    }
  } catch (err) {
    appendLog('error', 'HISTORY', `Erro ao carregar: ${err.message}`);
  }
}

function showSupabaseAudits() {
  if (auditHistoryData && auditHistoryData.audits) {
    const supabaseOnly = auditHistoryData.audits.filter(a => a.source === 'supabase');
    renderAuditList(supabaseOnly);
    appendLog('info', 'HISTORY', `Mostrando ${supabaseOnly.length} auditorias do Supabase`);
  } else {
    loadAuditHistory();
  }
}

// Auto-load history on page load (silent)
document.addEventListener('DOMContentLoaded', () => {
  fetch('/api/health')
    .then(res => res.json())
    .then(data => {
      console.log('=== System Status ===');
      console.log('Supabase Configured:', data.supabase?.configured);
      console.log('Supabase Status:', data.supabase?.status);
      console.log('Audits in DB:', data.supabase?.auditsInDb);
      console.log('=====================');
    })
    .catch(err => console.error('Health check error:', err));
});

// ═══════════════════════════════════════════════════════════════════
// PWA - Progressive Web App Support
// ═══════════════════════════════════════════════════════════════════

let deferredPrompt = null;

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  
  // Show install button
  const installBtn = document.getElementById('btnInstall');
  if (installBtn) {
    installBtn.style.display = 'flex';
    installBtn.style.alignItems = 'center';
    installBtn.style.gap = '6px';
    installBtn.style.background = 'linear-gradient(135deg, #00d4ff 0%, #a855f7 100%)';
    installBtn.style.border = 'none';
    installBtn.style.color = '#fff';
    installBtn.style.padding = '8px 16px';
    installBtn.style.borderRadius = '8px';
    installBtn.style.cursor = 'pointer';
    installBtn.style.fontSize = '0.85rem';
    installBtn.style.fontWeight = '500';
    installBtn.style.marginLeft = '8px';
    installBtn.style.transition = 'all 0.3s';
    
    installBtn.onmouseenter = () => {
      installBtn.style.transform = 'scale(1.05)';
      installBtn.style.boxShadow = '0 4px 20px rgba(0, 212, 255, 0.4)';
    };
    installBtn.onmouseleave = () => {
      installBtn.style.transform = 'scale(1)';
      installBtn.style.boxShadow = 'none';
    };
  }
});

window.addEventListener('appinstalled', () => {
  console.log('✅ App installed successfully!');
  deferredPrompt = null;
  
  const installBtn = document.getElementById('btnInstall');
  if (installBtn) {
    installBtn.style.display = 'none';
  }
  
  appendLog('info', 'PWA', 'App instalado com sucesso!');
});

function installApp() {
  if (!deferredPrompt) {
    appendLog('warn', 'PWA', 'Não é possível instalar agora. Tente novamente.');
    return;
  }
  
  deferredPrompt.prompt();
  
  deferredPrompt.userChoice.then((choiceResult) => {
    if (choiceResult.outcome === 'accepted') {
      console.log('User accepted the install prompt');
      appendLog('info', 'PWA', 'Instalando app...');
    } else {
      console.log('User dismissed the install prompt');
      appendLog('info', 'PWA', 'Instalação cancelada.');
    }
    deferredPrompt = null;
  });
}

// ═══════════════════════════════════════════════════════════════════
// MATRIX BINARY RAIN — Efeito de chuva de 0s e 1s
// ═══════════════════════════════════════════════════════════════════
(function initMatrixRain() {
  const canvas = document.getElementById('matrixCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Config
  const FONT_SIZE   = 14;        // px por caractere
  const CHARS       = ['0', '1'];
  const COLOR_HEAD  = '#ffffff';  // dígito da frente (mais brilhante)
  const COLOR_MAIN  = '#00ff41';  // cor principal (verde Matrix)
  const COLOR_MID   = '#00cc33';
  const COLOR_TAIL  = '#006618';

  // State
  let cols = 0;
  let drops = [];           // y de cada coluna (em caracteres)
  let speeds = [];          // velocidade de queda de cada coluna
  let scanningMode = false;
  let animId = null;
  let lastFrame = 0;

  // Intervalo entre frames: normal 60ms ≈ 16fps, scanning 30ms ≈ 33fps
  function frameDelay() { return scanningMode ? 35 : 60; }

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    const newCols = Math.floor(canvas.width / FONT_SIZE);

    if (newCols !== cols) {
      // Preserva drops existentes, preenche novos
      const old = drops.slice();
      const oldSpd = speeds.slice();
      cols  = newCols;
      drops = [];
      speeds = [];
      for (let i = 0; i < cols; i++) {
        drops[i]  = old[i]  !== undefined ? old[i]  : Math.floor(Math.random() * -80);
        speeds[i] = oldSpd[i] !== undefined ? oldSpd[i] : 0.4 + Math.random() * 0.8;
      }
    }
  }

  function draw(ts) {
    animId = requestAnimationFrame(draw);
    if (ts - lastFrame < frameDelay()) return;
    lastFrame = ts;

    const h = canvas.height;
    const w = canvas.width;

    // Fade trail — semi-transparent overlay
    ctx.fillStyle = 'rgba(10, 10, 15, 0.18)';
    ctx.fillRect(0, 0, w, h);

    ctx.font = `${FONT_SIZE}px "JetBrains Mono", monospace`;

    for (let i = 0; i < cols; i++) {
      const y = drops[i];
      const yPx = y * FONT_SIZE;

      if (yPx > 0 && yPx < h) {
        // Dígito líder (branco brilhante)
        ctx.fillStyle = COLOR_HEAD;
        ctx.shadowColor = COLOR_MAIN;
        ctx.shadowBlur = scanningMode ? 10 : 6;
        ctx.fillText(CHARS[Math.random() < 0.5 ? 0 : 1], i * FONT_SIZE, yPx);

        // Dígitos de rastro (um pouco acima)
        const trailLen = Math.floor(8 + Math.random() * 8);
        for (let t = 1; t <= trailLen && t <= y; t++) {
          const alpha = 1 - t / (trailLen + 1);
          const color = t < 3
            ? interpolateColor(COLOR_MAIN, COLOR_MID, t / 3)
            : interpolateColor(COLOR_MID, COLOR_TAIL, (t - 3) / (trailLen - 3));
          ctx.fillStyle = hexWithAlpha(color, alpha);
          ctx.shadowBlur = 0;
          ctx.fillText(CHARS[Math.random() < 0.5 ? 0 : 1], i * FONT_SIZE, (y - t) * FONT_SIZE);
        }
      }

      // Avança a gota
      drops[i] += speeds[i];

      // Reseta quando sai da tela (com atraso aleatório para ficar natural)
      const rows = Math.floor(h / FONT_SIZE);
      if (drops[i] > rows + 20) {
        if (Math.random() < (scanningMode ? 0.03 : 0.012)) {
          drops[i] = Math.floor(Math.random() * -60);
          speeds[i] = 0.4 + Math.random() * (scanningMode ? 1.4 : 0.8);
        }
      }
    }

    ctx.shadowBlur = 0;
  }

  // Helpers
  function hexWithAlpha(hex, alpha) {
    const r = parseInt(hex.slice(1,3), 16);
    const g = parseInt(hex.slice(3,5), 16);
    const b = parseInt(hex.slice(5,7), 16);
    return `rgba(${r},${g},${b},${alpha.toFixed(3)})`;
  }
  function interpolateColor(hex1, hex2, t) {
    const r = Math.round(parseInt(hex1.slice(1,3),16)*(1-t) + parseInt(hex2.slice(1,3),16)*t);
    const g = Math.round(parseInt(hex1.slice(3,5),16)*(1-t) + parseInt(hex2.slice(3,5),16)*t);
    const b = Math.round(parseInt(hex1.slice(5,7),16)*(1-t) + parseInt(hex2.slice(5,7),16)*t);
    return '#' + [r,g,b].map(x => x.toString(16).padStart(2,'0')).join('');
  }

  // Public API
  window.matrixSetScanning = function(active) {
    scanningMode = active;
    canvas.classList.toggle('scanning', active);
    // Ao iniciar scanning, acelera colunas paradas
    if (active) {
      for (let i = 0; i < cols; i++) {
        speeds[i] = 0.8 + Math.random() * 1.4;
      }
    } else {
      for (let i = 0; i < cols; i++) {
        speeds[i] = 0.4 + Math.random() * 0.8;
      }
    }
  };

  // Init
  resize();
  window.addEventListener('resize', resize);
  requestAnimationFrame(draw);
})();

// Register Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then(registration => {
        console.log('✅ Service Worker registered:', registration.scope);
      })
      .catch(error => {
        console.error('❌ Service Worker registration failed:', error);
      });
  });
}
