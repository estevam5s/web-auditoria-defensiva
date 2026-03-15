/*  ═══════════════════════════════════════════════════════════════════
    GROQ AI INTEGRATION
    Uses Groq API (like salary-funcionarios) to analyze audit results
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');

const GROQ_API_KEY = process.env.GROQ_API_KEY || process.env.GROK_API_KEY;
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL = 'llama-3.3-70b-versatile';

const SYSTEM_PROMPT = `Você é o SUPABASE GUARD AI Assistant, especialista em segurança de aplicações Supabase.

Responda em português brasileiro de forma concisa e prática.
Quando houver vulnerabilidades críticas, liste primeiro.
Forneça código SQL de exemplo quando aplicável para correção.
Não ultrapasse 500 palavras na resposta.`;

function buildAnalysisPrompt(auditData, userQuestion) {
  const { 
    projectUrl, projectRef, score, grade, results, 
    duration, catalogData, evidence 
  } = auditData;

  const criticalResults = (results?.filter(r => r.severity === 'critical' && r.status !== 'PASS') || []).slice(0, 5);
  const highResults = (results?.filter(r => r.severity === 'high' && r.status !== 'PASS') || []).slice(0, 5);
  const warnResults = (results?.filter(r => r.status === 'WARN') || []).slice(0, 5);
  const passResults = results?.filter(r => r.status === 'PASS') || [];

  let auditSummary = `
# AUDITORIA SUPABASE — ${projectUrl}

## INFO
- URL: ${projectUrl}
- Score: ${score}/100 (${grade?.label || 'N/A'})
- Audit ID: ${evidence?.auditId || 'N/A'}
- Verificações: ${results?.length || 0} | ✅ ${passResults.length} | ⚠️ ${warnResults.length} | 🔴 ${criticalResults.length + highResults.length}
`;

  if (criticalResults.length > 0) {
    auditSummary += `\n## CRÍTICAS\n`;
    criticalResults.forEach((r, i) => {
      auditSummary += `${i + 1}. [${r.severity.toUpperCase()}] ${r.check}: ${r.message}\n`;
    });
  }

  if (highResults.length > 0) {
    auditSummary += `\n## ALTAS\n`;
    highResults.forEach((r, i) => {
      auditSummary += `${i + 1}. [${r.severity.toUpperCase()}] ${r.check}: ${r.message}\n`;
    });
  }

  if (catalogData) {
    const tables = catalogData.openapi?.tables?.slice(0, 10).map(t => t.name) || [];
    if (tables.length > 0) {
      auditSummary += `\n## TABELAS: ${tables.join(', ')}\n`;
    }
  }

  auditSummary += `\n## PERGUNTA\n${userQuestion}\n\nResponda em português brasileiro de forma concisa.`;

  return auditSummary;
}

async function askGrok(auditData, userQuestion) {
  if (!GROQ_API_KEY) {
    return { success: false, error: 'GROQ_API_KEY não configurada. Defina a variável de ambiente.' };
  }

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: buildAnalysisPrompt(auditData, userQuestion) }
  ];

  const requestBody = {
    model: DEFAULT_MODEL,
    messages,
    temperature: 0.7,
    max_tokens: 2048,
    stream: false
  };

  try {
    const response = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Groq API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    if (data.choices && data.choices[0]) {
      return {
        success: true,
        response: data.choices[0].message.content,
        model: data.model,
        usage: data.usage
      };
    } else {
      throw new Error('Invalid response from Groq API');
    }
  } catch (error) {
    console.error('Groq API Error:', error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

async function askGrokStream(auditData, userQuestion, onChunk) {
  try {
    const result = await askGrok(auditData, userQuestion);
    if (!result.success) {
      onChunk({ error: result.error, done: true });
      return;
    }
    // Simulate streaming word by word for UI compatibility
    const words = result.response.split(' ');
    for (const word of words) {
      onChunk({ content: word + ' ', done: false });
      await new Promise(r => setTimeout(r, 10));
    }
    onChunk({ done: true });
  } catch (error) {
    console.error('Groq API Error:', error.message);
    onChunk({ error: error.message, done: true });
  }
}

// ═══════════════════════════════════════════════════════════════════
//  FIX PROMPT GENERATOR
//  Builds a comprehensive fix-command prompt to reach 100/100 score
// ═══════════════════════════════════════════════════════════════════

const FIX_PROMPT_SYSTEM = `Você é um especialista em segurança ofensiva e defensiva de aplicações Supabase/web.

Sua tarefa é analisar os resultados de uma auditoria de segurança e gerar um PROMPT DE CORREÇÃO COMPLETO E SUPERIOR.

O prompt gerado deve:
1. Listar TODAS as vulnerabilidades críticas e altas com contexto detalhado
2. Incluir credenciais expostas exatamente como encontradas
3. Fornecer SQL completo para corrigir RLS (Row Level Security)
4. Fornecer configurações exatas para o Supabase Dashboard
5. Fornecer código/config para headers de segurança
6. Fornecer passos para rotacionar/revogar credenciais expostas
7. Ser tão detalhado que qualquer desenvolvedor possa seguir sem ambiguidade
8. Garantir que o site alcance pontuação 100/100 após as correções

Responda APENAS com o prompt de correção, formatado em Markdown.
O prompt deve começar com "# PLANO DE CORREÇÃO DE SEGURANÇA — [URL]"
Não adicione introdução ou explicação antes do prompt.
Escreva em português brasileiro técnico e preciso.`;

function buildFixPromptInput(auditData) {
  const { projectUrl, score, grade, results = [], catalogData, evidence } = auditData;

  const critical = results.filter(r => r.severity === 'critical' && r.status !== 'PASS');
  const high = results.filter(r => r.severity === 'high' && r.status !== 'PASS');
  const medium = results.filter(r => r.severity === 'medium' && r.status !== 'PASS');
  const passed = results.filter(r => r.status === 'PASS');

  // Extract exposed credentials
  const exposedCreds = [];
  for (const r of results) {
    if (r.details?.supabaseUrl) exposedCreds.push(`SUPABASE_URL: ${r.details.supabaseUrl}`);
    if (r.details?.anonKeyFound) exposedCreds.push(`ANON_KEY: exposta no bundle JS`);
    if (r.details?.serviceRoleKeyFound) exposedCreds.push(`SERVICE_ROLE_KEY: EXPOSTA PUBLICAMENTE — EMERGÊNCIA`);
    if (r.details?.sources) {
      for (const s of r.details.sources) {
        exposedCreds.push(`${s.type}: encontrada em ${s.source} (valor mascarado: ${s.value})`);
      }
    }
  }

  // Extract exposed tables
  const exposedTables = [];
  for (const r of results) {
    if (r.check?.includes('REST') && Array.isArray(r.details?.tables)) {
      for (const t of r.details.tables) {
        if (t.readable) exposedTables.push(`${t.name} (${t.recordCount || 0} registros, gravável: ${t.writable || false})`);
      }
    }
  }

  // Extract all finding details
  let findingsBlock = '';
  for (const r of [...critical, ...high, ...medium]) {
    findingsBlock += `\n### ${r.check} [${r.severity.toUpperCase()}] [${r.status}]\n`;
    findingsBlock += `**Mensagem:** ${r.message}\n`;
    if (r.details?.recommendation) findingsBlock += `**Recomendação:** ${r.details.recommendation}\n`;
    if (Array.isArray(r.details?.functions)) findingsBlock += `**Funções:** ${r.details.functions.slice(0, 10).map(f => f.name || f).join(', ')}\n`;
    if (Array.isArray(r.details?.tables)) findingsBlock += `**Tabelas:** ${r.details.tables.slice(0, 15).map(t => t.name || t.table).join(', ')}\n`;
    if (Array.isArray(r.details?.files)) findingsBlock += `**Arquivos:** ${r.details.files.slice(0, 10).map(f => f.file || f).join(', ')}\n`;
    if (Array.isArray(r.details?.missing)) findingsBlock += `**Headers ausentes:** ${r.details.missing.join(', ')}\n`;
    else if (typeof r.details?.missing === 'string') findingsBlock += `**Headers ausentes:** ${r.details.missing}\n`;
  }

  // Catalog context
  const tables = catalogData?.openapi?.tables?.map(t => t.name) || [];
  const rpcs = catalogData?.openapi?.rpcFunctions?.map(f => f.name) || [];

  return `# DADOS DA AUDITORIA

**Site:** ${projectUrl}
**Score atual:** ${score}/100 (${grade?.grade} — ${grade?.label})
**Audit ID:** ${evidence?.auditId || 'N/A'}

## RESUMO
- Total de verificações: ${results.length}
- Aprovadas: ${passed.length}
- Críticas: ${critical.length}
- Altas: ${high.length}
- Médias: ${medium.length}

## CREDENCIAIS EXPOSTAS
${exposedCreds.length > 0 ? exposedCreds.map(c => `- ${c}`).join('\n') : '- Nenhuma credencial exposta detectada'}

## TABELAS EXPOSTAS PUBLICAMENTE (sem RLS)
${exposedTables.length > 0 ? exposedTables.map(t => `- ${t}`).join('\n') : '- Nenhuma tabela exposta'}

## CATÁLOGO COMPLETO
- Tabelas no schema: ${tables.slice(0, 30).join(', ') || 'N/A'}
- Funções RPC: ${rpcs.join(', ') || 'N/A'}

## TODAS AS VULNERABILIDADES ENCONTRADAS
${findingsBlock}

---

Com base nesses dados, gere o PROMPT DE CORREÇÃO COMPLETO que permite ao desenvolvedor corrigir TODAS as vulnerabilidades e atingir pontuação 100/100.

O prompt deve conter:
1. Lista de ações URGENTES (credenciais expostas)
2. SQL completo de RLS para cada tabela exposta
3. Configurações do Supabase Dashboard (Auth, Storage, API)
4. Código de middleware/headers para o framework detectado
5. Checklist final de verificação
`;
}

async function generateFixPrompt(auditData) {
  if (!GROQ_API_KEY) {
    return { success: false, error: 'GROQ_API_KEY não configurada. Defina a variável de ambiente.' };
  }

  const userContent = buildFixPromptInput(auditData);

  const requestBody = {
    model: DEFAULT_MODEL,
    messages: [
      { role: 'system', content: FIX_PROMPT_SYSTEM },
      { role: 'user', content: userContent }
    ],
    temperature: 0.3,
    max_tokens: 4096,
    stream: false
  };

  try {
    const response = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Groq API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    if (data.choices && data.choices[0]) {
      return {
        success: true,
        prompt: data.choices[0].message.content,
        model: data.model,
        usage: data.usage,
        score: auditData.score,
        criticalCount: (auditData.results || []).filter(r => r.severity === 'critical' && r.status !== 'PASS').length
      };
    } else {
      throw new Error('Invalid response from Groq API');
    }
  } catch (error) {
    console.error('Groq Fix Prompt Error:', error.message);
    return { success: false, error: error.message };
  }
}

module.exports = { askGrok, askGrokStream, buildAnalysisPrompt, generateFixPrompt };
