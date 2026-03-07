/*  ═══════════════════════════════════════════════════════════════════
    GROQ AI INTEGRATION
    Uses Groq API (like salary-funcionarios) to analyze audit results
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');

const GROQ_API_KEY = process.env.GROQ_API_KEY || process.env.GROK_API_KEY || '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';
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
      const content = data.choices[0].message.content;
      // Send content in chunks to simulate streaming
      const words = content.split(' ');
      for (const word of words) {
        onChunk({ content: word + ' ', done: false });
        await new Promise(r => setTimeout(r, 10));
      }
      onChunk({ done: true });
    } else {
      throw new Error('Invalid response from Groq API');
    }
  } catch (error) {
    console.error('Groq API Error:', error.message);
    onChunk({ error: error.message, done: true });
  }
}

module.exports = { askGrok, askGrokStream, buildAnalysisPrompt };
