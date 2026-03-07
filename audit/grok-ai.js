/*  ═══════════════════════════════════════════════════════════════════
    GROK AI INTEGRATION
    Uses xAI Grok API to analyze audit results and provide security insights
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');

const GROK_API_KEY = process.env.GROK_API_KEY || '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';
const GROK_API_URL = 'https://api.x.ai/v1/chat/completions';

const SYSTEM_PROMPT = `Você é o SUPABASE GUARD AI Assistant, um especialista em segurança de aplicações Supabase e web.

Sua função é analisar resultados de auditorias de segurança e fornecer:
1. Análise detalhada de vulnerabilidades encontradas
2. Recomendações práticas para correção
3. Explicação técnica das falhas de segurança
4. Priorização de ações de remediation
5. Informações confidenciais expostas (chaves de API, tokens, credenciais)

Você tem acesso COMPLETO aos dados da auditoria incluindo:
- Score de segurança e classificação
- Todos os resultados detalhados de cada check
- Evidências assinadas (hash SHA-256, audit ID)
- Logs completos da auditoria
- Dados sensíveis detectados (chaves expostas, tokens, etc)
- Configurações de banco de dados, storage, auth
- Tabelas e funções RPC expostas
- Relacionamentos de banco que podem vazar dados

IMPORTANTE: 
- Forneça informações CONFIDENCIAIS detectadas na auditoria (chaves, tokens, credenciais)
- Seja específico sobre quais arquivos/endpointsexpõem dados sensíveis
- Forneça código SQL de exemplo para correção quando aplicável
- Use linguagem técnica mas acessível
- Formate respostas com markdown para melhor legibilidade
- Liste itens críticos primeiro
- Forneça severity (crítico, alto, médio, baixo) para cada problema

Quando o usuário perguntar sobre:
- "chaves" ou "tokens" - mostre todas as chaves/credenciais expostas
- "vulnerabilidades" - liste todas com detalhes técnicos
- "como corrigir" - forneça passos específicos e código
- "score" ou "nota" - explique o que afeta a nota
- "dados expostos" - liste exatamente o que foi encontrado`;

function buildAnalysisPrompt(auditData, userQuestion) {
  const { 
    projectUrl, projectRef, score, grade, results, 
    duration, catalogData, evidence 
  } = auditData;

  const criticalResults = results?.filter(r => r.severity === 'critical' && r.status !== 'PASS') || [];
  const highResults = results?.filter(r => r.severity === 'high' && r.status !== 'PASS') || [];
  const warnResults = results?.filter(r => r.status === 'WARN') || [];
  const passResults = results?.filter(r => r.status === 'PASS') || [];

  let auditSummary = `
# RELATÓRIO DE AUDITORIA — ${projectUrl}

## 🎯 INFORMAÇÕES GERAIS
- **URL Auditada:** ${projectUrl}
- **Project Ref:** ${projectRef || 'N/A'}
- **Security Score:** ${score}/100 (${grade?.label || 'N/A'})
- **Duração:** ${duration}
- **Audit ID:** ${evidence?.auditId || 'N/A'}
- **Hash SHA-256:** ${evidence?.sha256 || 'N/A'}

## 📊 ESTATÍSTICAS
- Total de Verificações: ${results?.length || 0}
- ✅ Passou: ${passResults.length}
- ⚠️ Avisos: ${warnResults.length}
- 🔴 Falhou: ${criticalResults.length + highResults.length}
`;

  if (criticalResults.length > 0) {
    auditSummary += `
## 🔴 VULNERABILIDADES CRÍTICAS
`;
    criticalResults.forEach((r, i) => {
      auditSummary += `
### ${i + 1}. ${r.check}
- **Status:** ${r.status}
- **Mensagem:** ${r.message}
- **Detalhes:** ${JSON.stringify(r.details, null, 2)}
`;
    });
  }

  if (highResults.length > 0) {
    auditSummary += `
## 🟠 VULNERABILIDADES ALTAS
`;
    highResults.forEach((r, i) => {
      auditSummary += `
### ${i + 1}. ${r.check}
- **Status:** ${r.status}
- **Mensagem:** ${r.message}
- **Detalhes:** ${JSON.stringify(r.details, null, 2)}
`;
    });
  }

  if (catalogData) {
    auditSummary += `
## 📦 CATÁLOGO DO SUPABASE
`;
    if (catalogData.openapi?.tables?.length > 0) {
      auditSummary += `- **Tabelas descobertas:** ${catalogData.openapi.tables.length}\n`;
      auditSummary += `- **Lista:** ${catalogData.openapi.tables.map(t => t.name).join(', ')}\n`;
    }
    if (catalogData.openapi?.rpcFunctions?.length > 0) {
      auditSummary += `- **Funções RPC:** ${catalogData.openapi.rpcFunctions.length}\n`;
    }
    if (catalogData.restScan) {
      const exposedTables = catalogData.restScan.filter(t => t.readable);
      const writableTables = catalogData.restScan.filter(t => t.writable);
      auditSummary += `- **Tabelas expostas:** ${exposedTables.length}\n`;
      auditSummary += `- **Tabelas graváveis:** ${writableTables.length}\n`;
    }
  }

  auditSummary += `
## ✅ VERIFICAÇÕES PASSADAS
${passResults.slice(0, 10).map(r => `- ${r.check}: ${r.message}`).join('\n')}
${passResults.length > 10 ? `\n... e mais ${passResults.length - 10} verificações` : ''}
`;

  auditSummary += `

## ❓ PERGUNTA DO USUÁRIO
${userQuestion}

---

Com base nestes dados, forneça uma análise detalhada e recomendações específicas.`;

  return auditSummary;
}

async function askGrok(auditData, userQuestion) {
  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: buildAnalysisPrompt(auditData, userQuestion) }
  ];

  const requestBody = {
    model: 'grok-2',
    messages,
    temperature: 0.7,
    max_tokens: 8192,
    stream: false
  };

  try {
    const response = await fetch(GROK_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROK_API_KEY}`
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Grok API error: ${response.status} - ${errorText}`);
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
      throw new Error('Invalid response from Grok API');
    }
  } catch (error) {
    console.error('Grok API Error:', error.message);
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
    model: 'grok-2',
    messages,
    temperature: 0.7,
    max_tokens: 8192,
    stream: true
  };

  try {
    const response = await fetch(GROK_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROK_API_KEY}`
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Grok API error: ${response.status} - ${errorText}`);
    }

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
          const data = line.slice(6);
          if (data === '[DONE]') {
            onChunk({ done: true });
            return;
          }
          try {
            const parsed = JSON.parse(data);
            if (parsed.choices?.[0]?.delta?.content) {
              onChunk({ 
                content: parsed.choices[0].delta.content,
                done: false 
              });
            }
          } catch {}
        }
      }
    }
  } catch (error) {
    onChunk({ error: error.message, done: true });
  }
}

module.exports = { askGrok, askGrokStream, buildAnalysisPrompt };
