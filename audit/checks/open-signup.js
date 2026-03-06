/*  CHECK: Open Signup
    Tests if Supabase project allows unrestricted signups */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkOpenSignup(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  const settingsUrl = `${baseUrl}/auth/v1/settings`;
  const res = await safeFetch(settingsUrl, { headers });

  if (res.ok && res.json) {
    if (res.json.disable_signup === false) {
      results.push({
        check: 'Open Signup — Status',
        status: 'WARN',
        severity: 'medium',
        message: 'Registros públicos estão habilitados neste projeto.',
        details: {
          disable_signup: false,
          recommendation: 'Se este projeto não é destinado a registros públicos, desabilite em Auth > Settings.'
        }
      });
    } else if (res.json.disable_signup === true) {
      results.push({
        check: 'Open Signup — Status',
        status: 'PASS',
        severity: 'info',
        message: 'Registros públicos estão desabilitados. ✓',
        details: { disable_signup: true }
      });
    }

    // Check if email confirmation is required
    if (res.json.mailer_autoconfirm) {
      results.push({
        check: 'Open Signup — Email Verification',
        status: 'WARN',
        severity: 'medium',
        message: 'Auto-confirm de email está ativo. Contas são criadas sem verificação.',
        details: {
          mailer_autoconfirm: true,
          recommendation: 'Desabilite auto-confirm para requerer verificação de email e prevenir contas falsas.'
        }
      });
    }
  } else {
    results.push({
      check: 'Open Signup — Settings',
      status: 'INFO',
      severity: 'info',
      message: 'Não foi possível verificar configuração de signup.',
      details: { status: res.status }
    });
  }

  return results;
}

module.exports = { checkOpenSignup };
