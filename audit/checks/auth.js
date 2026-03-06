/*  CHECK: Auth Endpoints
    Tests authentication configuration and exposure */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkAuthEndpoints(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // 1. Check GoTrue auth settings endpoint
  const settingsUrl = `${baseUrl}/auth/v1/settings`;
  const settingsRes = await safeFetch(settingsUrl, { headers });

  if (settingsRes.ok && settingsRes.json) {
    const settings = settingsRes.json;

    results.push({
      check: 'Auth — Settings Exposure',
      status: 'WARN',
      severity: 'medium',
      message: 'Configurações de autenticação estão acessíveis publicamente.',
      details: {
        url: settingsUrl,
        providers: settings.external || {},
        disableSignup: settings.disable_signup,
        mailerAutoconfirm: settings.mailer_autoconfirm,
        phoneAutoconfirm: settings.phone_autoconfirm,
        smsProvider: settings.sms_provider
      }
    });

    // Check if signup is open
    if (settings.disable_signup === false) {
      results.push({
        check: 'Auth — Open Signup',
        status: 'WARN',
        severity: 'medium',
        message: 'Signup está habilitado. Qualquer pessoa pode criar conta no projeto.',
        details: {
          recommendation: 'Se não pretendido, desabilite signup em Authentication > Settings'
        }
      });
    }

    // Check autoconfirm
    if (settings.mailer_autoconfirm === true) {
      results.push({
        check: 'Auth — Auto Confirm Email',
        status: 'WARN',
        severity: 'medium',
        message: 'Auto-confirmação de email está ativa. Contas são ativadas instantaneamente.',
        details: {
          recommendation: 'Desabilite auto-confirm para requerer verificação de email.'
        }
      });
    }

    // Check enabled providers
    if (settings.external) {
      const enabledProviders = Object.entries(settings.external)
        .filter(([_, v]) => v === true || v?.enabled === true)
        .map(([k]) => k);

      if (enabledProviders.length > 0) {
        results.push({
          check: 'Auth — Providers',
          status: 'INFO',
          severity: 'info',
          message: `${enabledProviders.length} provider(s) de auth habilitado(s): ${enabledProviders.join(', ')}`,
          details: { providers: enabledProviders }
        });
      }
    }
  }

  // 2. Try to enumerate users (should be blocked)
  const usersUrl = `${baseUrl}/auth/v1/admin/users`;
  const usersRes = await safeFetch(usersUrl, { headers });

  if (usersRes.ok && usersRes.json?.users) {
    results.push({
      check: 'Auth — Admin Users Endpoint',
      status: 'FAIL',
      severity: 'critical',
      message: `Endpoint admin de users acessível! ${usersRes.json.users.length} usuário(s) exposto(s).`,
      details: {
        url: usersUrl,
        userCount: usersRes.json.users.length,
        recommendation: 'URGENTE: Este endpoint nunca deve ser acessível com anon key. Verifique configurações.'
      }
    });
  } else {
    results.push({
      check: 'Auth — Admin Users Endpoint',
      status: 'PASS',
      severity: 'info',
      message: 'Endpoint admin de users não acessível com anon key. ✓',
      details: { status: usersRes.status }
    });
  }

  // 3. Check signup endpoint
  const signupUrl = `${baseUrl}/auth/v1/signup`;
  const signupRes = await safeFetch(signupUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      email: 'test-audit@supabaseguard.local',
      password: 'AuditTest123!@#'
    })
  });

  // We don't actually want to create an account, just check if the endpoint responds
  if (signupRes.status === 200 || signupRes.status === 201) {
    results.push({
      check: 'Auth — Signup Active',
      status: 'WARN',
      severity: 'medium',
      message: 'Endpoint de signup está ativo e aceita registros.',
      details: {
        status: signupRes.status,
        recommendation: 'Verifique se signup público é intencional. Configure rate limiting.'
      }
    });
  } else if (signupRes.status === 422 || signupRes.status === 429) {
    results.push({
      check: 'Auth — Signup Protection',
      status: 'PASS',
      severity: 'info',
      message: 'Signup tem proteções ativas (validação ou rate limiting).',
      details: { status: signupRes.status }
    });
  }

  // 4. Check OTP / Magic Link endpoint
  const otpUrl = `${baseUrl}/auth/v1/otp`;
  const otpRes = await safeFetch(otpUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email: 'test@supabaseguard.local' })
  });

  if (otpRes.ok) {
    results.push({
      check: 'Auth — OTP/Magic Link',
      status: 'WARN',
      severity: 'low',
      message: 'Endpoint OTP/Magic Link está ativo.',
      details: {
        recommendation: 'Configure rate limiting para prevenir spam de emails.'
      }
    });
  }

  // 5. Check password recovery
  const recoveryUrl = `${baseUrl}/auth/v1/recover`;
  const recoveryRes = await safeFetch(recoveryUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email: 'test@supabaseguard.local' })
  });

  if (recoveryRes.ok) {
    results.push({
      check: 'Auth — Password Recovery',
      status: 'INFO',
      severity: 'info',
      message: 'Endpoint de password recovery está ativo.',
      details: {
        recommendation: 'Verifique rate limiting no endpoint de recovery.'
      }
    });
  }

  return results;
}

module.exports = { checkAuthEndpoints };
