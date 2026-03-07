/*  ═══════════════════════════════════════════════════════════════════
    AUTH SETTINGS: Comprehensive Authentication Analysis
    Extended detection of auth configuration, vulnerabilities
    Signup, email confirmation, providers, rate limiting
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function authSettingsScan(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const anonKey = config.anonKey;
  const headers = supabaseHeaders(anonKey);

  const settings = {
    signupOpen: null,
    emailAutoConfirm: null,
    phoneAutoConfirm: null,
    providers: [],
    rateLimiting: null,
    passwordPolicy: null,
    mfaEnabled: null,
    vulnerabilities: []
  };

  emit({ type: 'log', level: 'info', message: '[Auth Settings] Verificando configurações de autenticação...' });

  const settingsUrl = `${baseUrl}/auth/v1/settings`;
  const settingsRes = await safeFetch(settingsUrl, { headers, timeout: 10000 });

  if (settingsRes.ok && settingsRes.json) {
    const data = settingsRes.json;

    settings.signupOpen = data.disable_signup === false || data.disable_signup === null || data.disable_signup === undefined;
    settings.emailAutoConfirm = data.mailer_autoconfirm === true || data.email_confirm_changes === false;
    settings.emailConfirmDisabled = data.mailer_autoconfirm === true; // explicit flag for reporting
    settings.phoneAutoConfirm = data.phone_autoconfirm === true;

    if (data.external) {
      settings.providers = Object.entries(data.external)
        .filter(([_, v]) => v === true || v?.enabled === true)
        .map(([k]) => k);
    }

    settings.passwordPolicy = {
      minLength: data.password_min_length || 6,
      requireUppercase: data.password_require_uppercase || false,
      requireNumbers: data.password_require_numbers || false,
      requireSpecialChars: data.password_require_special_chars || false
    };

    emit({ type: 'log', level: 'info', message: `[Auth Settings] /auth/v1/settings -> 200 (signupOpen=${settings.signupOpen}, emailConfirmDisabled=${settings.emailConfirmDisabled})` });

    results.push({
      check: 'Auth Settings — Configuration',
      status: 'INFO',
      severity: 'info',
      message: 'Configurações de autenticação obtidas com sucesso.',
      details: {
        signupOpen: settings.signupOpen,
        emailAutoConfirm: settings.emailAutoConfirm,
        emailConfirmDisabled: settings.emailConfirmDisabled,
        phoneAutoConfirm: settings.phoneAutoConfirm,
        providers: settings.providers,
        passwordPolicy: settings.passwordPolicy
      }
    });

    if (settings.signupOpen) {
      settings.vulnerabilities.push('open_signup');
      results.push({
        check: 'Auth Settings — Open Signup',
        status: 'FAIL',
        severity: 'high',
        message: 'Auth hardening fraco: signup aberto — qualquer pessoa pode criar conta.',
        details: {
          vulnerability: 'open_signup',
          recommendation: 'Considere desabilitar signup público em Auth > Settings > Enable Email Signup se não for necessário.'
        }
      });
    }

    if (settings.emailConfirmDisabled) {
      settings.vulnerabilities.push('email_confirm_disabled');
      results.push({
        check: 'Auth Settings — Email Confirmation Disabled',
        status: 'FAIL',
        severity: 'medium',
        message: 'Auth hardening fraco: confirmação de email desabilitada — contas ativadas instantaneamente sem verificação.',
        details: {
          vulnerability: 'email_confirm_disabled',
          recommendation: 'Habilite confirmação de email em Auth > Settings > Enable email confirmations.'
        }
      });
    }

    if (settings.emailAutoConfirm) {
      settings.vulnerabilities.push('no_email_confirm');
      results.push({
        check: 'Auth Settings — No Email Confirmation',
        status: 'WARN',
        severity: 'medium',
        message: 'Auto-confirmação de EMAIL ativada. Contas ativadas instantaneamente.',
        details: {
          vulnerability: 'no_email_confirm',
          recommendation: 'Desabilite mailer_autoconfirm para exigir verificação de email.'
        }
      });
    }

    if (settings.phoneAutoConfirm) {
      settings.vulnerabilities.push('no_phone_confirm');
      results.push({
        check: 'Auth Settings — No Phone Confirmation',
        status: 'WARN',
        severity: 'medium',
        message: 'Auto-confirmação de TELEFONE ativada.',
        details: {
          vulnerability: 'no_phone_confirm',
          recommendation: 'Desabilite phone_autoconfirm para exigir verificação de SMS.'
        }
      });
    }

    if (settings.providers.length > 0) {
      results.push({
        check: 'Auth Settings — Providers',
        status: 'INFO',
        severity: 'info',
        message: `${settings.providers.length} provider(s) de auth: ${settings.providers.join(', ')}`,
        details: { providers: settings.providers }
      });
    }
  } else {
    emit({ type: 'log', level: 'warn', message: `[Auth Settings] /auth/v1/settings -> ${settingsRes.status}` });
  }

  emit({ type: 'log', level: 'info', message: '[Auth Settings] Testando endpoints de autenticação...' });

  const testEmail = `audit-${Date.now()}@supabaseguard.local`;

  const signupUrl = `${baseUrl}/auth/v1/signup`;
  const signupRes = await safeFetch(signupUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email: testEmail, password: 'Test1234!' }),
    timeout: 10000
  });

  if (signupRes.status === 200 || signupRes.status === 201) {
    settings.vulnerabilities.push('signup_accepts_requests');
    results.push({
      check: 'Auth Settings — Signup Endpoint',
      status: 'WARN',
      severity: 'medium',
      message: 'Signup endpoint aceita requisições.',
      details: {
        status: signupRes.status,
        response: signupRes.json,
        recommendation: 'Configure rate limiting no endpoint de signup.'
      }
    });
  } else if (signupRes.status === 429) {
    results.push({
      check: 'Auth Settings — Signup Rate Limited',
      status: 'PASS',
      severity: 'info',
      message: 'Signup endpoint tem rate limiting.',
      details: { status: signupRes.status }
    });
    settings.rateLimiting = true;
  }

  const otpUrl = `${baseUrl}/auth/v1/otp`;
  const otpRes = await safeFetch(otpUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email: testEmail }),
    timeout: 8000
  });

  if (otpRes.ok) {
    results.push({
      check: 'Auth Settings — OTP/Magic Link',
      status: 'INFO',
      severity: 'info',
      message: 'Endpoint OTP/Magic Link está ativo.',
      details: { recommendation: 'Configure rate limiting para prevenir spam.' }
    });
  }

  const recoveryUrl = `${baseUrl}/auth/v1/recover`;
  const recoveryRes = await safeFetch(recoveryUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email: testEmail }),
    timeout: 8000
  });

  if (recoveryRes.ok) {
    settings.vulnerabilities.push('recovery_active');
    results.push({
      check: 'Auth Settings — Password Recovery',
      status: 'WARN',
      severity: 'medium',
      message: 'Endpoint de recuperação de senha está ativo.',
      details: {
        recommendation: 'Implemente rate limiting e captcha no recovery.'
      }
    });
  }

  const verifyUrl = `${baseUrl}/auth/v1/verify`;
  const verifyRes = await safeFetch(verifyUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      email: testEmail,
      token: '123456',
      type: 'email_change'
    }),
    timeout: 8000
  });

  if (verifyRes.status === 400 || verifyRes.status === 401) {
    results.push({
      check: 'Auth Settings — Verify Endpoint',
      status: 'PASS',
      severity: 'info',
      message: 'Endpoint de verificação rejeita tokens inválidos (esperado).',
      details: { status: verifyRes.status }
    });
  }

  const userUrl = `${baseUrl}/auth/v1/user`;
  const userRes = await safeFetch(userUrl, { headers, timeout: 8000 });

  if (userRes.status === 200) {
    settings.vulnerabilities.push('user_endpoint_exposed');
    results.push({
      check: 'Auth Settings — User Endpoint',
      status: 'WARN',
      severity: 'high',
      message: 'Endpoint /auth/v1/user acessível com anon key!',
      details: {
        severity: 'high',
        recommendation: 'URGENTE: Este endpoint requer JWT válido, não anon key.'
      }
    });
  } else if (userRes.status === 401) {
    results.push({
      check: 'Auth Settings — User Endpoint Protected',
      status: 'PASS',
      severity: 'info',
      message: 'Endpoint /auth/v1/user requer autenticação válida.',
      details: { status: userRes.status }
    });
  }

  emit({ type: 'log', level: 'info', message: '[Auth Settings] Verificando segurança adicional...' });

  const adminUrl = `${baseUrl}/auth/v1/admin/users`;
  const adminRes = await safeFetch(adminUrl, { headers, timeout: 8000 });

  if (adminRes.ok && adminRes.json?.users) {
    settings.vulnerabilities.push('admin_users_exposed');
    results.push({
      check: 'Auth Settings — Admin Users Exposed',
      status: 'FAIL',
      severity: 'critical',
      message: `Endpoint admin expõe ${adminRes.json.users.length} usuário(s)!`,
      details: {
        severity: 'critical',
        userCount: adminRes.json.users.length,
        recommendation: 'URGENTE: Remova acesso anon ao endpoint admin.'
      }
    });
  }

  const anonymousUrl = `${baseUrl}/auth/v1/.json`;
  const anonRes = await safeFetch(anonymousUrl, { timeout: 5000 });

  if (anonRes.ok) {
    results.push({
      check: 'Auth Settings — Anonymous Access',
      status: 'WARN',
      severity: 'medium',
      message: 'Endpoint anónimo do auth está acessível.',
      details: { recommendation: 'Verifique se este acesso é intencional.' }
    });
  }

  if (settings.vulnerabilities.length > 0) {
    results.push({
      check: 'Auth Settings — Summary',
      status: settings.vulnerabilities.some(v => v.includes('admin') || v.includes('exposed')) ? 'FAIL' : 'WARN',
      severity: settings.vulnerabilities.some(v => v.includes('admin') || v.includes('exposed')) ? 'critical' : 'medium',
      message: `${settings.vulnerabilities.length} vulnerabilidade(s) de autenticação encontrada(s).`,
      details: {
        totalVulnerabilities: settings.vulnerabilities.length,
        vulnerabilities: settings.vulnerabilities,
        severity: settings.vulnerabilities.some(v => v.includes('admin') || v.includes('exposed')) ? 'critical' : 'medium',
        recommendation: 'Revise e corrija as configurações de autenticação no Dashboard.'
      }
    });
  } else {
    results.push({
      check: 'Auth Settings — Overall',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma vulnerabilidade crítica de autenticação detectada.',
      details: { vulnerabilities: [] }
    });
  }

  return { results, settings };
}

module.exports = { authSettingsScan };
