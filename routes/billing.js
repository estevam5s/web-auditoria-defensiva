// Rotas de billing/SaaS (Express) — Stripe + Supabase. Monte com mount(app).
const express = require('express');
const Stripe = require('stripe');
const { createClient } = require('@supabase/supabase-js');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE, { auth: { autoRefreshToken: false, persistSession: false } });
const SITE = process.env.SITE_URL || 'https://supabase-guard.up.railway.app';
const TRIAL = Number(process.env.TRIAL_DAYS || 7);

// ---- helpers ----
const BUCKET = new Map();
function rateLimit(key, max, win) { const n = Date.now(); const b = BUCKET.get(key); if (!b || n > b.reset) { BUCKET.set(key, { c: 1, reset: n + win }); return true; } if (b.c >= max) return false; b.c++; return true; }
function ip(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '0.0.0.0'; }
async function getUser(req) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  if (!t) return null;
  const { data } = await admin.auth.getUser(t);
  return data?.user || null;
}
async function isAdmin(uid) { const { data } = await admin.from('profiles').select('role').eq('id', uid).maybeSingle(); return data?.role === 'admin'; }

function mount(app) {
  // Webhook (corpo cru via req.rawBody capturado no express.json verify)
  app.post('/api/webhook', async (req, res) => {
    let event;
    try { event = stripe.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); }
    catch (e) { return res.status(400).send('sig error: ' + e.message); }
    const { error: dup } = await admin.from('payment_events').insert({ stripe_event_id: event.id, type: event.type, payload: event.data.object });
    if (dup && dup.code === '23505') return res.json({ received: true, duplicate: true });
    try {
      const o = event.data.object;
      if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated') {
        const priceId = o.items?.data?.[0]?.price?.id;
        const { data: plan } = await admin.from('plans').select('slug').or(`stripe_price_monthly.eq.${priceId},stripe_price_yearly.eq.${priceId}`).limit(1).maybeSingle();
        const patch = { status: o.status, billing_cycle: o.items?.data?.[0]?.price?.recurring?.interval === 'year' ? 'yearly' : 'monthly', stripe_subscription_id: o.id, stripe_customer_id: o.customer, current_period_end: o.current_period_end ? new Date(o.current_period_end * 1000).toISOString() : null, cancel_at_period_end: !!o.cancel_at_period_end };
        if (plan) patch.plan_slug = plan.slug;
        if (o.metadata?.user_id) await admin.from('subscriptions').update(patch).eq('user_id', o.metadata.user_id);
        else await admin.from('subscriptions').update(patch).eq('stripe_customer_id', o.customer);
      } else if (event.type === 'customer.subscription.deleted') {
        await admin.from('subscriptions').update({ plan_slug: 'inicial', status: 'canceled', billing_cycle: 'free', stripe_subscription_id: null }).eq('stripe_customer_id', o.customer);
      } else if (event.type === 'invoice.paid' || event.type === 'invoice.payment_succeeded') {
        const { data: sub } = await admin.from('subscriptions').select('user_id,plan_slug').eq('stripe_customer_id', o.customer).maybeSingle();
        await admin.from('payments').upsert({ user_id: sub?.user_id || null, stripe_invoice_id: o.id, stripe_customer_id: o.customer, amount: (o.amount_paid || 0) / 100, currency: o.currency, status: o.status, plan_slug: sub?.plan_slug || null, invoice_url: o.hosted_invoice_url }, { onConflict: 'stripe_invoice_id' });
      } else if (event.type === 'invoice.payment_failed') {
        if (o.customer) await admin.from('subscriptions').update({ status: 'past_due' }).eq('stripe_customer_id', o.customer);
      }
    } catch (e) { return res.status(500).json({ error: e.message }); }
    res.json({ received: true });
  });

  // Checkout
  app.post('/api/checkout', async (req, res) => {
    if (!rateLimit('chk:' + ip(req), 20, 60000)) return res.status(429).json({ error: 'rate_limited' });
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    const { plan_slug, cycle = 'monthly' } = req.body || {};
    const { data: plan } = await admin.from('plans').select('*').eq('slug', plan_slug).single();
    if (!plan || plan.billing_type === 'free') return res.status(400).json({ error: 'invalid_plan' });
    const priceId = cycle === 'yearly' ? plan.stripe_price_yearly : plan.stripe_price_monthly;
    if (!priceId) return res.status(400).json({ error: 'price_not_configured' });
    const { data: sub } = await admin.from('subscriptions').select('stripe_customer_id').eq('user_id', user.id).single();
    let customerId = sub?.stripe_customer_id;
    if (!customerId) { const c = await stripe.customers.create({ email: user.email, metadata: { user_id: user.id, app: 'auditoria' } }); customerId = c.id; await admin.from('subscriptions').update({ stripe_customer_id: customerId }).eq('user_id', user.id); }
    const meta = { user_id: user.id, plan_slug, cycle, app: 'auditoria' };
    const session = await stripe.checkout.sessions.create({ mode: 'subscription', customer: customerId, line_items: [{ price: priceId, quantity: 1 }], allow_promotion_codes: true, locale: 'pt-BR', metadata: meta, subscription_data: { trial_period_days: TRIAL, metadata: meta }, success_url: `${SITE}/dashboard.html?status=success`, cancel_url: `${SITE}/dashboard.html?status=cancelled` });
    res.json({ url: session.url });
  });

  // Portal
  app.post('/api/portal', async (req, res) => {
    const user = await getUser(req); if (!user) return res.status(401).json({ error: 'unauthorized' });
    const { data: sub } = await admin.from('subscriptions').select('stripe_customer_id').eq('user_id', user.id).single();
    if (!sub?.stripe_customer_id) return res.status(400).json({ error: 'no_customer' });
    const s = await stripe.billingPortal.sessions.create({ customer: sub.stripe_customer_id, return_url: `${SITE}/dashboard.html` });
    res.json({ url: s.url });
  });

  // Gestão de assinatura (cancelar c/ feedback, reativar, downgrade/upgrade, reembolso)
  app.post('/api/subscription', async (req, res) => {
    const user = await getUser(req); if (!user) return res.status(401).json({ error: 'unauthorized' });
    const { action, plan_slug, cycle, reason, comment } = req.body || {};
    const { data: sub } = await admin.from('subscriptions').select('*').eq('user_id', user.id).single();
    if (!sub) return res.status(404).json({ error: 'no_subscription' });
    try {
      if (action === 'cancel' || action === 'refund') {
        await admin.from('cancellation_feedback').insert({ user_id: user.id, plan_slug: sub.plan_slug, reason: reason || action, comment: comment || null });
        if (sub.stripe_subscription_id) await stripe.subscriptions.update(sub.stripe_subscription_id, { cancel_at_period_end: true });
        await admin.from('subscriptions').update({ cancel_at_period_end: true, canceled_at: new Date().toISOString() }).eq('user_id', user.id);
        if (action === 'refund') await admin.from('support_messages').insert({ user_id: user.id, email: user.email, priority: true, subject: `[Reembolso] ${sub.plan_slug}`, message: `Pedido de reembolso (7 dias). Motivo: ${reason || '—'}. ${comment || ''}` });
        return res.json({ ok: true, message: action === 'refund' ? 'Reembolso solicitado (até 7 dias).' : 'Cancelamento agendado para o fim do período.' });
      }
      if (action === 'reactivate') { if (sub.stripe_subscription_id) await stripe.subscriptions.update(sub.stripe_subscription_id, { cancel_at_period_end: false }); await admin.from('subscriptions').update({ cancel_at_period_end: false, canceled_at: null }).eq('user_id', user.id); return res.json({ ok: true, message: 'Assinatura reativada.' }); }
      if (action === 'change') {
        const { data: target } = await admin.from('plans').select('*').eq('slug', plan_slug).single();
        const { data: cur } = await admin.from('plans').select('*').eq('slug', sub.plan_slug).single();
        const newPrice = (cycle || 'monthly') === 'yearly' ? target.stripe_price_yearly : target.stripe_price_monthly;
        if (!target || target.billing_type === 'free' || !newPrice) return res.status(400).json({ error: 'invalid_target' });
        if (!sub.stripe_subscription_id) return res.status(409).json({ error: 'no_active_subscription', checkout: true });
        const ss = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);
        const up = Number(target.monthly_price) >= Number(cur?.monthly_price || 0);
        if (up) { await stripe.subscriptions.update(sub.stripe_subscription_id, { items: [{ id: ss.items.data[0].id, price: newPrice }], proration_behavior: 'always_invoice', metadata: { user_id: user.id, plan_slug, cycle, app: 'auditoria' } }); await admin.from('subscriptions').update({ plan_slug, billing_cycle: cycle, pending_plan_slug: null }).eq('user_id', user.id); return res.json({ ok: true, message: `Upgrade para ${target.name} aplicado.` }); }
        const sch = await stripe.subscriptionSchedules.create({ from_subscription: sub.stripe_subscription_id });
        await stripe.subscriptionSchedules.update(sch.id, { end_behavior: 'release', phases: [{ items: [{ price: (cycle === 'yearly' ? cur.stripe_price_yearly : cur.stripe_price_monthly), quantity: 1 }], start_date: sch.phases[0].start_date, end_date: ss.current_period_end }, { items: [{ price: newPrice, quantity: 1 }], metadata: { user_id: user.id, plan_slug, cycle } }] });
        await admin.from('subscriptions').update({ pending_plan_slug: plan_slug, pending_cycle: cycle, pending_effective_at: new Date(ss.current_period_end * 1000).toISOString() }).eq('user_id', user.id);
        return res.json({ ok: true, message: `Downgrade para ${target.name} agendado para o próximo ciclo.` });
      }
      if (action === 'delete_account') { await admin.from('cancellation_feedback').insert({ user_id: user.id, plan_slug: sub.plan_slug, reason: reason || 'delete_account', comment }); if (sub.stripe_subscription_id) { try { await stripe.subscriptions.cancel(sub.stripe_subscription_id); } catch (e) {} } await admin.auth.admin.deleteUser(user.id); return res.json({ ok: true, message: 'Conta excluída.' }); }
      res.status(400).json({ error: 'unknown_action' });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Pré-checagem de cadastro (e-mail real/duplicado/IP)
  const dns = require('dns').promises;
  app.post('/api/signup-check', async (req, res) => {
    const i = ip(req);
    if (!rateLimit('su:' + i, 30, 60000)) return res.status(429).json({ error: 'rate_limited' });
    const { email, mode } = req.body || {};
    if (mode === 'log') { await admin.from('signup_log').insert({ ip: i, email: email || null }); return res.json({ ok: true }); }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.json({ ok: false, message: 'E-mail inválido.' });
    const domain = email.split('@')[1];
    const real = await dns.resolveMx(domain).then((m) => m.length > 0).catch(() => dns.resolve(domain).then((a) => a.length > 0).catch(() => false));
    if (!real) return res.json({ ok: false, message: 'Este domínio de e-mail não recebe mensagens.' });
    const { data: prof } = await admin.from('profiles').select('id').eq('email', email).maybeSingle();
    if (prof) return res.json({ ok: false, message: 'Já existe uma conta com este e-mail.' });
    const since = new Date(Date.now() - 7 * 864e5).toISOString();
    const { count } = await admin.from('signup_log').select('id', { count: 'exact', head: true }).eq('ip', i).gte('created_at', since);
    if ((count || 0) >= 3) return res.json({ ok: false, message: 'Muitas contas criadas a partir desta rede.' });
    res.json({ ok: true });
  });

  // Admin (criar usuário máximo, responder suporte, set plano)
  app.post('/api/admin', async (req, res) => {
    const user = await getUser(req);
    if (!user || !(await isAdmin(user.id))) return res.status(403).json({ error: 'forbidden' });
    const { action } = req.body || {};
    try {
      if (action === 'create_user') { const { email, password, full_name, plan = 'enterprise', make_admin } = req.body; const { data: c, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name } }); if (error) return res.status(400).json({ error: error.message }); await admin.from('profiles').update({ role: make_admin ? 'admin' : 'user', plan_slug: plan, full_name }).eq('id', c.user.id); await admin.from('subscriptions').upsert({ user_id: c.user.id, plan_slug: plan, status: 'active', billing_cycle: 'yearly' }, { onConflict: 'user_id' }); return res.json({ ok: true, id: c.user.id }); }
      if (action === 'set_plan') { await admin.from('subscriptions').upsert({ user_id: req.body.user_id, plan_slug: req.body.plan, status: 'active', billing_cycle: 'yearly' }, { onConflict: 'user_id' }); await admin.from('profiles').update({ plan_slug: req.body.plan }).eq('id', req.body.user_id); return res.json({ ok: true }); }
      if (action === 'delete_user') { await admin.auth.admin.deleteUser(req.body.user_id); return res.json({ ok: true }); }
      if (action === 'reply_support') { const patch = { admin_reply: req.body.reply }; if (req.body.resolve !== undefined) patch.status = req.body.resolve ? 'resolved' : 'open'; await admin.from('support_messages').update(patch).eq('id', req.body.id); return res.json({ ok: true }); }
      res.status(400).json({ error: 'unknown_action' });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
}

module.exports = { mount };
