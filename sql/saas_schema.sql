-- Supabase Guard — schema SaaS (perfis + suporte + segurança + admin + cotas de auditoria).
-- Idempotente. Roda sobre o billing da skill (plans/subscriptions/payment_events/cancellation_feedback).

create extension if not exists "pgcrypto";

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text, full_name text, role text not null default 'user',
  plan_slug text default 'inicial', referral_source text, created_at timestamptz default now(), updated_at timestamptz default now()
);
alter table public.profiles add column if not exists role text not null default 'user';
alter table public.profiles add column if not exists plan_slug text default 'inicial';
alter table public.profiles add column if not exists referral_source text;
alter table public.profiles enable row level security;
drop policy if exists prof_self on public.profiles;
create policy prof_self on public.profiles for select using (auth.uid() = id or public.is_admin());
drop policy if exists prof_upd on public.profiles;
create policy prof_upd on public.profiles for update using (auth.uid() = id or public.is_admin());
drop policy if exists prof_ins on public.profiles;
create policy prof_ins on public.profiles for insert with check (auth.uid() = id);
drop policy if exists prof_admin on public.profiles;
create policy prof_admin on public.profiles for all using (public.is_admin()) with check (public.is_admin());

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public as $$
begin
  insert into public.profiles (id, email, full_name, referral_source)
  values (new.id, new.email, new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'referral_source')
  on conflict (id) do nothing; return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
drop trigger if exists trg_touch_prof on public.profiles;
create trigger trg_touch_prof before update on public.profiles for each row execute function public.touch_updated_at();

-- Auditorias por usuário (cota mensal por plano)
create table if not exists public.user_audits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  target_url text, project_ref text, status text default 'done',
  score int, findings jsonb default '{}'::jsonb, created_at timestamptz default now()
);
create index if not exists idx_ua_user on public.user_audits(user_id, created_at desc);
alter table public.user_audits enable row level security;
drop policy if exists ua_own on public.user_audits;
create policy ua_own on public.user_audits for all using (user_id = auth.uid() or public.is_admin()) with check (user_id = auth.uid());

create or replace function public.enforce_audit_quota()
returns trigger language plpgsql security definer set search_path=public as $$
declare v_slug text; v_limit int; v_count int;
begin
  select coalesce(plan_slug,'inicial') into v_slug from public.subscriptions where user_id = new.user_id;
  select (limits->>'auditorias_mes')::int into v_limit from public.plans where slug = coalesce(v_slug,'inicial');
  if v_limit is null or v_limit < 0 then return new; end if;
  select count(*) into v_count from public.user_audits where user_id = new.user_id and created_at >= date_trunc('month', now());
  if v_count >= v_limit then
    raise exception 'Limite de % auditorias/mês do seu plano atingido. Faça upgrade.', v_limit using errcode='P0001';
  end if; return new;
end; $$;
drop trigger if exists trg_audit_quota on public.user_audits;
create trigger trg_audit_quota before insert on public.user_audits for each row execute function public.enforce_audit_quota();

create table if not exists public.support_messages (
  id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id) on delete cascade,
  email text, subject text not null, message text not null, priority boolean default false,
  status text not null default 'open', admin_reply text, created_at timestamptz default now(), updated_at timestamptz default now()
);
alter table public.support_messages enable row level security;
drop policy if exists sm_self on public.support_messages;
create policy sm_self on public.support_messages for select using (user_id = auth.uid() or public.is_admin());
drop policy if exists sm_ins on public.support_messages;
create policy sm_ins on public.support_messages for insert with check (user_id = auth.uid());
drop policy if exists sm_admin on public.support_messages;
create policy sm_admin on public.support_messages for all using (public.is_admin()) with check (public.is_admin());

create table if not exists public.signup_log (id uuid primary key default gen_random_uuid(), ip text not null, email text, user_id uuid, created_at timestamptz default now());
create index if not exists idx_signup_ip on public.signup_log(ip, created_at desc);
alter table public.signup_log enable row level security;
drop policy if exists su_admin on public.signup_log; create policy su_admin on public.signup_log for select using (public.is_admin());

create table if not exists public.payments (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id) on delete set null, stripe_invoice_id text unique, stripe_customer_id text, amount numeric(12,2) default 0, currency text default 'brl', status text, plan_slug text, invoice_url text, created_at timestamptz default now());
alter table public.payments enable row level security;
drop policy if exists pay_self on public.payments; create policy pay_self on public.payments for select using (user_id = auth.uid() or public.is_admin());

create table if not exists public.visitor_events (id bigint generated always as identity primary key, product text default 'auditoria', path text, ip text, country text, city text, device text, browser text, referer text, created_at timestamptz default now());
alter table public.visitor_events enable row level security;
drop policy if exists vis_admin on public.visitor_events; create policy vis_admin on public.visitor_events for select using (public.is_admin());

create table if not exists public.audit_logs (id bigint generated always as identity primary key, actor uuid, actor_email text, level text default 'info', action text not null, target text, meta jsonb default '{}'::jsonb, created_at timestamptz default now());
alter table public.audit_logs enable row level security;
drop policy if exists au_admin on public.audit_logs; create policy au_admin on public.audit_logs for select using (public.is_admin());

grant select, insert, update, delete on public.user_audits, public.support_messages to authenticated;
grant select, update on public.profiles to authenticated;
grant select on public.payments to authenticated;
grant all on public.profiles, public.user_audits, public.support_messages, public.signup_log, public.payments, public.visitor_events, public.audit_logs to service_role;
