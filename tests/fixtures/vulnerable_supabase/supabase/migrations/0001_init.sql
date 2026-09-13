-- A deliberately-vulnerable Supabase schema for testing Tainted.

create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  display_name text
);

create table public.invoices (
  id uuid primary key,
  owner uuid not null,
  amount integer not null,
  memo text
);

create table public.notes (
  id uuid primary key,
  author uuid not null,
  body text
);

create table public.public_posts (
  id uuid primary key,
  title text,
  body text
);

-- profiles: RLS enabled with a correct ownership policy (SAFE — should NOT be flagged).
alter table public.profiles enable row level security;
create policy "profiles are self-readable"
  on public.profiles for select
  using (auth.uid() = user_id);

-- invoices: RLS ENABLED but the policy is permissive `true` (HOLE — everyone reads all rows).
alter table public.invoices enable row level security;
create policy "invoices readable"
  on public.invoices for select
  using (true);

-- notes: RLS NEVER ENABLED, and the client reads it directly (HOLE — no boundary at all).
-- (no alter table ... enable row level security)

-- public_posts: intentionally public content, RLS off (benign, but read by client).
