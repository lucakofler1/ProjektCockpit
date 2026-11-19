-- =====================================================================
--  Projekt-Cockpit · Supabase-Setup            (Cockpit von Luca Kofler)
--  Einmal komplett im Supabase "SQL Editor" einfügen und auf "Run" klicken.
--  Kann gefahrlos erneut ausgeführt werden.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Tabellen ----------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  username    text unique not null,
  name        text not null default '',
  email       text default '',
  is_admin    boolean not null default false,
  can_create  boolean not null default false,
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.pending_signups (
  email          text primary key,
  username       text not null,
  name           text not null default '',
  contact_email  text default '',
  is_admin       boolean not null default false,
  can_create     boolean not null default false,
  created_at     timestamptz not null default now()
);

create table if not exists public.projects (
  id          text primary key,
  data        jsonb not null default '{}'::jsonb,
  created_by  uuid references auth.users(id) on delete set null,
  updated_at  timestamptz not null default now()
);

create table if not exists public.tasks (
  id          text primary key,
  project_id  text not null references public.projects(id) on delete cascade,
  data        jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now()
);
create index if not exists tasks_project_idx on public.tasks(project_id);

-- ---------- Hilfsfunktionen ----------
create or replace function public.cockpit_is_active() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select active from public.profiles where id = auth.uid()), false)
$$;

create or replace function public.cockpit_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin and active from public.profiles where id = auth.uid()), false)
$$;

create or replace function public.cockpit_can_create() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select (is_admin or can_create) and active from public.profiles where id = auth.uid()), false)
$$;

create or replace function public.cockpit_is_member(p jsonb) returns boolean
language sql stable as $$
  select exists (
    select 1 from jsonb_array_elements(coalesce(p->'members','[]'::jsonb)) m
    where m->>'accountId' = auth.uid()::text)
$$;

-- Hat die eigene Rolle im Projekt mindestens eines der Rechte?
create or replace function public.cockpit_can(p jsonb, perms text[]) returns boolean
language sql stable as $$
  select coalesce(bool_or(coalesce((r->'perms'->>x)::boolean, false)), false)
  from jsonb_array_elements(coalesce(p->'members','[]'::jsonb)) m
  join jsonb_array_elements(coalesce(p->'roles','[]'::jsonb)) r on r->>'id' = m->>'roleId'
  cross join unnest(perms) x
  where m->>'accountId' = auth.uid()::text
$$;

-- Zugriff auf ein Projekt (perms = null → nur Mitgliedschaft nötig)
create or replace function public.cockpit_project_access(pid text, perms text[] default null) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.projects p
    where p.id = pid and public.cockpit_is_active() and (
      public.cockpit_is_admin() or p.created_by = auth.uid() or
      case when perms is null then public.cockpit_is_member(p.data)
           else public.cockpit_can(p.data, perms) end))
$$;

create or replace function public.cockpit_project_owner(pid text) returns uuid
language sql stable security definer set search_path = public as $$
  select created_by from public.projects where id = pid
$$;

-- ---------- Row Level Security ----------
alter table public.profiles        enable row level security;
alter table public.pending_signups enable row level security;
alter table public.projects        enable row level security;
alter table public.tasks           enable row level security;

drop policy if exists "profiles_read"   on public.profiles;
drop policy if exists "profiles_update" on public.profiles;
drop policy if exists "profiles_delete" on public.profiles;
create policy "profiles_read"   on public.profiles for select to authenticated using (public.cockpit_is_active());
create policy "profiles_update" on public.profiles for update to authenticated using (public.cockpit_is_admin()) with check (public.cockpit_is_admin());
create policy "profiles_delete" on public.profiles for delete to authenticated using (public.cockpit_is_admin());

drop policy if exists "pending_admin" on public.pending_signups;
create policy "pending_admin" on public.pending_signups for all to authenticated
  using (public.cockpit_is_admin()) with check (public.cockpit_is_admin());

drop policy if exists "projects_read"   on public.projects;
drop policy if exists "projects_insert" on public.projects;
drop policy if exists "projects_update" on public.projects;
drop policy if exists "projects_delete" on public.projects;
create policy "projects_read" on public.projects for select to authenticated
  using (public.cockpit_is_active() and (public.cockpit_is_admin() or created_by = auth.uid() or public.cockpit_is_member(data)));
create policy "projects_insert" on public.projects for insert to authenticated
  with check (public.cockpit_can_create() and created_by = auth.uid());
create policy "projects_update" on public.projects for update to authenticated
  using (public.cockpit_project_access(id, array['projekt_bearbeiten','handbuch_bearbeiten','mitglieder_verwalten','rollen_verwalten']))
  with check (public.cockpit_is_admin() or created_by is not distinct from public.cockpit_project_owner(id));
create policy "projects_delete" on public.projects for delete to authenticated
  using (public.cockpit_project_access(id, array['projekt_loeschen']));

drop policy if exists "tasks_read"   on public.tasks;
drop policy if exists "tasks_insert" on public.tasks;
drop policy if exists "tasks_update" on public.tasks;
drop policy if exists "tasks_delete" on public.tasks;
create policy "tasks_read" on public.tasks for select to authenticated
  using (public.cockpit_project_access(project_id));
create policy "tasks_insert" on public.tasks for insert to authenticated
  with check (public.cockpit_project_access(project_id, array['aufgaben_erstellen']));
create policy "tasks_update" on public.tasks for update to authenticated
  using (public.cockpit_project_access(project_id, array['aufgaben_alle_bearbeiten','aufgaben_eigene_bearbeiten','aufgaben_zuweisen','aufgaben_erstellen','kommentieren']))
  with check (public.cockpit_project_access(project_id, array['aufgaben_alle_bearbeiten','aufgaben_eigene_bearbeiten','aufgaben_zuweisen','aufgaben_erstellen','kommentieren']));
create policy "tasks_delete" on public.tasks for delete to authenticated
  using (public.cockpit_project_access(project_id, array['aufgaben_loeschen']));

-- ---------- Registrierung sperren ----------
-- Das allererste Konto wird Admin. Danach entstehen Konten NUR,
-- wenn ein Admin sie in der Benutzerverwaltung freigegeben hat.
create or replace function public.cockpit_handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare pend public.pending_signups%rowtype;
begin
  if not exists (select 1 from public.profiles) then
    insert into public.profiles (id, username, name, is_admin, can_create)
    values (new.id,
            lower(coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1))),
            coalesce(new.raw_user_meta_data->>'name',''), true, true);
    return new;
  end if;
  select * into pend from public.pending_signups where email = lower(new.email);
  if not found then
    raise exception 'Registrierung nicht erlaubt';
  end if;
  insert into public.profiles (id, username, name, email, is_admin, can_create)
  values (new.id, pend.username, pend.name, pend.contact_email, pend.is_admin, pend.can_create);
  delete from public.pending_signups where email = pend.email;
  return new;
end $$;

drop trigger if exists cockpit_on_auth_user_created on auth.users;
create trigger cockpit_on_auth_user_created
  after insert on auth.users for each row execute function public.cockpit_handle_new_user();

-- ---------- Funktionen für die App ----------
create or replace function public.cockpit_needs_setup() returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.profiles)
$$;

create or replace function public.cockpit_admin_set_password(target uuid, new_password text) returns void
language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not public.cockpit_is_admin() then raise exception 'Nur für Admins'; end if;
  if length(coalesce(new_password,'')) < 8 then raise exception 'Passwort zu kurz'; end if;
  update auth.users set encrypted_password = extensions.crypt(new_password, extensions.gen_salt('bf')),
                        updated_at = now()
   where id = target;
  delete from auth.sessions where user_id = target;   -- alte Anmeldungen beenden
end $$;

create or replace function public.cockpit_admin_delete_user(target uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.cockpit_is_admin() then raise exception 'Nur für Admins'; end if;
  if target = auth.uid() then raise exception 'Du kannst dich nicht selbst löschen'; end if;
  delete from auth.users where id = target;
end $$;

-- Gesperrte Konten sofort abmelden
create or replace function public.cockpit_on_profile_update() returns trigger
language plpgsql security definer set search_path = public, auth as $$
begin
  if new.active = false and old.active = true then
    delete from auth.sessions where user_id = new.id;
  end if;
  return new;
end $$;
drop trigger if exists cockpit_profile_updated on public.profiles;
create trigger cockpit_profile_updated after update on public.profiles
  for each row execute function public.cockpit_on_profile_update();

revoke execute on function public.cockpit_admin_set_password(uuid, text) from anon;
revoke execute on function public.cockpit_admin_delete_user(uuid) from anon;
grant execute on function public.cockpit_needs_setup() to anon, authenticated;

-- ---------- Live-Updates ----------
do $$ begin
  begin alter publication supabase_realtime add table public.projects; exception when others then null; end;
  begin alter publication supabase_realtime add table public.tasks;    exception when others then null; end;
  begin alter publication supabase_realtime add table public.profiles; exception when others then null; end;
end $$;

-- Fertig ✓

-- ---------- Update: Benutzer bearbeiten (Benutzername & eigener Name) ----------
create or replace function public.cockpit_admin_set_username(target uuid, new_username text, login_domain text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare u text := lower(trim(coalesce(new_username,'')));
begin
  if not public.cockpit_is_admin() then raise exception 'Nur für Admins'; end if;
  if u !~ '^[a-z0-9][a-z0-9._-]{1,39}$' then raise exception 'Ungültiger Benutzername'; end if;
  if exists (select 1 from public.profiles where username = u and id <> target) then
    raise exception 'Benutzername already exists';
  end if;
  update public.profiles set username = u where id = target;
  update auth.users set email = u || '@' || login_domain, updated_at = now() where id = target;
  update auth.identities set identity_data = identity_data || jsonb_build_object('email', u || '@' || login_domain), updated_at = now()
   where user_id = target and provider = 'email';
end $$;
revoke execute on function public.cockpit_admin_set_username(uuid, text, text) from anon;

create or replace function public.cockpit_update_my_name(new_name text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.cockpit_is_active() then raise exception 'Nicht erlaubt'; end if;
  if length(trim(coalesce(new_name,''))) = 0 then raise exception 'Name fehlt'; end if;
  update public.profiles set name = trim(new_name) where id = auth.uid();
end $$;
revoke execute on function public.cockpit_update_my_name(text) from anon;

-- ---------- Update: Benutzer-Sichtbarkeit ----------
-- Admins sehen alle Benutzer, alle anderen nur sich selbst und Personen aus gemeinsamen Projekten.
create or replace function public.cockpit_shares_project(other uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.projects p
    where (p.created_by = auth.uid() or public.cockpit_is_member(p.data))
      and (p.created_by = other or exists (
            select 1 from jsonb_array_elements(coalesce(p.data->'members','[]'::jsonb)) m
            where m->>'accountId' = other::text)))
$$;
drop policy if exists "profiles_read" on public.profiles;
create policy "profiles_read" on public.profiles for select to authenticated
  using (public.cockpit_is_active() and (public.cockpit_is_admin() or id = auth.uid() or public.cockpit_shares_project(id)));
