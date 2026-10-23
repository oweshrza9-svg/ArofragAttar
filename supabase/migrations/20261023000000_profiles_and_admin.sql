begin;

create type public.app_role as enum ('customer', 'admin');

create table public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    full_name text,
    phone text,
    role public.app_role not null default 'customer',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Automatically create a customer profile for each new Auth user.
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    insert into public.profiles (id, full_name, role)
    values (
        new.id,
        nullif(new.raw_user_meta_data ->> 'full_name', ''),
        'customer'::public.app_role
    )
    on conflict (id) do nothing;

    return new;
end;
$$;

revoke all on function public.handle_new_user()
    from public, anon, authenticated;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- Database-side admin check; SECURITY DEFINER avoids RLS recursion.
create function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.profiles as p
        where p.id = (select auth.uid())
          and p.role = 'admin'::public.app_role
    );
$$;

revoke all on function public.is_admin()
    from public, anon, authenticated;

grant execute on function public.is_admin() to authenticated;

-- Maintain updated_at automatically.
create function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

revoke all on function public.set_updated_at()
    from public, anon, authenticated;

create trigger profiles_set_updated_at
before update on public.profiles
for each row execute function public.set_updated_at();

-- Explicit table and column permissions.
revoke all on table public.profiles from anon, authenticated;

grant select on table public.profiles to authenticated;
grant update (full_name, phone)
    on table public.profiles to authenticated;

create policy "profiles_select_own"
on public.profiles
for select
to authenticated
using (id = (select auth.uid()));

create policy "profiles_select_admin"
on public.profiles
for select
to authenticated
using ((select public.is_admin()));

create policy "profiles_update_own"
on public.profiles
for update
to authenticated
using (id = (select auth.uid()))
with check (id = (select auth.uid()));

commit;