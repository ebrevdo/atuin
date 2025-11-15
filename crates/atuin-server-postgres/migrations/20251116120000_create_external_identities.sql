create table if not exists external_identities (
    id bigserial primary key,
    user_id bigint not null references users(id) on delete cascade,
    provider text not null,
    subject text not null,
    display_claims jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists external_identities_provider_subject_idx
    on external_identities(provider, subject);

create index if not exists external_identities_user_idx
    on external_identities(user_id);

create or replace function set_external_identity_updated_at()
returns trigger as $$
begin
    new.updated_at = now();
    return new;
end;
$$ language plpgsql;

drop trigger if exists external_identities_set_updated_at on external_identities;

create trigger external_identities_set_updated_at
before update on external_identities
for each row execute function set_external_identity_updated_at();
