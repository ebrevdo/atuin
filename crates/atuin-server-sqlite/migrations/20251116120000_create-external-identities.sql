create table if not exists external_identities (
    id integer primary key autoincrement,
    user_id integer not null references users(id) on delete cascade,
    provider text not null,
    subject text not null,
    display_claims text
        check (display_claims is null or json_valid(display_claims)),
    created_at timestamp not null default (datetime('now')),
    updated_at timestamp not null default (datetime('now'))
);

create unique index if not exists external_identities_provider_subject_idx
    on external_identities(provider, subject);

create index if not exists external_identities_user_idx
    on external_identities(user_id);
