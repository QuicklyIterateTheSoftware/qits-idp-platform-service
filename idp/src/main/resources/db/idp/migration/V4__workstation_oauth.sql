-- Git workstations are public OAuth clients.  Authorization codes are short lived and single use;
-- refresh credentials are opaque, rotating values grouped by a revocable family.  Plain values never
-- reach this store: every lookup value is a sha-256 fingerprint just like sessions and client secrets.
create table idp_authorization_code (
    id uuid not null primary key,
    code_hash varchar(255) not null unique,
    user_id uuid not null references idp_user (id),
    redirect_uri varchar(2048) not null,
    code_challenge varchar(128) not null,
    created_at timestamp(6) with time zone not null,
    expires_at timestamp(6) with time zone not null,
    consumed_at timestamp(6) with time zone
);
create index idx_idp_authorization_code_user on idp_authorization_code (user_id, created_at);

create table idp_workstation_refresh_token (
    id uuid not null primary key,
    family_id uuid not null,
    token_hash varchar(255) not null unique,
    user_id uuid not null references idp_user (id),
    created_at timestamp(6) with time zone not null,
    expires_at timestamp(6) with time zone not null,
    used_at timestamp(6) with time zone,
    revoked_at timestamp(6) with time zone
);
create index idx_idp_workstation_refresh_token_user on idp_workstation_refresh_token (user_id, created_at);
create index idx_idp_workstation_refresh_token_family on idp_workstation_refresh_token (family_id);
