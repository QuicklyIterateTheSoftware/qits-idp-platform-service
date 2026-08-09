-- The idp schema. Two tables, and one of them is empty by design.
--
-- ONE V1 AND NO INHERITED LINEAGE. This file used to be the same two tables on H2; the store moved
-- to PostgreSQL, and the H2 lineage was deleted rather than continued. That was allowed by one
-- precondition and no other: the move is an UNWRAP AND A RE-BOOTSTRAP, so no database anywhere is
-- on the H2 lineage and no `V2__move_to_postgres.sql` had a reader. It costs a fresh idp state —
-- the signing key is generated again on the first start and every token minted before the move
-- stops verifying — which the re-bootstrap that rolls this out accepts. FROM HERE ON THE ORDINARY
-- RULE IS BACK: keep appending, never edit an applied migration, and a second clean start is not a
-- precedent.
--
-- The shape below is the H2 pair TRANSLATED, not redesigned: `clob` became `text` (the only type
-- that had no postgres spelling), and nothing else about either table moved. What is stored here
-- has identity semantics — a keypair and, later, a client — so the move changes the engine and
-- deliberately nothing else.

-- The signing keys. ROTATION IS A DATA CHANGE, not a schema change, and this table is shaped for
-- it: many rows may exist, the newest ACTIVE one signs, and every row is published in the JWKS so
-- a token minted before a rotation still verifies until it expires. A rotation is therefore
-- "insert a new ACTIVE row, set the old one RETIRED"; a cleanup is "delete RETIRED rows whose keys
-- can no longer have live tokens". Nothing here has to change for that to work.
--
-- NO PARTIAL UNIQUE INDEX ON "EXACTLY ONE ACTIVE", and the reason is no longer the engine's.
-- `unique (kid) where status = 'ACTIVE'` is available on postgres and is refused: a rotation
-- INSERTS the new active row before retiring the old one, so an index forbidding two would forbid
-- the intermediate state of the very statement order that performs the rotation. The reader
-- already resolves the newest ACTIVE row, which makes an overlap harmless rather than a boot
-- failure.
--
-- The check constraint is kept as it was written. It enumerates a two-value set that
-- IdpSigningKeyStatus also owns, which is a second list to keep in step — the price is paid for
-- the reader who meets the table without the code.
--
-- The private key is PKCS#8 PEM and the public key is X.509 SubjectPublicKeyInfo PEM — the public
-- half is stored rather than derived so the JWKS can be built without unwrapping the private key.
-- Both are `text`: a PEM has no length worth declaring, and the entity carries no @Lob, so
-- Hibernate binds them as ordinary strings against this column type.
create table idp_signing_key (
    kid varchar(64) not null primary key,
    algorithm varchar(16) not null,
    status varchar(16) not null check (status in ('ACTIVE', 'RETIRED')),
    private_key_pem text not null,
    public_key_pem text not null,
    created_at timestamp(6) with time zone not null,
    retired_at timestamp(6) with time zone
);

create index idx_idp_signing_key_status on idp_signing_key (status, created_at);

-- Dynamic clients — PHASE 2, and empty until then. It exists now so the phase that adds
-- POST/DELETE /idp/api/clients is an endpoint plus a repository and not a migration against a
-- live database. Nothing reads it yet; the static service clients are config, not rows
-- (see the idp jar's META-INF/microprofile-config.properties).
--
-- lease_expires_at is the lease: a registrar asks for a TTL, the row carries the deadline, and
-- expired rows are collected — an orphaned agent loses access with no cleanup code on the
-- registrar's side. registered_by names the static client that minted this one, which is what the
-- granting-template check is audited against.
create table idp_client (
    client_id varchar(128) not null primary key,
    secret_hash varchar(255) not null,
    audiences varchar(1024) not null,
    claims text,
    registered_by varchar(128),
    lease_expires_at timestamp(6) with time zone,
    created_at timestamp(6) with time zone not null
);

create index idx_idp_client_lease_expires_at on idp_client (lease_expires_at);
