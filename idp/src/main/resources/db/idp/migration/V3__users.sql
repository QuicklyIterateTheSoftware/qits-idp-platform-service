-- Users. The idp stops being machine-only: an operator registers an account with a one-time token
-- minted at bootstrap, logs in with a passkey or a password, and holds a session the edge
-- introspects. Five tables, and every one of them exists because a decision in
-- user-authentication-plan.md (qits superproject, 2026-08-14) said so.
--
-- WHY THE USER ROW IS THIS SMALL. There is no email, no display name and — the one worth arguing
-- about — NO ROLE COLUMN. Roles are an assignment table from day one, because admins and plain
-- users will be told apart later and a set does not belong in a column. What a role PERMITS is a
-- later plan: the idp stores the strings and interprets none of them.
--
-- WHY SESSIONS ARE ROWS AND COOKIES ARE OPAQUE. The cookie carries 256 random bits; this store
-- holds its SHA-256 fingerprint, exactly like a commissioned client's secret. The edge introspects
-- and caches, so the database stays the single truth and logout is a row update rather than
-- cryptography. The alternative — a JWT cookie the edge verifies offline against the JWKS it
-- already holds — costs revocation and buys only idp-outage tolerance, which the edge's cache grace
-- buys back.
--
-- WHY PASSWORDS HASH DIFFERENTLY FROM SECRETS. `idp_client.secret_hash` is a plain SHA-256 and the
-- argument for it is written in ClientSecret: a commissioned secret is 256 bits of SecureRandom and
-- there is no guessing to slow down. A HUMAN-CHOSEN password is the case that argument does not
-- cover, so `idp_user.password_hash` holds a bcrypt digest under a `bcrypt:` prefix beside the
-- existing `sha-256:` one. The prefix exists precisely so a second scheme can land without a
-- migration, and this is it landing.
--
-- CAUSATION: these tables carry no causation columns, like `idp_signing_key` and `idp_client`
-- before them. This context has no compile-time dependency on any other qits module (AGENTS.md,
-- "Adding a dependency on another context"), so the causation stack is not on this classpath and
-- adding it to stamp a login would be the dependency that rule forbids.

-- One account. `username` is the identity everything else hangs off: it is what a passkey's
-- credential record is keyed by inside quarkus-security-webauthn, and it is what the edge injects
-- as `X-Qits-User` once sessions are gated.
--
-- `password_hash` IS NULLABLE ON PURPOSE. Passwordless is the default — an account registered with
-- a passkey has no password at all, and the column stays null until someone sets one. A null here
-- is "no password factor", never "empty password"; the code refuses a blank one on the way in.
--
-- USERS ARE PER-INSTALLATION. These rows survive deploys and restarts like every other idp row, and
-- are never shared or migrated between installations: the localhost platform now and a
-- domain-hosted one later each start from their own register token. That decision is what makes a
-- passkey's rp-id binding to `localhost` a non-issue rather than a migration problem.
create table idp_user (
    id uuid not null primary key,
    username varchar(128) not null unique,
    password_hash varchar(255),
    created_at timestamp(6) with time zone not null
);

-- The one-time registration ticket. It is a row minted through an API and printed by the bootstrap
-- — never a log line, because idp's logs ship to qits-observability and a credential must not ride
-- the log plane.
--
-- ONE-TIME USE IS `consumed_at`, NOT A DELETE. The row stays after it is spent so that an operator
-- can see a token was used and which account it made; `created_user_id` is that link. A registration
-- consumes the token and creates the user in ONE transaction, so there is no state where a token is
-- spent and no account exists.
--
-- `minted_by` is the client id of the caller that asked for it. Only a STATIC service client may
-- mint — the commissioning rule, reused verbatim: a credential handed to a build step or an agent
-- container must not be able to produce accounts.
--
-- The stored value is a `sha-256:` fingerprint, same scheme and same column width as
-- `idp_client.secret_hash`. The plaintext exists once, in the mint response.
create table idp_register_token (
    id uuid not null primary key,
    token_hash varchar(255) not null unique,
    minted_by varchar(128) not null,
    created_at timestamp(6) with time zone not null,
    consumed_at timestamp(6) with time zone,
    created_user_id uuid references idp_user (id)
);

-- Role assignments. Plain namespaced strings, `$app:$resource:$role`, with the middle segment
-- simply omitted until something needs it. A register-token registration writes two —
-- `qits-platform:admin` and `qits:admin` — and nothing else writes this table today.
--
-- NO ROLE CATALOG TABLE until a role carries data of its own. A catalog whose only column is the
-- name it is joined on is a second place to keep the same string.
--
-- The primary key is the pair, which is what makes granting a role twice a no-op at the store
-- rather than a check in code.
create table idp_user_role (
    user_id uuid not null references idp_user (id),
    role varchar(128) not null,
    created_at timestamp(6) with time zone not null,
    primary key (user_id, role)
);

-- One registered authenticator. THE COLUMNS BELOW ARE NOT A DESIGN — they are exactly
-- `WebAuthnCredentialRecord.RequiredPersistedData` from quarkus-security-webauthn 3.34.6, read off
-- the extension's own source, because that record is what `fromRequiredPersistedData` reassembles a
-- credential out of at login time. Its `username` field is the one member not stored here: the join
-- to `idp_user` carries it, and duplicating it would be a second spelling of the same account.
--
--   credential_id         base64url of the credential id. varchar(1364) is not a guess: the WebAuthn
--                         spec bounds a credential id at 1023 bytes, and base64url of 1023 bytes is
--                         1364 characters. It is the primary key because the spec requires it to be
--                         unique, and because a login arrives naming it and nothing else.
--   aaguid                the authenticator model's identity (all zeroes for the software ones).
--   public_key            X.509 SubjectPublicKeyInfo, as bytes. Stored as `bytea` rather than PEM
--                         because the extension hands over and takes back a byte[].
--   public_key_algorithm  the COSE algorithm identifier. NEGATIVE numbers (-7 for ES256, -257 for
--                         RS256), which is why the column is signed and why it is not an enum.
--   counter               the authenticator's signature counter. It is UPDATED on every login and
--                         that is the whole point of it: a counter that went backwards means a
--                         cloned authenticator, and webauthn4j refuses the login.
--
-- Many rows per user is the intended shape — a second authenticator is added while logged in, and
-- an account page that removes one is a delete here.
create table idp_webauthn_credential (
    credential_id varchar(1364) not null primary key,
    user_id uuid not null references idp_user (id),
    aaguid uuid not null,
    public_key bytea not null,
    public_key_algorithm bigint not null,
    counter bigint not null,
    created_at timestamp(6) with time zone not null
);

-- The login ceremony reads every credential a username has; the login itself reads exactly one by
-- its id, which the primary key already answers.
create index idx_idp_webauthn_credential_user on idp_webauthn_credential (user_id);

-- A browser session. `token_hash` is the `sha-256:` fingerprint of the opaque value in the
-- `qits-session` cookie, and the unique index on it is the lookup: introspection arrives with a
-- cookie value, hashes it, and reads one row.
--
-- THREE COLUMNS DECIDE WHETHER A SESSION IS LIVE, and they are deliberately not one. `expires_at`
-- is the absolute deadline written when the row is created (`qits.idp.session-ttl`, PT12H);
-- `revoked_at` is logout, set rather than deleted so a session that ended is distinguishable from
-- one that never existed. Neither is enforced by a constraint — a reader compares both against now,
-- because "expired" is a fact about the clock and not about the row.
--
-- Revocation lags at the edge by its introspection cache TTL, seconds, configurable, and stated in
-- the plan so nobody files it as a bug.
create table idp_session (
    id uuid not null primary key,
    token_hash varchar(255) not null unique,
    user_id uuid not null references idp_user (id),
    created_at timestamp(6) with time zone not null,
    expires_at timestamp(6) with time zone not null,
    revoked_at timestamp(6) with time zone
);

-- "Which sessions does this user have", for the account page that lists and revokes them, and for
-- the sweep that will eventually delete rows past their deadline.
create index idx_idp_session_user on idp_session (user_id, created_at);
