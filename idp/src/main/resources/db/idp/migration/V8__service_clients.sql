-- Service clients move into the database (service-client-identity-plan.md, contract C2).
--
-- WHY A NEW TABLE AND NOT A KIND COLUMN ON idp_client. idp_client's owner/context_kind/context_id
-- are NOT NULL and mean nothing for a service client: it has no owner and belongs to no dynamic
-- context. A kind column would make every service-client row carry three columns that exist only
-- to be ignored, and every reader of idp_client would need a branch it does not need today. A
-- second table costs one more repository and buys a shape that says what it holds.
--
-- WHAT THIS DOES NOT CHANGE. The token path stays off postgres for an ENVIRONMENT client: nothing
-- here touches IdpClients or the qits.idp.clients config registry. A database service client is
-- new: ServiceClients loads every row into a volatile map at start (the same shape SigningKeys and
-- DynamicClients already use) and writes through DbRetry.inNewTx, so token issuance for one is
-- still a map read rather than a query.
--
-- ROTATION KEEPS THE PREVIOUS SECRET LIVE FOR A GRACE WINDOW (D4). A start-first rollback to the
-- predecessor container must not be locked out the moment its successor rotates the shared secret,
-- so the row carries both hashes and a deadline for the old one rather than overwriting it outright.

create table idp_service_client (
  client_id            varchar(128) primary key,
  secret_hash          varchar(255) not null,
  previous_secret_hash varchar(255),
  previous_valid_until timestamptz,
  created_by           varchar(128) not null,
  created_at           timestamptz  not null,
  rotated_at           timestamptz
);

-- The one-time seed, so the platform's very first service client can exist before any other one
-- does (nothing to authenticate a POST /idp/api/service-clients with otherwise). id is pinned to 1
-- by the check constraint: there is exactly one row, ever, and its presence is the marker that
-- seeding already ran — QITS_IDP_SEED_CLIENT_ID/_SECRET are read at most once per installation,
-- never again once this row exists, even if the variables are still set on every later boot.
create table idp_seed (
  id        smallint primary key check (id = 1),
  client_id varchar(128) not null,
  seeded_at timestamptz not null
);
