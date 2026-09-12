-- Which public client a code and a refresh family belong to.
--
-- There are two of them now: the Git workstation and qits-cli.  They differ by everything an
-- exchanged code is worth — the audience, the roles, the credential_type — so without this column
-- a code approved for the deliberately narrow Git credential could be spent as the wide one, and
-- the narrowness would be a suggestion rather than a rule.
--
-- Added nullable, backfilled, then made not null, so the statement works against a store that
-- already holds rows.  EVERY EXISTING ROW IS A WORKSTATION: qits-cli does not exist before this
-- migration, and the value is the shipped default of qits.idp.workstation.client-id.  A deployment
-- that overrode that key must backfill with its own value instead — but the check at exchange is a
-- string comparison against the configured id, so a mismatched backfill fails closed: the old
-- credential is refused and the workstation re-authorizes.  Nothing widens.
alter table idp_authorization_code add column client_id varchar(255);
update idp_authorization_code set client_id = 'qits-git-workstation' where client_id is null;
alter table idp_authorization_code alter column client_id set not null;

alter table idp_workstation_refresh_token add column client_id varchar(255);
update idp_workstation_refresh_token set client_id = 'qits-git-workstation' where client_id is null;
alter table idp_workstation_refresh_token alter column client_id set not null;

-- The devices page reads one user's families and groups them by client, and the refresh path locks
-- one row by its hash (already unique).  The existing (user_id, created_at) index carries the list;
-- this one is for the per-client reads the page and any future sweep make.
create index idx_idp_workstation_refresh_token_client on idp_workstation_refresh_token (client_id);
