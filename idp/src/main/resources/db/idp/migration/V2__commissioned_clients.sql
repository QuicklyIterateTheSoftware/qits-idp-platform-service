-- Commissioned clients: idp_client stops being a placeholder and becomes the table the commission
-- API writes.
--
-- V1 SHIPPED THIS TABLE EMPTY AND NOTHING HAS EVER WRITTEN IT. That is what makes the destructive
-- statements below safe, and it is also what makes them the honest ones: `add column … not null`
-- with no default fails loudly against a table that turned out to hold rows, which is exactly the
-- reading to want if this assumption were ever wrong.
--
-- WHAT CHANGED IN THE MODEL, and why V1's shape did not fit it. V1 was written for a LEASE: a
-- registrar asked for a TTL, the row carried a deadline, and expired rows were collected. The
-- credential model replaced that (authenticated-reads-plan.md, 2026-08-14): a commissioned
-- credential's lifetime IS its context's lifetime, so the owner decommissions it when the context
-- ends and there is no deadline to store. A lease column nothing writes would be a lie about how
-- access ends, so it goes.
--
-- `audiences` and `claims` go for the same reason. A commissioned client is issued its OWNER's
-- audiences and claims, resolved from the owner's record at mint time — full access now, per the
-- plan — so nothing writes these columns either. Per-context scoping is the declared follow-up, and
-- it brings them back together with the code that reads them. A column no reader has is not
-- forward compatibility; it is a trap for whoever writes it first and sees nothing happen.
--
-- `registered_by` was already the owner; the rename only makes the column say what the API,
-- the entity and the plan all call it. A rename preserves whatever data exists, so it is safe
-- regardless of the emptiness argument above.

alter table idp_client rename column registered_by to owner;
alter table idp_client alter column owner set not null;

-- The context this credential was commissioned for. The owner's spelling in both fields; the idp
-- stores them and interprets neither. They exist from day one so that a reconcile can compare a
-- listing against live contexts, and so per-context permissions have something to attach to.
alter table idp_client add column context_kind varchar(32) not null;
alter table idp_client add column context_id varchar(256) not null;

-- The lease is gone with the model that needed it; its index goes with the column.
alter table idp_client drop column lease_expires_at;

-- Read from the owner at mint time, not stored. See the header.
alter table idp_client drop column audiences;
alter table idp_client drop column claims;

-- List-by-owner is the reconciliation read and the only query with a where clause. created_at
-- rides along so the ordering is the index's too.
create index idx_idp_client_owner on idp_client (owner, created_at);
