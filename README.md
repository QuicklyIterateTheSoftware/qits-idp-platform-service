# qits-idp-platform-service

The platform's own identity provider, for **machines and for people**, deployed as the
`qits-platform-idp` application.

The machine half is an RS256 signing key that survives restarts, a JWKS, an OIDC discovery document,
and a `client_credentials` token endpoint the platform's services authenticate to each other with,
plus a commission API for the credentials that belong to one dynamic context.

The user half is accounts: an operator registers with a one-time token minted at bootstrap, logs in
with a passkey (WebAuthn) or an optional password, and holds an opaque `qits-session` cookie that
the edge introspects here and turns into the `X-Qits-User` / `X-Qits-User-Id` / `X-Qits-Roles`
headers services already read. **There is no OAuth dance for the first-party UI** and no session at
the gateway any more: the edge is the single ingress and terminates the browser session against
this service. The model, the rollout order and the flags are `user-authentication-plan.md` in the
qits superproject.

## The surface

Everything is served under `/idp`, the segment the gateway routes verbatim.

| path | what it is |
|---|---|
| `GET /idp/.well-known/openid-configuration` | discovery. An OIDC consumer configured with auth-server-url `http://qits-platform-idp:8080/idp` derives this URL itself. |
| `GET /idp/jwks` | the public signing keys, each with its `kid`. |
| `GET /idp/authorize` | signed-in browser approval for the local Git workstation's Authorization Code + PKCE flow. |
| `POST /idp/token` | `application/x-www-form-urlencoded`: `client_credentials`, workstation `authorization_code`, or rotating workstation `refresh_token`. |
| `POST /idp/api/clients` | commission a credential for one dynamic context. |
| `GET /idp/api/clients` | the caller's own live commissions. |
| `DELETE /idp/api/clients/{clientId}` | decommission one. |
| `POST /idp/api/auth/register-options` | WebAuthn creation options. Guarded by a register token or a session. |
| `POST /idp/api/auth/register` | an attestation or a password → an account and a session. |
| `POST /idp/api/auth/login-options` | WebAuthn request options. Anonymous. |
| `POST /idp/api/auth/login` | an assertion or `{username, password}` → a session. |
| `POST /idp/api/auth/logout` | revoke the session and clear the cookie. |
| `POST /idp/api/auth/password` | set or replace the signed-in account's password. |
| `POST /idp/api/sessions/introspect` | what the edge asks a cookie about. Basic, static client. |
| `POST /idp/api/register-tokens` | mint a one-time register token. Basic, static client. |
| `GET /idp/api/workstations` | the signed-in user's revocable Git workstation credentials. |
| `DELETE /idp/api/workstations/{familyId}` | revoke one signed-in user's workstation refresh-token family. |
| `GET /idp/q/health/ready` | readiness, where the deployment convention expects it. |
| `GET /idp/` | the client — four routes, `/idp/login`, `/idp/register`, `/idp/clients` and `/idp/users`. |

### The client

`qits-idp-platform-frontend` (Angular) is a submodule at `service/src/main/webui`, and Quinoa builds
it during `mvn package` and serves it from this process at `/idp/`.

**The client and the protocol share one root**, which no sibling service does: everywhere else the
REST surface is `/<segment>/api`, one level below the SPA. Here `quarkus.rest.path` is `/idp`
itself, because OIDC fixes where a consumer looks. So `quarkus.quinoa.ignored-path-prefixes` names
the whole machine surface — `/api,/q,/.well-known,/token,/jwks`, matched after `/idp` is stripped —
and it is the only thing keeping a mistyped protocol path from being answered with the page. The
reasoning is in `service/src/main/resources/application.properties`, the proof in
`IdpPackagedSurfaceIT`, and the rule is that a new literal route lands with its prefix entry in the
same commit.

A token request authenticates with `client_secret_basic` **or** `client_secret_post`, never both,
and may name an `audience` (repeated or whitespace-separated). Naming none asks for every audience
the client is allowed.

    curl -s -X POST http://qits-platform-idp:8080/idp/token \
      -d grant_type=client_credentials \
      -d client_id=prod-qits-ci -d client_secret=... \
      -d audience=qits-deployments

The token is RS256, carries a `kid`, and says:

| claim | value |
|---|---|
| `iss` | `qits.idp.issuer` |
| `sub` | the client id |
| `aud` | the resolved audiences, always a JSON array |
| `iat`, `exp`, `jti` | issued now, valid for `qits.idp.token-ttl-seconds` (3600 by default) |
| `groups` | the client's configured roles, **plus `clients/<client id>`** — see below |
| `project`, `workspace`, `branch` | only when granted to the client, copied verbatim |

**Every client token names its own client.** `groups` — which `quarkus-oidc` reads as roles — always
ends with `clients/<the id in `sub`>`, stamped at mint time and configured nowhere. A role naming one
client is therefore held by that client alone, by construction rather than by grant, and a resource
service can write `@RolesAllowed("clients/prod-qits-projects")` for a route exactly one caller may
ever reach. It is additive: consumers allowlist the roles they care about, so the extra entry is
inert everywhere else.

That is why **`clients/` is a reserved namespace**: a `qits.idp.client.<id>.roles` line containing
one is refused with `invalid_request` (400) — another client's id and the client's own alike — and
the client mints nothing until it is removed. A user credential gets no such role: the workstation
token below carries `qits:git:external` and nothing more, so the machine identity a service gates on
cannot be reached through a login.

**Claims, not scopes.** `aud` names the service a token may be used at; the structured claims name
what it may be used for *within* that service. The idp states them and interprets nothing — a
resource service decides what a value permits, including whether `*` means "any". They reach a token
from two places: a static client's configured `qits.idp.client.<id>.claims.<name>`, and — for a
commissioned credential — the `claims` its commission stated, which is the narrower of the two by
construction.

Refusals are RFC 6749 §5.2: `invalid_client` (401, with a `WWW-Authenticate` challenge),
`invalid_request` / `unsupported_grant_type` / `invalid_target` (400).

### Local Git workstations

`qits login` uses a public OAuth client, `qits-git-workstation`, rather than receiving a service
credential. It starts `GET /idp/authorize` in the browser with `response_type=code`, an S256 PKCE
challenge, the fixed githost audience and an exact `http://127.0.0.1:<ephemeral-port>/…` callback.
The browser must already hold a `qits-session`; approval returns a two-minute, one-use code to that
loopback listener. Exchanging it at `/token` returns a fifteen-minute access token and a rotating,
opaque refresh token. Refresh-token replay revokes the entire family, and the account can revoke a
family through `/api/workstations`.

The access token is deliberately not the user's ordinary administrator identity: it has
`groups=["qits:git:external"]`, `credential_type=workstation`,
`git_ref_pattern=refs/heads/external/*`, and only the configured githost audience. The githost must
enforce that ref pattern for every update; no workstation token has `qits:system`.

## Clients

There are two kinds, and they differ in where the identity comes from: the **static service
clients** are config, because a platform service's identity is genuinely static, and the
**commissioned clients** are rows, because a build run or a workspace is not.

### Static service clients

`qits.idp.clients` lists the ids that exist; each one has
`qits.idp.client.<id>.secret`, `.audiences`, and `.claims.<name>`. The shipped list is the names
services are dialed by — `prod-qits-ci`, `qits-platform-artifacts`, `prod-qits-workspaces` — and
the full key reference is in
`idp/src/main/resources/META-INF/microprofile-config.properties`.

**An id is part of the config key**, so a renamed client takes its `qits.idp.client.<id>.*` lines
with it. `qits-deployments` is an audience with no client: it receives tokens and mints none.

**An audience IS a wire alias**, so how a service is planed decides how it is spelled. An
environment service carries its environment (`prod-qits-ci`); a platform service is its repository
name and nothing else — `qits-platform-artifacts`, and `qits-deployments` since the deployer became
one. Get the two sides out of step and the failure is a silent 401 at the resource service, with a
valid token nobody rejected here.

**No secret ships with any of them, and a client with a blank secret is unusable rather than open.**
An unconfigured deployment therefore issues nothing; `QITS_IDP_CLIENT_PROD_QITS_CI_SECRET=…` is what
turns a client on. This is the opposite reading from `qits.artifacts.token`, where a blank value
means "no guard" — the difference is that a guard with no secret protects a network that is already
trusted, while an issuer with no secret would mint identity for whoever asks.

### Commissioned clients

A service that provisions a **dynamic context** — one ci build run, one workspace, one agent
container — asks for a credential for that context and hands it back when the context ends. The
credential's lifetime *is* the context's: no lease, no TTL on the pair, nothing durable left behind.
The model, and which owner decommissions at which event, is `authenticated-reads-plan.md` in the
qits superproject.

Three verbs, all authenticated with **HTTP Basic carrying the caller's own client id and secret** —
the pair it already holds to get tokens with. No new audience, no bearer, no second credential to
distribute, and the idp does not have to validate its own tokens to answer.

    # commission — the secret is in this answer and nowhere else
    curl -s -u prod-qits-ci:$SECRET -H 'Content-Type: application/json' \
      -d '{"contextKind":"ci-run","contextId":"4711"}' \
      http://qits-platform-idp:8080/idp/api/clients
    # 201
    # {"clientId":"dyn-ci-run-4711-8Xq…","secret":"…","owner":"prod-qits-ci",
    #  "contextKind":"ci-run","contextId":"4711","claims":{},"createdAt":"2026-08-14T11:02:03.412Z"}

    # commission SCOPED — what this context is about, and therefore what the credential may act on
    curl -s -u prod-qits-workspaces:$SECRET -H 'Content-Type: application/json' \
      -d '{"contextKind":"workspace","contextId":"1101",
           "claims":{"project":"b03b84b1-1875-4071-9dbf-854550156258"}}' \
      http://qits-platform-idp:8080/idp/api/clients
    # 201, and every token it mints carries project=b03b84b1-…

    # what this caller has out — for reconciling orphans after a crash
    curl -s -u prod-qits-ci:$SECRET http://qits-platform-idp:8080/idp/api/clients
    # 200
    # [{"clientId":"dyn-ci-run-4711-8Xq…","owner":"prod-qits-ci",
    #   "contextKind":"ci-run","contextId":"4711","claims":{},"createdAt":"…"}]

    # decommission — 204
    curl -s -X DELETE -u prod-qits-ci:$SECRET \
      http://qits-platform-idp:8080/idp/api/clients/dyn-ci-run-4711-8Xq…

The rules around them:

- **A commissioned client mints exactly like a service client.** Same `POST /idp/token`, same
  grant, same token shape — which is why docker's Bearer dance and `quarkus-oidc-client` need no
  second code path.
- **It is issued its owner's audiences and roles**, read from the owner's config when a token is
  minted. So narrowing an owner's audiences narrows every credential it commissioned, at once.
- **Its claims are its own, and a commission narrows.** The optional `claims` member states what
  this context is *about* — `{"project":"<projectId>"}` for a workspace — and those land on the row
  and go into every token it mints, over the owner's grants for the same names and beside the ones
  it does not state. **`*` is refused with `invalid_request` (400)**, and that asymmetry is the
  whole rule: a concrete value is narrower than saying nothing (a resource service reads an absent
  claim as "unscoped" and answers it from roles), while `*` is the one value that is never a
  narrowing. The wildcard stays a deployment's configured grant on a service client, which an
  operator writes and a request cannot. Only `project`, `workspace` and `branch` may be stated; any
  other name is a 400. See `control/CommissionedClaims`.
- **Its self-role is its own, never its owner's.** `clients/dyn-…` is stamped from the id in `sub`,
  so a credential commissioned by a service cannot walk through a door held open for that service.
- **Only a static service client may commission.** A commissioned credential authenticates here —
  so a context can hand its own credential back — but `POST` refuses it, and the blast radius of a
  leaked one therefore stops at one context.
- **Decommission is deleting the row**, and it is immediate: the credential mints nothing from the
  next request onward. **Tokens it already minted live out their `exp`**, because validation is
  offline against the JWKS and there is no revocation list. With the shipped hour that grace is an
  hour — see `qits.idp.token-ttl-seconds`, where the trade is written down.
- **Only the owner may decommission or list**, or the credential itself for its own row. Anyone
  else is told exactly what a caller naming an id that never existed is told.
- **The secret is returned once.** The row holds a SHA-256 of it, so a dump of the idp's database
  mints nothing. A caller that lost the secret decommissions and commissions again.
- **The id reads in a listing** — `dyn-<kind>-<context slug>-<random>` — and cannot collide with a
  service client's name, because config is resolved first and no static id carries the prefix.

## Users

Accounts are **per-installation**. They live in this service's store and survive deploys and
restarts like every other idp row, and they are never shared or migrated between installations: the
localhost platform now and a domain-hosted one later each start from their own register token. That
is the decision that makes a passkey's binding to one host a non-issue.

The user row is minimal on purpose — an id, a unique username, an optional password hash — and
**there is no role column**. Roles are `idp_user_role`, an assignment table, from day one. The
strings are namespaced `$app:$resource:$role` with the middle segment omitted while unused; a
bootstrap registration grants `qits-platform:admin` and `qits:admin` and nothing else writes the
table today. The idp stores them and interprets none of them.

### Getting the first account

A register token is a row, minted through the API, printed by the bootstrap — never logged, because
this service's logs ship to qits-observability and a credential must not ride the log plane. It is
good for exactly one account, and only a **static** service client may mint one (the commissioning
rule, reused).

    # mint — the token is in this answer and nowhere else
    curl -s -X POST -u prod-qits-ci:$SECRET \
      http://qits-platform-idp:8080/idp/api/register-tokens
    # 201 {"id":"…","token":"CUiyE4rThoFF…","createdAt":"…"}

Registration is then two calls from the browser: `POST /idp/api/auth/register-options` with the
token and a username, which answers the WebAuthn creation options verbatim for
`navigator.credentials.create()`, and `POST /idp/api/auth/register` with the resulting attestation.
**The token is checked at the first call**, before any ceremony state exists, so an authenticator is
never asked to make a key that will be thrown away. The second call creates the account, stores the
passkey, spends the token, grants the two roles and opens a session — one transaction.

`{"password":"…"}` instead of an attestation registers without a passkey. That path exists for
automated callers and for the one browsing route with no secure context (see below).

### Logging in, and the session

`POST /idp/api/auth/login-options` then `.../login` with the assertion, or one `.../login` with
`{username, password}`. Either way the answer is the same four fields and a cookie:

    Set-Cookie: qits-session=<43 chars>; Path=/; Domain=wohlben.eu; Max-Age=43200; HttpOnly; SameSite=Lax

`Secure` is appended when the request — or `X-Forwarded-Proto` — says https. A domain bootstrap
sets `Domain=<parent domain>` so the apex and explicitly configured browser environment hosts share
one login; localhost leaves it host-only. `Path=/` because the cookie is for the **edge**, which
introspects it on requests to every segment, not for this service. The edge removes this named
cookie before proxying to machine-only registry, mirror, and git-host vhosts.

WebAuthn still runs only at the canonical apex origin. An unauthenticated environment navigation is
sent there with a return authority and path; after login or registration the SPA asks
`GET /idp/api/auth/return-location`. This service validates the authority against its configured
browser-host allow-list and returns an absolute location. A public query string therefore cannot
turn the login page into an open redirect.

An allow-list entry is either an exact authority or `*.<authority>`, which matches exactly one extra
label in front of it — `*.dev.wohlben.eu` allows `ci.dev.wohlben.eu` and refuses both
`a.b.dev.wohlben.eu` and the bare `dev.wohlben.eu`. The port is part of the authority, so
`*.dev.localhost:8080` refuses `ci.dev.localhost:9090`. One entry covers every per-service host of
an environment, which is what those hosts need; the session cookie already spans them through
`Domain=<parent domain>`, and WebAuthn is untouched because the ceremony still runs only at the
canonical origin.

The value is 256 random bits and nothing else. This store holds a `sha-256:` fingerprint of it, so a
dump of the idp's database logs nobody in, and the only way to learn anything from a cookie is
`POST /idp/api/sessions/introspect` — Basic, static client, the edge's own `{env}-qits-edge`
credential:

    curl -s -u prod-qits-edge:$SECRET -H 'Content-Type: application/json' \
      -d '{"token":"<cookie value>"}' \
      http://qits-platform-idp:8080/idp/api/sessions/introspect
    # 200 {"userId":"…","username":"alice","roles":["qits-platform:admin","qits:admin"],
    #      "expiresAt":"2026-08-15T05:48:00.427825Z"}
    # 404 for anything not live — unknown, expired or revoked alike

**An opaque cookie rather than a JWT the edge could verify offline** is the trade this service
makes: it costs one cached call per request and it buys revocation, because logout is a row update
and there is no revocation list to distribute. Revocation therefore lags at the edge by its own
cache TTL — seconds, configurable there, and stated so nobody files it as a bug.

Sessions expire absolutely, `qits.idp.session-ttl` after they open (PT12H). There is no sliding
renewal yet.

### Passkeys, and the one route without them

The ceremony is quarkus-security-webauthn used **as a library**: this service calls it, verifies the
attestation and the assertion itself, and issues its own session. The extension's built-in endpoints
are off and its own `quarkus-credential` cookie is never written.

`quarkus.webauthn.relying-party.id` and `.origins` are the browser-facing host, from
`QITS_IDP_WEBAUTHN_RP_ID` and `QITS_IDP_WEBAUTHN_ORIGINS`, defaulting to `localhost` and
`http://localhost:8080`. **A passkey is bound to the rp id it was registered under** and will not
assert under another — which costs nothing here, because accounts are per-installation anyway.

`localhost`, `*.localhost` and the loopback addresses are secure contexts over plain http by browser
rule, so passkeys work on `http://localhost:8080` with no TLS. The one route that is **not** a
secure context is a raw IP — `http://<wsl-ip>:8080`, today's Windows-browser path to this platform —
where `navigator.credentials` does not exist at all and only the password fallback logs in. TLS via
`QITS_DOMAIN`, or Windows reaching localhost again, dissolves it.

## The signing key

Generated on the first start that finds no active key, and stored in the `idp` datasource as PKCS#8
PEM with a random `kid`. Every start after that reads it back. **That row is the only reason a token
issued before a restart still verifies after one** — an idp pointed at a fresh or ephemeral database
rotates its key by accident and invalidates everything in flight.

The datasource is a **PostgreSQL database of this service's own**, provisioned for it and handed
over as the platform's generic resource triple: `QITS_RESOURCE_DB_URL`, `_USERNAME`, `_PASSWORD`.
`.config/qits/deployments.yml` declares `resources: postgresql:db`, which is what makes
qits-platform-deployments create the role and the database `qits_platform_idp` before the successor
container starts; at bootstrap, before any deployer exists, the CLI does the same. There is no
default and no fallback URL — a process handed none stops at Flyway rather than opening a store
nobody meant.

The table holds many keys with one active, so rotation is a data change: insert a new `ACTIVE` row,
retire the old one, and both keep being published until the old one's tokens have expired.
`SigningKeys.reload()` is what picks the change up.

## Building and running

`./mvnw verify` on a clone is the gate — no monorepo, no docker, no prior install. It does need two
things a clone alone does not have: **the client submodule and a node**.

    git submodule update --init      # service/src/main/webui, or the build stops at
                                     # "No package.json found in Web UI directory"

Node must be on `PATH` at the platform's pin or newer (22.22.0), because `verify` runs `package` and
Quinoa shells out to the host's npm. Nothing downloads a toolchain for you — that is deliberate, and
the fix for a machine with no node is node, not a config key. `./mvnw test` still needs neither, as
Quinoa is disabled in test mode.

The suite takes a free port (`service/src/test/resources/application.properties` sets
`quarkus.http.test-port=0`), because on the deployment host 8081 is the platform's npm registry.

    ./mvnw verify                    # the @QuarkusTest suite
    ./mvnw verify -DskipITs=false    # plus IdpPackagedSurfaceIT, against the fast-jar
    ./mvnw verify -Dnative           # plus the same IT, against the GraalVM binary

The suite opens a real PostgreSQL — zonky's binaries, resolved as ordinary Maven artifacts and
spawned as a child process. Still no docker.

`docker/Dockerfile` ships the native binary. Read its header before deploying: the container refuses
to boot without the `QITS_RESOURCE_DB_*` triple, and that is deliberate.

## What is not here yet

**Per-context permission scoping.** A commissioned credential gets its owner's whole access today.
The follow-up narrows it per context — ci may publish, a refinement container may not — on the rows
the commission API already writes, and is the same day the token lifetime is worth shrinking again.

**Authorization.** Roles are stored, reported by introspection and delivered to every service, and
**nothing enforces one yet**. Which route demands which role is a later plan, together with
per-context scoping on dynamic clients.

**Invites for user #2, and an account page.** The register-token API already has the shape an invite
needs — a session-authenticated user minting one — but the UX is undecided, and there is no listing
of a user's own authenticators or sessions to remove one from.

**Sliding session renewal, and "remember me".** The TTL is absolute. Logging in again is one
ceremony, so this is a comfort question rather than a blocker.

**An authorization-code flow for third-party apps.** Nothing first-party needs it — the UI is
first-party and the edge terminates its session — but the issuer core is ready if it ever comes.
Note that `qits-idp-plan.md`'s phase 3 described users arriving as an OAuth dance against this
service with the session at the gateway; that is superseded by `user-authentication-plan.md`, and
phase 2 also landed differently from that sketch (no lease TTL, no granting template).
