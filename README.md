# qits-platform-idp

The platform's own identity provider. Phase 1 — this tree — is **machine identity only**: an RS256
signing key that survives restarts, a JWKS, an OIDC discovery document, and a `client_credentials`
token endpoint the platform's services authenticate to each other with.

There is no user, no login and no session here. Browser sessions stay at the gateway, which keeps
forwarding `X-Qits-User`; this service becomes the auth server that gateway points at in phase 3.

## The surface

Everything is served under `/idp`, the segment the gateway routes verbatim.

| path | what it is |
|---|---|
| `GET /idp/.well-known/openid-configuration` | discovery. An OIDC consumer configured with auth-server-url `http://qits-platform-idp:8080/idp` derives this URL itself. |
| `GET /idp/jwks` | the public signing keys, each with its `kid`. |
| `POST /idp/token` | `application/x-www-form-urlencoded`, `grant_type=client_credentials`. |
| `POST /idp/api/clients` | commission a credential for one dynamic context. |
| `GET /idp/api/clients` | the caller's own live commissions. |
| `DELETE /idp/api/clients/{clientId}` | decommission one. |
| `GET /idp/q/health/ready` | readiness, where the deployment convention expects it. |
| `GET /idp/` | the client — four routes, `/idp/login`, `/idp/register`, `/idp/clients` and `/idp/users`. |

### The client

`qits-platform-spa-idp` (Angular) is a submodule at `service/src/main/webui`, and Quinoa builds it
during `mvn package` and serves it from this process at `/idp/`.

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
      -d audience=prod-qits-deployments

The token is RS256, carries a `kid`, and says:

| claim | value |
|---|---|
| `iss` | `qits.idp.issuer` |
| `sub` | the client id |
| `aud` | the resolved audiences, always a JSON array |
| `iat`, `exp`, `jti` | issued now, valid for `qits.idp.token-ttl-seconds` (3600 by default) |
| `project`, `workspace`, `branch` | only when granted to the client, copied verbatim |

**Claims, not scopes.** `aud` names the service a token may be used at; the structured claims name
what it may be used for *within* that service. The idp states them and interprets nothing — a
resource service decides what a value permits, including whether `*` means "any".

Refusals are RFC 6749 §5.2: `invalid_client` (401, with a `WWW-Authenticate` challenge),
`invalid_request` / `unsupported_grant_type` / `invalid_target` (400).

## Clients

There are two kinds, and they differ in where the identity comes from: the **static service
clients** are config, because a platform service's identity is genuinely static, and the
**commissioned clients** are rows, because a build run or a workspace is not.

### Static service clients

`qits.idp.clients` lists the ids that exist; each one has
`qits.idp.client.<id>.secret`, `.audiences`, and `.claims.<name>`. The shipped list is the names
services are dialed by — `prod-qits-ci`, `qits-platform-artifacts`, `prod-qits-workspaces`,
`prod-qits-gateway` — and the full key reference is in
`idp/src/main/resources/META-INF/microprofile-config.properties`.

**An id is part of the config key**, so a renamed client takes its `qits.idp.client.<id>.*` lines
with it. `prod-qits-deployments` is an audience with no client: it receives tokens and mints none.

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
    #  "contextKind":"ci-run","contextId":"4711","createdAt":"2026-08-14T11:02:03.412Z"}

    # what this caller has out — for reconciling orphans after a crash
    curl -s -u prod-qits-ci:$SECRET http://qits-platform-idp:8080/idp/api/clients
    # 200
    # [{"clientId":"dyn-ci-run-4711-8Xq…","owner":"prod-qits-ci",
    #   "contextKind":"ci-run","contextId":"4711","createdAt":"…"}]

    # decommission — 204
    curl -s -X DELETE -u prod-qits-ci:$SECRET \
      http://qits-platform-idp:8080/idp/api/clients/dyn-ci-run-4711-8Xq…

The rules around them:

- **A commissioned client mints exactly like a service client.** Same `POST /idp/token`, same
  grant, same token shape — which is why docker's Bearer dance and `quarkus-oidc-client` need no
  second code path.
- **It is issued its owner's audiences and claims**, read from the owner's config when a token is
  minted. Full access for now; per-context scoping is the declared follow-up, and the owner +
  context-kind + context-id triple on the row is what it will attach to.
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

**Phase 3: users** — invites, the authorization-code flow, and the gateway cutover. See
`qits-idp-plan.md` in the qits superproject. Note that phase 2 landed in a different shape than
that plan describes: no lease TTL and no granting template, because a commissioned credential's
lifetime is its context's and its access is its owner's.
