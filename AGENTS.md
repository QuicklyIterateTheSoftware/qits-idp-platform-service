# qits-platform-idp — working notes

Read `README.md` first: it defines the surface, the token's shape, and where clients and keys come
from. This file is the working conventions on top of it.

## The rules that shape everything

**A clone of this repo alone builds and tests green** — no monorepo, no docker, no prior
`mvn install` elsewhere, no credentials. `./mvnw verify` is the gate, and it needs no port
argument — `service/src/test/resources/application.properties` sets `quarkus.http.test-port=0`.

**Clone-alone now means clone *and* `git submodule update --init`, plus a node on `PATH`.** This
service serves a client: `qits-platform-spa-idp` at `service/src/main/webui`, built by Quinoa during
`package` and served at `/idp/`. `verify` runs `package`, so both are required — an uninitialised
submodule is an empty directory and stops the build at "No package.json found in Web UI directory".
`./mvnw test` needs neither, because Quinoa is disabled in test mode, which is also why nothing
about the client can be proven by a `@QuarkusTest` (see `IdpPackagedSurfaceIT`).

**The one thing it now needs besides Maven Central** is the platform's own Maven repository, for
`qits-db-core` and `qits-arch-rules` — the patient driver every connection opens through, and the
test that refuses to let the datasource baseline go missing. `<repositories>` in the root pom points
at `${qits.maven.repository.url}` (the developer-host address by default); the image build overrides
it with `--build-arg QITS_MAVEN_REPOSITORY_URL`, and `.qits-maven-settings.xml` mirrors the
`qits-maven` repository id onto that address — an exact id match, which is what gets past Maven's
`external:http:*` blocker without permitting arbitrary HTTP repositories. The docker build moved to
`--network host` in the same commit, because buildkit needs it to reach the registry at all. Those
three files move together; a third platform jar needs none of them again.

**The baseline is not a formality here.** Every other service asks this one for a token, so a
postgres cutover that fails this pool fails the platform's whole call graph rather than one
application. `DatasourceBaselineTest` is three lines and fails the build naming any postgresql
datasource missing one of the three; the doctrine and the measurements are in the superproject's
`docs/project-setup-quinoa-angular.md`.

**Issuing a token for a STATIC client does not read postgres, and that has to stay true.**
`SigningKeys.signing()` and `published()` take a volatile cache, and a static client is four config
lookups. A commissioned client is a row, so `DynamicClients` caches a resolved one and only a miss
reaches the store — the map is bounded by live contexts, `decommission` evicts in the same call
that deletes, and misses are never cached, which is what makes both directions immediate. **One idp
process is assumed** (which is what this service is deployed as); a second instance would hold its
own copy of a row deleted at the first, and that is the day this needs a bounded entry age rather
than a bigger cache.

**Every seam that touches the store carries a `DbRetry`, and the rule is one boundary per use
case.** `SigningKeys.reload()` — the boot load and a rotation — plus `DynamicClients`' reads and
writes, plus `Users`, `RegisterTokens`, `Sessions` and `Registrations`. The writes use
`DbRetry.inNewTx`/`runInNewTx` rather than `DbRetry.call`: a commission is a bare insert, so the
retry has to own the transaction boundary to know which failures certainly did not commit, and a
lost commit acknowledgement must be reported rather than repeated — repeating it would leave a
second credential in the store that no owner ever heard of.

**The user-side classes add one shape worth knowing.** Each of `Users`, `RegisterTokens` and
`Sessions` owns its transaction in its public methods, and each also has package-private `…Row`
methods doing the same work *inside the caller's* transaction. That exists for exactly one caller:
`Registrations`, which puts a single boundary around the five writes a registration is — the
account, its factor, the token's consumption, the two roles, the session. A token spent against an
account that was never created leaves an installation with no way in and a one-time ticket gone, so
"all or none" here is not tidiness. Do not add a second composite operation without deciding which
of the two sets it uses; mixing them nests transactions.

The signing-key seam's shape is the part with the subtlety: the `synchronized` moved off `reload` and onto the private
`loadOnce`, so the retry sits **outside** the monitor and an attempt takes the lock and releases it
before the pause. A retry inside a monitor sleeps while holding it, which is why the placement rules
forbid it; the guard the lock exists for — two cold callers must not both generate a key — is
unchanged, because one load still commits before the next begins. What is no longer serialized is
the cache assignment, and two concurrent reloads writing complete key sets in either order is not a
disagreement worth a lock. `SigningKeyCutoverTest` is the proof.

**And it stays `DbRetry.call`, not `DbRetry.inNewTx`** — considered on 2026-08-11 and refused, so
that the question is not reopened by the write inside it. `inNewTx` owns the transaction boundary,
which here would have to sit either outside the monitor (a thread blocked on the lock would then be
holding an open transaction and its connection) or inside it (the pause back in the monitor, the
exact thing the paragraph above moved out). Both are worse shapes, and the safety they would buy is
already here: this write is generate-**or**-load, so a second attempt re-reads first and a key that
did commit is found rather than duplicated, and the ambiguous case `inNewTx` exists to refuse — a
failure the transaction manager reports — carries no connection marker for `DbRetry.call` to match,
so it is rethrown either way. A write without that re-read would need `inNewTx`; this one does not.

The store being PostgreSQL does not change that answer. `testdb/EmbeddedPg` starts **zonky's**
postgres — real binaries resolved as ordinary Maven artifacts, spawned as a child process — and
`testdb/EmbeddedPgConfigSource` hands its url, username and password to every `@QuarkusTest` at an
ordinal above `application.properties`, because the port is chosen at run time and cannot be written
down. Testcontainers is not on this classpath and must not arrive, and
`quarkus.devservices.enabled=false` says the same thing from the other side.

**`service/` compiles to a GraalVM native image.** `.sdkmanrc` names `25.0.2-graalce`. The
consequence to keep in your head here is narrower than in the siblings and more dangerous: this
service's whole job goes through JCA — `KeyPairGenerator`, `KeyFactory`, RS256 signing — and a
native image that lost a provider boots fine and cannot mint. `IdpPackagedSurfaceIT` mints a token
in the packaged process for exactly that reason; run it (`-DskipITs=false`, or `-Dnative`) after
touching anything about keys, secrets, or a JSON body.

**Two native traps this repo has already fallen into, both on 2026-08-14, both caught by `-Dnative`
and by nothing else:**

- **A `SecureRandom` in a static field** is instantiated during image generation and lands in the
  image heap with its seed baked in — every deployment of that binary would produce the same ids and
  secrets. GraalVM refuses to build it outright. Construct one per call — which is what
  `RandomSecret` does, and it is where every credential value (a commissioned secret, a register
  token, a session cookie) now comes from.
- **A resource method returning `jakarta.ws.rs.core.Response`** carries its entity as an `Object`,
  so the image builder has no type to register and the binary answers **500, "no properties
  discovered"**, while the JVM suite stays green. Return `RestResponse<T>` when a method needs a
  status or a header *and* a body; a plain `T` when it needs neither. `Response` is fine only where
  there is no entity at all (`noContent()`), and `@RegisterForReflection` is a workaround rather
  than the fix, because it leaves the signature still saying nothing.

**The `clients/` role namespace is minted, never granted.** Every `client_credentials` token's
`groups` ends with `clients/<the id in sub>` (`ClientRoles`, called from `TokenService`), and a
configured `roles` line under that prefix is refused where the roles are read (`IdpClients.find`,
400 `invalid_request`) — for another client's id and for the client's own alike. One guard covers
every surface because every surface resolves a client through that one lookup: the token endpoint,
the Basic-authenticated machine APIs, and a commissioned credential inheriting its owner's roles.
A new place that accepts roles from anywhere else has to call `refuseReserved` itself, and a new
mint that is not to a client credential must not stamp one — `TokenService.workstation` is the
standing example, and `@RolesAllowed("clients/<x>")` in a sibling service is what all of it is for.

**Never make the safe direction configurable.** A client with a blank secret is unusable. There is
no flag that turns that into "open", and adding one would make an unconfigured deployment issue
identity to whoever asks. `IdpTokenTest.aClientWithNoSecretIsUnusableRatherThanOpen` runs against
`prod-qits-workspaces` — a *shipped* client with no secret — rather than a fixture, so the test pins
the real default.

## Package and module conventions

`eu.wohlben.qits.idp.*`, split across maven modules with disjoint sub-packages so there is no split
package:

- `idp/` — `entity`, `persistence`, `control`, `error`. Framework-free in the sense that matters:
  no JAX-RS, no web stack. `control` owns the keys (`SigningKeys`), the JWKS document (`Jwks`), the
  issuer string (`Issuer`), the grant (`TokenService`) and the client registry — which is three
  classes: `IdpClients` (static, from config), `DynamicClients` (commissioned, from rows) and
  `ClientRegistry`, which is the only thing that knows both exist. The user half is four more:
  `Users`, `RegisterTokens`, `Sessions`, and `Registrations`, which is the only thing that knows
  those three exist — the same split as `ClientRegistry`, for the same reason. `PasswordHash` and
  `RandomSecret` are the two value helpers beside them.
- `service/` — `api` only, and it is the HTTP boundary plus the one bean the web stack demands:
  the two metadata routes, the token endpoint, the commission API, the user surface
  (`IdpAuthController`, `IdpSessionsController`, `IdpRegisterTokensController`), the shared
  machine-caller check (`BasicCaller`), the session cookie's spelling (`SessionCookie`), and two
  error mappers. `WebAuthnCredentials` lives here rather than in the domain because
  quarkus-security-webauthn is a web stack — it depends on quarkus-vertx-http and its ceremonies
  take a `RoutingContext` — and the domain jar's rule is that it does not.

**Two error vocabularies, and the difference is the caller.** `OAuthException` is RFC 6749's and its
mapper attaches `WWW-Authenticate: Basic` to every 401, because the machine surfaces authenticate
with a Basic pair. `AuthException` is the user surface's — two codes, `invalid_request` and
`invalid_credentials` — and its mapper sends **no** challenge, because these routes are called by a
browser with `fetch` and a Basic challenge there is a native credentials dialog in front of the
login page. A new route picks the one that matches who calls it, not the one nearest in the file.

**`TokenService` must not learn which half a client came from.** It asks `ClientRegistry` and gets
an `IdpClient` either way; a commissioned credential mints identically to a service client because
there is no branch to make it differ. That identity is the whole commission model working — docker's
Bearer dance and `quarkus-oidc-client` need no second code path — so a change that makes the token
endpoint check the kind of client it has is a change worth arguing about first.

The directories are `idp/` and `service/`; the artifactIds are `qits-idp-domain` and
`qits-idp-service` — generic coordinates would collide in a shared `~/.m2`.

## Addressing

`quarkus.rest.path=/idp`, **not** `/idp/api`. That is the one place this repo departs from the
sibling services, and it is not cosmetic: an OIDC consumer configured with auth-server-url
`http://qits-platform-idp:8080/idp` fetches `/idp/.well-known/openid-configuration` by its own
derivation and follows the document from there. An `/api` segment would move the discovery document off the path
every OIDC client computes. The commission API takes `@Path("/api/clients")` relative to
this — `/idp/api/clients` — which keeps the machine-admin surface separate without moving the
protocol.

**Everything added since goes under `/api` too, and that is why the ignore list has not had to
change**: `/api/auth/*`, `/api/sessions/introspect` and `/api/register-tokens` are all covered by
the single `/api` entry. Keep it that way — a route added as a new literal beside `/token` and
`/jwks` costs an ignore-list entry, an `IdpPackagedSurfaceIT` case, and the risk described below.
The one surface this rule does not cover is the extension's: quarkus-security-webauthn registers
`/idp/q/webauthn/*` (under `/q`, already ignored) and `/.well-known/webauthn` at the **root**,
outside `/idp` entirely, which the gateway therefore never routes to.

**That departure is what makes `quarkus.quinoa.ignored-path-prefixes` load-bearing here.** The
client mounts at `/idp/` like every sibling's, but because the REST surface is the segment rather
than `/idp/api`, the protocol routes sit directly beside the SPA's own. The SPA fallback answers any
unmatched path under `/idp` with `200 text/html`, so the list — `/api,/q,/.well-known,/token,/jwks`,
**relative**, matched after `/idp` is stripped — is the whole of what keeps a mistyped protocol path
a 404. Get it wrong and an OIDC consumer caches a page as its discovery document. Adding a literal
route means adding its entry and its `IdpPackagedSurfaceIT` case in the same commit.

The issuer string is spelled **once**, in `qits.idp.issuer`, and `Issuer` normalises it. The
discovery document's `token_endpoint` and `jwks_uri` are derived from it, and so is every token's
`iss`. Never configure an endpoint separately: a consumer rejects a token whose `iss` differs from
the discovery document's `issuer` by one character, and two config keys is how that character
appears.

## Untrusted input

`client_id` arrives on an unauthenticated request and is concatenated into a config key.
`IdpClients.find` checks membership in `qits.idp.clients` **before** it builds any key, which is
what keeps a caller from probing the config namespace. Keep that order.

Secrets are compared with `MessageDigest.isEqual`, never `String.equals` — the comparison is against
a value a caller may retry freely. `ClientSecret` is where both kinds do it: a configured value
compared as it is, a stored one compared as a SHA-256. That hash is deliberately not a password
hash — a commissioned secret is 256 bits of `SecureRandom` and there is nothing to slow a guesser
down, while the token path is the platform's whole call graph. The argument is in the class.

Client ids reach the log on a refusal, so `LoggableClientId.of` bounds what can be written there.
A **context id never reaches the log at all**: it is the caller's string and the generated client id
already carries a bounded slug of it.

`contextKind` and `contextId` arrive on an authenticated request and both end up inside a client id.
The kind is matched against a lowercase-slug pattern and refused outright; the id is slugged down to
`[a-z0-9-]` for the client id and stored raw, so what a listing shows an operator and what a
reconcile compares are the same string the owner sent.

**Randomness is generated per call, never from a static field.** A `SecureRandom` in a static is
instantiated during native-image generation and lands in the image heap with its seed baked in —
every deployment of that binary would then produce the same ids and secrets. GraalVM refuses to
build it (measured 2026-08-14, `DynamicClients` was written that way first), which is the only
reason this is a caught bug rather than a shipped one. `RandomSecret` is where the rule is written
down and where every credential value comes from; `SigningKeys.randomKid` keeps its own copy of the
idiom because a `kid` is an identifier rather than a secret.

**A username is an HTTP header value, and `Users.normaliseUsername` is where that is enforced.** It
leaves this service as `X-Qits-User`, injected by the edge and read by five services, so a name
carrying a carriage return would be a header-splitting hole in every one of them. Control
characters are refused; beyond that and the column's length the name is the user's own.

## Schema changes

`idp/src/main/resources/db/idp/migration/`, hand-written, its own lineage on its own datasource —
keep appending, never edit an applied migration. V1 is the keys and an empty client table, V2 fills
the client table in, V3 is the five user tables.

**One column set in V3 is not a design and must not be treated as one.** `idp_webauthn_credential`
is exactly `WebAuthnCredentialRecord.RequiredPersistedData` from quarkus-security-webauthn, read off
the extension's source — that record is what `fromRequiredPersistedData` rebuilds a verifiable
credential out of, so a field dropped from it is a login that cannot be checked. Its `username`
member is the one thing not stored, because the join to `idp_user` carries it. A Quarkus upgrade
that changes that record changes this table.

**The store is PostgreSQL, and the lineage restarted at V1 to say so.** The H2 lineage was deleted
rather than continued, on one precondition: the move is an **unwrap and a re-bootstrap**, so no
database anywhere is on it and no `V2__move_to_postgres.sql` had a reader. It costs a fresh idp
state — a new signing key, every token minted before the move stops verifying — which the
re-bootstrap accepts. The fresh V1 is the H2 pair **translated and not redesigned**: `clob` became
`text` and nothing else about either table moved, because what is stored here has identity
semantics. **A second clean start is not a precedent** — the ordinary rule (append, never edit) is
back from V1 onward.

The datasource is the platform's generic resource contract — `jdbc.url=${QITS_RESOURCE_DB_URL}` and
its two siblings, with **no fallback**, so a process that was handed nothing dies at Flyway instead
of opening a store nobody meant. `.config/qits/deployments.yml` carries the `resources:
postgresql:db` line that fills it, and the bootstrap CLI fills it for the seed container, since this
service boots before a deployer exists.

Two things about the shipped V1:

- `idp_signing_key` is shaped so **rotation is a data change**. Many rows, one `ACTIVE`, all
  published. Do not add a "one active key" partial unique index — postgres does have one now, and
  V1's header refuses it: a rotation inserts the new active row before retiring the old one, so the
  index would forbid the intermediate state of the very statement order that rotates. The reader
  already resolves the newest active row.
- `idp_client` was **empty on purpose** — and V2 is the migration that filled the shape in. It was
  written for a lease (a TTL the registrar asked for, a deadline on the row, expired rows
  collected); the credential model that shipped instead has no deadline, because a commissioned
  credential's lifetime is its context's. So V2 renames `registered_by` to `owner`, adds
  `context_kind` and `context_id`, and **drops `lease_expires_at`, `audiences` and `claims`**. The
  last two go because a commissioned client is issued its *owner's* audiences and claims, resolved
  at mint time — a column no reader has is not forward compatibility, it is a trap for whoever
  writes it first and sees nothing happen. Per-context scoping brings them back with the code that
  reads them.

  The `add column … not null` statements have no default, so they fail loudly against a table that
  turned out to hold rows. That is deliberate: nothing had ever written this table, and if that were
  somehow wrong it is worth stopping for.

## Adding a dependency on another context

Don't. This context has no compile-time dependency on any other qits module and must not grow one —
least of all on a service it issues tokens for. Everything it knows arrives as config.

## Tests

- App-level config lives in `service/src/main/resources/application.properties` and Quarkus merges
  it into the test config. **Never re-declare an app-level setting in test resources.** The suite's
  copy re-declares exactly one — `qits.idp.clients`, because a test client cannot be added without
  restating the list — and says so where it does.
- **Tokens are verified against `GET /idp/jwks`, over HTTP, never against a key reachable
  in-process** (`PublishedJwks`). Verifying in-process would pass with an empty, wrong, or
  private-key-leaking JWKS, and the JWKS is the only thing a real consumer sees.
- `SigningKeyPersistenceTest` exercises the restart seam the suite cannot actually restart:
  `SigningKeys.reload()` drops the cache and goes back to the database. A generate-on-every-load
  regression changes the `kid` there.
- `CommissionedClientsTest` is the commission API end to end, and its cases are the invariants
  rather than the endpoints: a commissioned client mints exactly what its owner may, the row holds
  no plaintext, decommission stops the minting on the very next request, only the owner (or the
  credential itself) may delete, a commissioned client may not commission, and the listing is the
  caller's own. The suite shares one application and therefore one store, so **every test names its
  own `contextKind`** and the listing case filters on it instead of assuming an empty table.
- `UserAuthenticationTest` is the user surface end to end, and its cases are the invariants: a
  register token makes exactly one account, the two bootstrap roles are granted as rows, the cookie
  carries exactly the attributes the plan fixed, a session introspects until it is revoked and not
  after, only a static client may mint or introspect, and every way a login can fail is one 401
  whose body is byte-for-byte the same. **The ceremony is real** —
  `quarkus-test-security-webauthn`'s emulated authenticator holds an EC keypair and signs actual
  assertions, so nothing here is a fixture that can go stale. Two things it constrains:
  `WebAuthnTestHardware` hard-codes the origin `http://localhost:8080`, which must be a
  **shipped** `quarkus.webauthn.origins` value (webauthn4j checks the origin inside the browser's
  own clientDataJSON, never the port the request arrived on — so a random test port is fine), and
  the emulator hashes `localhost` as the relying party, which the shipped rp id must therefore be.
  Every test invents its own username, because the suite shares one application and one store.
- `SessionLifetimeTest` costs its own application start to pin `qits.idp.session-ttl`, the way
  `TokenLifetimeTest` does for the token's. It is also the only place expiry is proven: the shipped
  twelve hours cannot be waited out, and expiry is the third of the three states — unknown, revoked,
  expired — that introspection has to refuse alike.
- `TokenLifetimeTest` costs its own application start to pin that `qits.idp.token-ttl-seconds` is
  honoured, in both places a caller reads a lifetime. The number is a trade (see the key's comment),
  and shrinking it again is the lever that closes the post-decommission grace — so the lever has to
  stay connected.
- `IdpPackagedSurfaceIT` runs the **packaged artifact** and asserts what a native build can silently
  lose: the build-time route prefixes, the shipped datasource *expression* (it hands the launched
  process `QITS_RESOURCE_DB_URL` and its two siblings — the generic contract a deployment supplies —
  rather than restating the datasource keys, so the jar's own `${…}` indirection is what is under
  test), Flyway's migrations surviving as resources, and RSA key generation plus signing in the
  packaged process. **The commission round trip is there too** — commission, mint, decommission,
  refused — because every step of it is a thing native can lose quietly: record deserialization
  needs reflection registration, SHA-256 needs a JCA provider, and the table only exists if `V2`
  survived the packaging. **The user round trip is there for the same reason and is the heavier
  case** — register a passkey, log in with it, introspect, log out: the ceremony is JCA end to end
  (`KeyFactory.getInstance("EC")` rebuilding the stored key, `SHA256withECDSA` verifying the
  assertion), webauthn4j parses CBOR reflectively, four request and response records need types the
  image builder can see, and `V3` has to have survived as a resource for any of the five tables to
  exist. A binary that lost any of it boots, answers the discovery document, and verifies no login.
  Its embedded postgres reaches the profile through a **system property**, because
  a `QuarkusTestProfile` is instantiated in two classloaders and a static field is not shared
  between them. **The client's probes are here for the same reason** — Quinoa is off in test mode,
  so `/idp/` is served by nothing during the `@QuarkusTest` suite: that the page arrives with the
  matching `<base href>`, that a deep link falls back to it, and that every ignored prefix answers
  404 rather than HTML are all packaged-only facts.
