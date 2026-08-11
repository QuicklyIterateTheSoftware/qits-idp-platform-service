# qits-platform-idp — working notes

Read `README.md` first: it defines the surface, the token's shape, and where clients and keys come
from. This file is the working conventions on top of it.

## The rules that shape everything

**A clone of this repo alone builds and tests green** — no monorepo, no docker, no prior
`mvn install` elsewhere, no credentials, and (unlike every sibling) no node either: this service
serves no client in phase 1, so there is no Quinoa and no webui submodule. `./mvnw verify` is the
gate, and it needs no port argument — `service/src/test/resources/application.properties` sets
`quarkus.http.test-port=0`.

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

**One seam carries a `DbRetry` on top of that, and only one.** Issuing a token does not read
postgres — `SigningKeys.signing()` and `published()` take a volatile cache — so the only calls a
cutover can reach are the boot load and a rotation, both through `SigningKeys.reload()`, which is
wrapped. The shape is the point: the `synchronized` moved off `reload` and onto the private
`loadOnce`, so the retry sits **outside** the monitor and an attempt takes the lock and releases it
before the pause. A retry inside a monitor sleeps while holding it, which is why the placement rules
forbid it; the guard the lock exists for — two cold callers must not both generate a key — is
unchanged, because one load still commits before the next begins. What is no longer serialized is
the cache assignment, and two concurrent reloads writing complete key sets in either order is not a
disagreement worth a lock. `SigningKeyCutoverTest` is the proof.

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
touching anything about keys.

**Never make the safe direction configurable.** A client with a blank secret is unusable. There is
no flag that turns that into "open", and adding one would make an unconfigured deployment issue
identity to whoever asks. `IdpTokenTest.aClientWithNoSecretIsUnusableRatherThanOpen` runs against
`prod-qits-gateway` — a *shipped* client with no secret — rather than a fixture, so the test pins
the real default.

## Package and module conventions

`eu.wohlben.qits.idp.*`, split across maven modules with disjoint sub-packages so there is no split
package:

- `idp/` — `entity`, `persistence`, `control`, `error`. Framework-free in the sense that matters:
  no JAX-RS, no web stack. `control` owns the keys (`SigningKeys`), the JWKS document (`Jwks`), the
  client registry (`IdpClients`), the issuer string (`Issuer`) and the grant (`TokenService`).
- `service/` — `api` only: the two metadata routes, the token endpoint, and the RFC 6749 error
  mapper.

The directories are `idp/` and `service/`; the artifactIds are `qits-idp-domain` and
`qits-idp-service` — generic coordinates would collide in a shared `~/.m2`.

## Addressing

`quarkus.rest.path=/idp`, **not** `/idp/api`. That is the one place this repo departs from the
sibling services, and it is not cosmetic: an OIDC consumer configured with auth-server-url
`http://qits-platform-idp:8080/idp` fetches `/idp/.well-known/openid-configuration` by its own
derivation and follows the document from there. An `/api` segment would move the discovery document off the path
every OIDC client computes. Phase 2's registration API takes `@Path("/api/clients")` relative to
this, which keeps the machine-admin surface separate without moving the protocol.

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
a value a caller may retry freely.

Client ids reach the log on a refusal, so `TokenService.loggable` bounds what can be written there.

## Schema changes

`idp/src/main/resources/db/idp/migration/`, hand-written, its own lineage on its own datasource —
keep appending, never edit an applied migration.

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
- `idp_client` is **empty on purpose** — phase 2's dynamic agent clients. Nothing reads it yet.
  Deleting it because it is unused would put a migration against a live database into the phase that
  adds the endpoint.

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
- `IdpPackagedSurfaceIT` runs the **packaged artifact** and asserts what a native build can silently
  lose: the build-time route prefixes, the shipped datasource *expression* (it hands the launched
  process `QITS_RESOURCE_DB_URL` and its two siblings — the generic contract a deployment supplies —
  rather than restating the datasource keys, so the jar's own `${…}` indirection is what is under
  test), Flyway's migration surviving as a resource, and RSA key generation plus signing in the
  packaged process. Its embedded postgres reaches the profile through a **system property**, because
  a `QuarkusTestProfile` is instantiated in two classloaders and a static field is not shared
  between them.
