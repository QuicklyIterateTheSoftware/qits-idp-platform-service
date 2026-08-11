# qits-platform-idp as a GraalVM-native container IMAGE — the same shape as its siblings'
# docker/Dockerfile: a Mandrel builder stage compiles the binary, a minimal runtime stage carries
# only it.
#
# This file is not how the binary is built; it is how the binary is SHIPPED. `.sdkmanrc` names a
# GraalVM (25.0.2-graalce), so `sdk env && ./mvnw package -Dnative` produces
# `service/target/qits-idp` with no container involved.
#
# Build from the repo root:
#
#     docker build -t qits/idp:latest -f docker/Dockerfile .
#
# There is no client to build first and no npm anywhere: phase 1 of this service serves two JSON
# documents and a token endpoint. That is the one way this Dockerfile is shorter than its siblings'.
#
# --- this image does NOT run with an empty environment, and that is not a packaging bug ------------
# `docker run --rm qits/idp:latest` dies before the HTTP listener: the `idp` jar ships its datasource
# as ${QITS_RESOURCE_DB_URL} and its two siblings with NO fallback, so an unset triple leaves the
# expression unresolvable and the process stops at Flyway. IT IS DELIBERATELY LEFT THAT WAY (the
# qits-ci stance), and here the stake is higher than for any sibling:
#
#   THE SIGNING KEY LIVES IN THAT DATABASE. An idp that came up healthy against a store nobody meant
#   would generate a new keypair, and the next redeploy another one — invalidating every token in
#   flight, everywhere, with nothing in any log to say why. A container that refuses to start is the
#   failure you see; one that starts on a store of its own invention is the failure that hides for a
#   week.
#
# The triple is NOT set by hand. `.config/qits/deployments.yml` declares `resources: postgresql:db`,
# and qits-platform-deployments creates the role and the database on the tier's postgres before this
# container starts and injects all three; at bootstrap, before any deployer exists, the CLI does the
# same over plain JDBC. What a `docker run` by hand looks like, and what those two produce:
#
#   docker run \
#     -e QITS_RESOURCE_DB_URL=jdbc:postgresql://prod-qits-oci-postgresql:5432/qits_platform_idp \
#     -e QITS_RESOURCE_DB_USERNAME=qits_platform_idp \
#     -e QITS_RESOURCE_DB_PASSWORD=... \
#     -e QITS_IDP_CLIENT_PROD_QITS_CI_SECRET=... \
#     ...
#
# No volume, and that is the change: the store is a database on another host now, so this container
# keeps nothing that has to outlive it.
#
# --- what else a deployment owns ------------------------------------------------------------------
#
#   QITS_IDP_CLIENT_<ID>_SECRET
#                           EVERY STATIC CLIENT SHIPS WITHOUT A SECRET AND IS THEREFORE UNUSABLE.
#                           That is the safe direction — a blank secret is refused, never accepted —
#                           but it also means an idp nobody configured issues nothing at all, and
#                           the only symptom is `invalid_client` in the caller's log. The client ids
#                           are the names each service is DIALED by: prod-qits-ci,
#                           qits-platform-artifacts, prod-qits-workspaces, prod-qits-gateway.
#   QITS_IDP_ISSUER         the `iss` of every token and the base of every advertised endpoint.
#                           Defaults to http://qits-platform-idp:8080/idp, which is what consumers
#                           on qits-net use. Change it and EVERY consumer's configured issuer must
#                           change with it; a mismatch is rejected at validation.
#   QITS_OBSERVABILITY_URL  where OTLP export goes; absent qits-observability, the exporter logs a
#                           warning per export loudly enough to bury real lines
#                           (OTEL_SDK_DISABLED=true is the escape hatch).
#
# This image needs no docker socket and no git. It dials exactly one host — the postgres its
# datasource names — and otherwise only answers the callers that dial it.
#
# --- stage `build`: native-compile ----------------------------------------------------------------
# The builder JDK MUST be 25: native-image cannot read bytecode newer than its own JDK, and this
# project targets release 25.
FROM quay.io/quarkus/ubi9-quarkus-mandrel-builder-image:jdk-25 AS build
USER root
WORKDIR /src

# Fetch the Maven distribution first, keyed only on the wrapper files, so a source-only change does
# not re-download it.
COPY mvnw .
COPY .mvn/ .mvn/
RUN ./mvnw --version

# The whole reactor, not a module list. `-am` builds `service`'s dependency from source —
# `qits-idp-domain` is a version this repo never publishes, so a builder container with an empty
# ~/.m2 has nowhere else to get it. `.dockerignore` is what keeps this cheap.
COPY . .

# Tests are skipped because `./mvnw verify` on a clone is their gate (AGENTS.md); stopping at
# `package` rather than `verify` keeps IdpPackagedSurfaceIT out of the image build. Cap
# native-image RAM so the build is deterministic on small machines.
#
# --- where the two qits jars come from ------------------------------------------------------------
# This repo depends on qits-db-core (PatientPgDriver) and qits-arch-rules, which live only on the
# platform's own Maven repository. The CI recipe passes the address the step container can reach, and
# `.qits-maven-settings.xml` mirrors the `qits-maven` repository id onto it — an exact id match,
# which is what gets past Maven's external:http:* blocker without permitting arbitrary HTTP
# repositories. The ARG default is the developer-host address, so a plain host-side `docker build`
# still works.
ARG QITS_MAVEN_REPOSITORY_URL=http://localhost:8081/artifacts/maven/maven
ENV QITS_MAVEN_REPOSITORY_URL=$QITS_MAVEN_REPOSITORY_URL
RUN ./mvnw -B -ntp -s .qits-maven-settings.xml -pl service -am package -Dnative -DskipTests \
      -Dqits.maven.repository.url="$QITS_MAVEN_REPOSITORY_URL" \
      -Dquarkus.native.native-image-xmx=4g

# --- runtime --------------------------------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6
WORKDIR /work

# curl, so the container answers a docker healthcheck — the deployer injects one at `docker run`
# and polls it through `docker inspect`, and the probe runs INSIDE the container.
# UBI minimal already supplies curl-minimal; assert it is present without installing the
# conflicting full curl package.
RUN curl --version >/dev/null

# `quarkus.package.output-name` names the binary `qits-idp` (no -runner suffix), so the process is
# identifiable in `ps`/`docker top`. That name is spelled a third time in service/pom.xml as
# failsafe's `native.image.path`; all three move together.
COPY --from=build --chown=1001:root /src/service/target/qits-idp /work/qits-idp
RUN chmod +x /work/qits-idp

EXPOSE 8080
USER 1001

# Quarkus binds 127.0.0.1 outside dev mode, which inside a container means nothing can reach it —
# not the gateway, not a peer on qits-net.
ENTRYPOINT ["/work/qits-idp", "-Dquarkus.http.host=0.0.0.0"]
