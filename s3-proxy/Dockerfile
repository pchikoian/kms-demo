# ── build stage ───────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# 1. Install the upstream s3proxy submodule into the local Maven repo.
#    Only re-runs when the submodule source changes.
COPY s3proxy-upstream/pom.xml           s3proxy-upstream/pom.xml
COPY s3proxy-upstream/src               s3proxy-upstream/src
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN cd s3proxy-upstream \
    && git init -q \
    && git config user.email "build@docker" \
    && git config user.name "Docker" \
    && git commit --allow-empty -qm "init" \
    && mvn install -DskipTests -q

# 2. Resolve s3-proxy dependencies (cached layer).
COPY s3-proxy/pom.xml s3-proxy/pom.xml
RUN cd s3-proxy && mvn dependency:go-offline -q

# 3. Build the envelope-encryption proxy.
COPY s3-proxy/src s3-proxy/src
RUN cd s3-proxy && mvn package -DskipTests -q

# ── runtime stage ─────────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/s3-proxy/target/s3-proxy.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
