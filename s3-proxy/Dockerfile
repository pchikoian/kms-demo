# ── build stage ──────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Cache dependency downloads separately from source changes
COPY pom.xml .
RUN mvn dependency:go-offline -q

COPY src ./src
RUN mvn package -DskipTests -q

# ── runtime stage ─────────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/target/s3-proxy.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
