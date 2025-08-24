# ========================================
# DOCKERFILE - AUDIT LOGS MICROSERVICE
# ========================================

# Stage 1: Build
FROM openjdk:17-jdk-slim AS builder

WORKDIR /app

# Copier les fichiers de configuration Maven
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

# Télécharger les dépendances (cache layer)
RUN chmod +x ./mvnw
RUN ./mvnw dependency:go-offline -B

# Copier le code source
COPY src src

# Construire l'application
RUN ./mvnw clean package -DskipTests

# Stage 2: Runtime
FROM openjdk:17-jre-slim

LABEL maintainer="audit-team"
LABEL description="Audit & Logs Microservice"
LABEL version="1.0.0"

# Créer utilisateur non-root pour sécurité
RUN groupadd -r audit && useradd -r -g audit audit

# Créer les répertoires nécessaires
RUN mkdir -p /app/logs /app/config /app/data
RUN chown -R audit:audit /app

WORKDIR /app

# Copier l'artifact depuis le stage de build
COPY --from=builder /app/target/*.jar app.jar

# Changer vers l'utilisateur non-root
USER audit

# Variables d'environnement
ENV JAVA_OPTS="-Xms512m -Xmx1g" \
    SPRING_PROFILES_ACTIVE=docker \
    SERVER_PORT=8080

# Port exposé
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/audit/health || exit 1

# Point d'entrée
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]