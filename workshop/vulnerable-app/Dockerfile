# ===========================================
# Dockerfile pour VulnerableBank
# ATTENTION: Configuration volontairement non sécurisée
# ===========================================

FROM maven:3.8.4-openjdk-11 AS build

WORKDIR /app

# Copier les fichiers de configuration Maven
COPY pom.xml .

# Télécharger les dépendances
RUN mvn dependency:go-offline -B

# Copier le code source
COPY src ./src

# Compiler l'application
RUN mvn clean package -DskipTests

# ===========================================
# Image de production
# ===========================================

FROM eclipse-temurin:11-jre

WORKDIR /app

# VULNÉRABILITÉ: Exécution en tant que root
# (Bonne pratique: utiliser un utilisateur non-root)

# Copier le JAR
COPY --from=build /app/target/*.jar app.jar

# Exposer le port
EXPOSE 8080

# VULNÉRABILITÉ: Pas de healthcheck
# VULNÉRABILITÉ: Debug activé en production

# Variables d'environnement
ENV JAVA_OPTS="-Xms256m -Xmx512m"

# Démarrer l'application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
