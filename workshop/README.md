# Workshop - Securisation d'Applications Java Spring Boot

## Description

Ce workshop propose une formation pratique complète sur l'intégration de la sécurité dans le cycle de développement logiciel. Les participants travailleront sur une application bancaire Spring Boot **volontairement vulnérable** pour apprendre à :

- Identifier les vulnérabilités courantes (OWASP Top 10)
- Configurer des outils d'analyse de sécurité (SCA, SAST, DAST)
- Intégrer ces analyses dans un pipeline CI/CD
- Corriger les vulnérabilités détectées

## Avertissement

**Cette application contient des vulnérabilités INTENTIONNELLES à des fins pédagogiques.**

- Ne JAMAIS déployer en production
- Ne JAMAIS utiliser sur un réseau non isolé
- Utiliser uniquement dans un environnement de formation contrôlé

## Objectifs d'Apprentissage

A la fin de ce workshop, vous serez capable de :

1. **Analyser les dépendances** avec OWASP Dependency-Check et Trivy
2. **Générer un SBOM** (Software Bill of Materials) avec CycloneDX
3. **Configurer SonarQube** pour l'analyse statique (SAST)
4. **Utiliser Semgrep et SpotBugs** pour la détection de vulnérabilités
5. **Executer OWASP ZAP** pour les tests dynamiques (DAST)
6. **Integrer ces outils** dans GitLab CI/CD et GitHub Actions
7. **Corriger les vulnérabilités** identifiées

## Structure du Projet

```
workshop-devsecops/
├── vulnerable-app/              # Application vulnérable
│   ├── src/
│   │   ├── main/java/          # Code Java vulnérable
│   │   └── resources/          # Configuration et templates
│   ├── pom.xml                 # Dépendances (vulnérables)
│   ├── Dockerfile
│   └── sonar-project.properties
├── solutions/                   # Code corrigé
│   ├── src/main/java/          # Code Java sécurisé
│   └── pom.xml                 # Dépendances sécurisées
├── pipeline/                    # Configurations CI/CD
│   ├── .gitlab-ci.yml
│   └── .github/workflows/
├── docs/                        # Documentation
│   └── WORKSHOP-GUIDE.md       # Guide détaillé
└── docker-compose.yml          # Infrastructure de test
```

## Demarrage Rapide

### Prérequis

- Docker et Docker Compose
- Java 11+
- Maven 3.8+
- 8 Go de RAM minimum

### Installation

```bash
# Cloner le repository
git clone <repository-url>
cd workshop-devsecops

# Lancer l'infrastructure
docker-compose up -d

# Attendre que les services démarrent (2-3 minutes)
docker-compose ps

# Compiler l'application vulnérable
cd vulnerable-app
mvn clean package -DskipTests
```

### Accès aux Services

| Service | URL | Identifiants |
|---------|-----|--------------|
| Application | http://localhost:8080 | admin / admin123 |
| SonarQube | http://localhost:9000 | admin / admin |
| OWASP ZAP | http://localhost:8090 | - |
| Dependency-Track | http://localhost:8082 | admin / admin |
| Console H2 | http://localhost:8080/h2-console | admin / admin123 |

## Modules du Workshop

### Module 1 : Découverte (30 min)
- Explorer l'application vulnérable
- Identifier les vulnérabilités manuellement
- Exploiter les failles (SQL injection, XSS, IDOR)

### Module 2 : Analyse des Dépendances - SCA (45 min)
- OWASP Dependency-Check
- Génération SBOM avec CycloneDX
- Scan avec Trivy

### Module 3 : Analyse Statique - SAST (60 min)
- Configuration SonarQube
- Analyse avec Semgrep
- SpotBugs + Find Security Bugs

### Module 4 : Analyse Dynamique - DAST (60 min)
- OWASP ZAP Baseline Scan
- ZAP Full Scan
- Scan authentifié

### Module 5 : Corrections (90 min)
- Mise à jour des dépendances
- Correction injection SQL
- Correction XSS, CSRF, IDOR

### Module 6 : CI/CD (45 min)
- Pipeline GitLab CI/CD
- GitHub Actions
- Quality Gates


## Commandes Utiles

```bash
# Analyse des dépendances
mvn org.owasp:dependency-check-maven:check

# Génération SBOM
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom

# Analyse SonarQube
mvn sonar:sonar -Dsonar.host.url=http://localhost:9000

# Scan Trivy
docker run --rm -v $(pwd):/app aquasec/trivy:latest fs /app

# Scan ZAP
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:8080
```

## Ressources

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [SonarQube Documentation](https://docs.sonarqube.org/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Semgrep Rules](https://semgrep.dev/r)


