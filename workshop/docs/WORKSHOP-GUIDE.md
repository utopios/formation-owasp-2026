# Workshop DevSecOps : Sécurisation d'une Application Java Spring Boot

## Objectifs du Workshop

Ce workshop vous permettra de :

1. **Comprendre** les vulnérabilités courantes dans une application Java Spring Boot
2. **Configurer** une analyse des dépendances (SCA - Software Composition Analysis)
3. **Implémenter** une analyse statique du code (SAST)
4. **Réaliser** une analyse dynamique (DAST)
5. **Corriger** les vulnérabilités identifiées
6. **Intégrer** ces analyses dans un pipeline CI/CD

## Prérequis

### Logiciels requis

- Docker et Docker Compose
- Java 11 ou supérieur
- Maven 3.8+
- Git
- Un IDE (IntelliJ IDEA, VS Code, Eclipse)
- curl ou Postman pour les tests API

### Vérification de l'environnement

```bash
# Vérifier Docker
docker --version
docker-compose --version

# Vérifier Java
java -version
mvn -version

# Vérifier Git
git --version
```

## Architecture du Workshop

```
workshop/
├── vulnerable-app/          # Application Spring Boot vulnérable
│   ├── src/
│   │   ├── main/java/      # Code source Java
│   │   └── resources/      # Configuration et templates
│   ├── pom.xml             # Dépendances Maven (vulnérables)
│   ├── Dockerfile          # Image Docker
│   └── sonar-project.properties
├── pipeline/               # Configurations CI/CD
│   ├── .gitlab-ci.yml     # Pipeline GitLab
│   └── .github/workflows/ # Pipeline GitHub Actions
├── solutions/              # Corrections des vulnérabilités
├── docs/                   # Documentation
└── docker-compose.yml      # Infrastructure de test
```

## Démarrage Rapide

### 1. Cloner le projet

```bash
git clone <repository-url>
cd workshop
```

### 2. Lancer l'infrastructure

```bash
# Démarrer tous les services
docker-compose up -d

# Vérifier que les services sont démarrés
docker-compose ps
```

### 3. Accéder aux services

| Service | URL | Credentials |
|---------|-----|-------------|
| Application vulnérable | http://localhost:8080 | admin/admin123 |
| SonarQube | http://localhost:9000 | admin/admin |
| OWASP ZAP | http://localhost:8090 | - |
| Dependency-Track | http://localhost:8082 | admin/admin |
| Console H2 | http://localhost:8080/h2-console | admin/admin123 |

---

## Contenu du Workshop

### Module 1 : Découverte de l'Application Vulnérable 

#### Exercice 1.1 : Explorer l'application

1. Accédez à http://localhost:8080
2. Connectez-vous avec les comptes de test
3. Explorez les fonctionnalités

#### Exercice 1.2 : Identifier les vulnérabilités

Tentez d'exploiter les vulnérabilités suivantes :

**Injection SQL dans la recherche :**
```
URL: /dashboard/search?query=' OR '1'='1
```

**XSS dans le message de connexion :**
```
URL: /login?message=<script>alert('XSS')</script>
```

**IDOR sur les profils :**
```
URL: /dashboard/profile/1
URL: /dashboard/profile/2
URL: /api/balance/1
```

---

### Module 2 : Analyse des Dépendances - SCA 

#### Exercice 2.1 : OWASP Dependency-Check

```bash
cd vulnerable-app

# Exécuter l'analyse
docker run --rm \
  -v $(pwd):/src \
  owasp/dependency-check \
  --scan /src \
  --format HTML \
  --out /src/dependency-check-report

# Ouvrir le rapport
open dependency-check-report/dependency-check-report.html
```

**Questions :**
1. Combien de CVE critiques sont détectées ?
2. Quelle version de Log4j est utilisée ?
3. Quel est le score CVSS de CVE-2021-44228 (Log4Shell) ?

#### Exercice 2.2 : Génération du SBOM

```bash
# Générer le SBOM avec CycloneDX
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom

# Examiner le SBOM
cat target/bom.json | jq '.components | length'
cat target/bom.json | jq '.components[] | select(.name | contains("log4j"))'
```

#### Exercice 2.3 : Trivy

```bash
# Scanner le projet avec Trivy
docker run --rm -v $(pwd):/app aquasec/trivy:latest fs /app

# Scanner avec format JSON
docker run --rm -v $(pwd):/app aquasec/trivy:latest fs \
  --format json \
  --output /app/trivy-report.json \
  /app
```

---

### Module 3 : Analyse Statique - SAST 

#### Exercice 3.1 : Configuration de SonarQube

1. Accédez à http://localhost:9000 (admin/admin)
2. Changez le mot de passe
3. Créez un nouveau projet "vulnerable-bank"
4. Générez un token d'analyse

```bash
# Configurer le token
export SONAR_TOKEN=<votre-token>

# Lancer l'analyse
mvn sonar:sonar \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=$SONAR_TOKEN
```

**Questions :**
1. Combien de vulnérabilités sont détectées ?
2. Quelles sont les "Security Hotspots" ?
3. Quel est le rating de sécurité (A-E) ?

#### Exercice 3.2 : Semgrep

```bash
# Exécuter Semgrep
docker run --rm -v $(pwd):/src returntocorp/semgrep \
  semgrep scan \
  --config=auto \
  --config=p/java \
  --config=p/owasp-top-ten \
  /src/src/main/java

# Avec rapport JSON
docker run --rm -v $(pwd):/src returntocorp/semgrep \
  semgrep scan \
  --config=auto \
  --json \
  --output=/src/semgrep-report.json \
  /src/src/main/java
```

#### Exercice 3.3 : SpotBugs avec Find Security Bugs

Ajoutez au pom.xml :

```xml
<plugin>
    <groupId>com.github.spotbugs</groupId>
    <artifactId>spotbugs-maven-plugin</artifactId>
    <version>4.7.3.0</version>
    <configuration>
        <plugins>
            <plugin>
                <groupId>com.h3xstream.findsecbugs</groupId>
                <artifactId>findsecbugs-plugin</artifactId>
                <version>1.12.0</version>
            </plugin>
        </plugins>
    </configuration>
</plugin>
```

```bash
mvn spotbugs:check
mvn spotbugs:gui  # Interface graphique
```

---

### Module 4 : Analyse Dynamique - DAST

#### Exercice 4.1 : OWASP ZAP Baseline Scan

```bash
# Assurez-vous que l'application est en cours d'exécution
curl http://localhost:8080/api/health

# Lancer le scan baseline
docker run --rm -t \
  --network host \
  owasp/zap2docker-stable \
  zap-baseline.py \
  -t http://localhost:8080 \
  -r zap-baseline-report.html
```

#### Exercice 4.2 : ZAP Full Scan

```bash
docker run --rm -t \
  --network host \
  -v $(pwd)/zap-reports:/zap/wrk \
  owasp/zap2docker-stable \
  zap-full-scan.py \
  -t http://localhost:8080 \
  -r zap-full-report.html \
  -x zap-full-report.xml \
  -J zap-full-report.json
```

#### Exercice 4.3 : Scan authentifié

```bash
docker run --rm -t \
  --network host \
  owasp/zap2docker-stable \
  zap-full-scan.py \
  -t http://localhost:8080 \
  -r zap-auth-report.html \
  --auth-loginurl http://localhost:8080/login \
  --auth-username admin \
  --auth-password admin123 \
  --auth-submitfield "submit"
```

#### Exercice 4.4 : Scan API

```bash
# Scanner les endpoints API
docker run --rm -t \
  --network host \
  owasp/zap2docker-stable \
  zap-api-scan.py \
  -t http://localhost:8080/api \
  -f openapi \
  -r zap-api-report.html
```

---

### Module 5 : Correction des Vulnérabilités

#### Exercice 5.1 : Mise à jour des dépendances

Modifiez le `pom.xml` pour utiliser des versions sécurisées :

```xml
<!-- Log4j sécurisé -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.21.1</version>
</dependency>

<!-- Jackson sécurisé -->
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.15.3</version>
</dependency>

<!-- SnakeYAML sécurisé -->
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>2.2</version>
</dependency>

<!-- Commons Text sécurisé -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.11.0</version>
</dependency>
```

#### Exercice 5.2 : Correction de l'injection SQL

**Avant (vulnérable) :**
```java
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
Query query = entityManager.createNativeQuery(sql, User.class);
```

**Après (sécurisé) :**
```java
String sql = "SELECT u FROM User u WHERE u.username = :username";
return entityManager.createQuery(sql, User.class)
        .setParameter("username", username)
        .getResultList()
        .stream()
        .findFirst()
        .orElse(null);
```

#### Exercice 5.3 : Correction du XSS

**Dans les templates Thymeleaf :**
```html
<!-- Avant (vulnérable) -->
<div th:utext="${message}"></div>

<!-- Après (sécurisé) -->
<div th:text="${message}"></div>
```

#### Exercice 5.4 : Correction du CSRF

Ajoutez Spring Security :

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .authorizeRequests()
            .antMatchers("/login", "/register").permitAll()
            .anyRequest().authenticated();
    }
}
```

#### Exercice 5.5 : Correction du contrôle d'accès

```java
@PostMapping("/transfer")
public String doTransfer(@RequestParam Long fromUserId,
                        @RequestParam Long toUserId,
                        @RequestParam Double amount,
                        HttpSession session) {
    
    Long currentUserId = (Long) session.getAttribute("userId");
    
    // Vérification que l'utilisateur ne peut transférer que depuis son compte
    if (!fromUserId.equals(currentUserId)) {
        throw new AccessDeniedException("Vous ne pouvez pas transférer depuis ce compte");
    }
    
    // Validation du montant
    if (amount <= 0 || amount > 10000) {
        throw new IllegalArgumentException("Montant invalide");
    }
    
    // Suite du traitement...
}
```

---

### Module 6 : Intégration CI/CD

#### Exercice 6.1 : Configuration du pipeline GitLab

1. Copiez `.gitlab-ci.yml` dans votre projet
2. Configurez les variables CI/CD :
   - `SONAR_TOKEN`
   - `SONAR_HOST_URL`
3. Lancez le pipeline

#### Exercice 6.2 : Configuration GitHub Actions

1. Copiez `.github/workflows/devsecops.yml`
2. Configurez les secrets GitHub :
   - `SONAR_TOKEN`
   - `SONAR_HOST_URL`
3. Poussez le code pour déclencher le pipeline

#### Exercice 6.3 : Analyse des résultats

1. Examinez les rapports générés
2. Identifiez les vulnérabilités bloquantes
3. Vérifiez le Quality Gate SonarQube


---

## Ressources

### Documentation officielle
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [SonarQube](https://docs.sonarqube.org/)
- [Semgrep](https://semgrep.dev/docs/)

### Tutoriels
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [CycloneDX SBOM](https://cyclonedx.org/)
- [NIST NVD](https://nvd.nist.gov/)

---
