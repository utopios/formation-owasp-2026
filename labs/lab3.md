### Lab 3
### Objectif :
- Apprendre à déployer un WAF (ModSecurity) avec NGINX à l'aide de conteneurs Docker pour protéger une application web.
- Comprendre comment utiliser les règles OWASP Core Rule Set (CRS) pour détecter et prévenir les attaques courantes.

### Prérequis :
- Connaissance de base de Docker et Docker Compose.
- Docker et Docker Compose installés sur votre machine.
- Une application web simple pour servir d'exemple (nous utiliserons une application simple de NGINX dans cet exemple).



### Préparer les fichiers nécessaires

#### 1. Créez un fichier `Dockerfile` pour NGINX avec ModSecurity

```dockerfile
FROM nginx:alpine

# Installer les dépendances nécessaires
RUN apk add --no-cache \
    git \
    gcc \
    g++ \
    libxml2-dev \
    curl-dev \
    pcre-dev \
    automake \
    autoconf \
    libtool \
    make \
    apache2-dev \
    libmaxminddb-dev \
    linux-headers  # Ajoute les en-têtes Linux

# Télécharger et compiler ModSecurity
RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity /opt/ModSecurity && \
    cd /opt/ModSecurity && \
    git submodule init && \
    git submodule update && \
    ./build.sh && \
    ./configure && \
    make && \
    make install

# Télécharger et configurer ModSecurity pour NGINX
RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /opt/ModSecurity-nginx

# Télécharger et configurer OWASP CRS
RUN git clone https://github.com/SpiderLabs/owasp-modsecurity-crs /etc/nginx/modsec/owasp-modsecurity-crs && \
    cp /etc/nginx/modsec/owasp-modsecurity-crs/crs-setup.conf.example /etc/nginx/modsec/owasp-modsecurity-crs/crs-setup.conf && \
    echo "Include /etc/nginx/modsec/owasp-modsecurity-crs/crs-setup.conf" >> /etc/nginx/modsec/main.conf && \
    echo "Include /etc/nginx/modsec/owasp-modsecurity-crs/rules/*.conf" >> /etc/nginx/modsec/main.conf

# Configurer ModSecurity dans NGINX
RUN printf '\nModSecurityEnabled on\nModSecurityConfig /etc/nginx/modsec/main.conf\n' >> /etc/nginx/nginx.conf

CMD ["nginx", "-g", "daemon off;"]
```

#### 2. Créez un fichier `docker-compose.yml`

```yaml
version: '3'
services:
  nginx-waf:
    build: .
    ports:
      - "8080:80"
    volumes:
      - ./modsecurity.conf:/etc/nginx/modsec/modsecurity.conf
    restart: always
```

#### 3. Créez un fichier `modsecurity.conf`

```bash
# Extrait de configuration de base pour activer ModSecurity
SecRuleEngine On

SecRequestBodyAccess On
SecResponseBodyAccess On

# Enregistre les attaques dans un fichier de log
SecAuditLog /var/log/modsec_audit.log

# Limite la taille des requêtes
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecResponseBodyLimit 524288
```

### Étape 3 : Lancer les conteneurs

- Placez tous les fichiers dans un répertoire (ex : `modsecurity-lab`).
- Ouvrez un terminal et positionnez-vous dans ce répertoire.
- Exécutez la commande suivante pour démarrer les conteneurs :

```bash
docker-compose up --build
```

NGINX avec ModSecurity et les règles OWASP CRS sera lancé sur le port 8080. L'application est maintenant protégée par un WAF.

### Étape 4 : Tester le WAF

- Ouvrez un navigateur et allez à l'URL `http://localhost:8080`.
- Pour tester le WAF, vous pouvez essayer d'injecter des requêtes malveillantes (par exemple, SQL Injection) et vérifier que ModSecurity les bloque.

Par exemple, vous pouvez utiliser cURL pour simuler une attaque SQL Injection :

```bash
curl -X GET "http://localhost:8080/?id=1' OR '1'='1"
```

ModSecurity devrait bloquer cette requête, et vous pouvez consulter les logs dans le fichier `/var/log/modsec_audit.log` dans le conteneur pour voir l'attaque détectée.

### Étape 5 : Observer les logs

Pour accéder aux logs de sécurité générés par ModSecurity :

- Exécutez la commande suivante pour entrer dans le conteneur NGINX :

```bash
docker exec -it <container_id> /bin/sh
```

```bash
cat /var/log/modsec_audit.log
```
