### Sujet du Laboratoire : Sécurisation d'une Application Web avec **Content Security Policy (CSP)** et **Subresource Integrity (SRI)**

#### Objectifs :
1. Implémenter une **Content Security Policy (CSP)** pour limiter les sources autorisées des ressources (scripts, styles, images).
2. Apprendre à utiliser **Subresource Integrity (SRI)** pour assurer l'intégrité des fichiers externes.
3. Tester la robustesse de la configuration en simulant des violations de CSP et SRI.

#### Scénario :
Vous allez créer une petite application web qui :
1. Charge des ressources externes (par exemple, une feuille de style CSS ou un script JavaScript hébergé sur un CDN).
2. Implémente une politique CSP stricte pour restreindre les ressources chargées uniquement depuis certaines sources sécurisées.
3. Utilise des **hashes SRI** pour garantir l'intégrité des fichiers externes.
4. Teste les violations des politiques CSP et SRI pour garantir que la configuration est efficace contre des attaques comme le **Cross-Site Scripting (XSS)** ou la modification de fichiers externes.

#### Tâches :

1. **Configurer une politique CSP** :
   - Restreindre les sources des scripts et styles à `'self'` et à un CDN spécifique.
   - Désactiver l'exécution des scripts inline avec des directives comme `unsafe-inline`.
   - Limiter les images à des sources spécifiques (comme `'self'` et HTTPS).
   - Ajouter une directive `report-uri` ou `report-to` pour capturer les violations de la politique.

2. **Implémenter SRI** :
   - Charger un script JavaScript et une feuille de style CSS depuis un CDN.
   - Calculer manuellement le hash SRI de ces ressources (par exemple avec `openssl` ou un outil en ligne).
   - Ajouter les attributs `integrity` et `crossorigin` dans les balises `<script>` et `<link>` pour vérifier l'intégrité des ressources.

3. **Tester les violations** :
   - Modifier une ressource externe pour provoquer une erreur SRI et observer le comportement.
   - Essayer d'injecter un script non autorisé et vérifier que la politique CSP le bloque.
   - Capturer et analyser les rapports de violations envoyés au serveur via `report-uri`.

