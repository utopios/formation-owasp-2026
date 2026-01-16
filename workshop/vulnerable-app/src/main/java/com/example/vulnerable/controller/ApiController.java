package com.example.vulnerable.controller;

import com.example.vulnerable.model.User;
import com.example.vulnerable.service.UserService;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * API REST pour les opérations utilisateur.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Pas d'authentification API
 * - CORS permissif
 * - CVE-2022-42889 (Apache Commons Text)
 * - CVE-2022-1471 (SnakeYAML)
 * - Information Disclosure
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")  // VULNÉRABILITÉ : CORS trop permissif
public class ApiController {

    @Autowired
    private UserService userService;

    /**
     * VULNÉRABLE : Liste tous les utilisateurs sans authentification
     */
    @GetMapping("/users")
    public List<User> getAllUsers() {
        // VULNÉRABILITÉ : Pas d'authentification requise
        // VULNÉRABILITÉ : Expose toutes les données sensibles (mots de passe, SSN, etc.)
        return userService.getAllUsers();
    }

    /**
     * VULNÉRABLE : Récupère un utilisateur par ID
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        // VULNÉRABILITÉ : IDOR
        User user = userService.findById(id);
        if (user != null) {
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.notFound().build();
    }

    /**
     * VULNÉRABLE : Recherche avec injection SQL
     */
    @GetMapping("/users/search")
    public List<User> searchUsers(@RequestParam String q) {
        // VULNÉRABILITÉ : Injection SQL propagée
        return userService.searchUsers(q);
    }

    /**
     * VULNÉRABLE : CVE-2022-42889 - Apache Commons Text RCE
     * Exploit: ${script:javascript:java.lang.Runtime.getRuntime().exec('calc')}
     */
    @PostMapping("/template")
    public String processTemplate(@RequestBody Map<String, String> request) {
        String template = request.get("template");
        Map<String, String> values = new HashMap<>();
        values.put("name", request.getOrDefault("name", "User"));
        values.put("date", java.time.LocalDate.now().toString());
        
        // VULNÉRABILITÉ : StringSubstitutor avec interpolation par défaut
        // Permet l'exécution de code via ${script:...}
        StringSubstitutor substitutor = new StringSubstitutor(values);
        return substitutor.replace(template);
    }

    /**
     * VULNÉRABLE : CVE-2022-1471 - SnakeYAML RCE
     * Permet la désérialisation d'objets arbitraires via YAML
     */
    @PostMapping("/config")
    public String loadConfig(@RequestBody String yamlContent) {
        try {
            // VULNÉRABILITÉ : SnakeYAML sans SafeConstructor
            // Permet l'instanciation d'objets arbitraires
            Yaml yaml = new Yaml();
            Object config = yaml.load(yamlContent);
            return "Config chargée: " + config.toString();
        } catch (Exception e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABLE : Endpoint de santé exposant trop d'informations
     */
    @GetMapping("/health")
    public Map<String, Object> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        
        // VULNÉRABILITÉ : Information Disclosure
        health.put("status", "UP");
        health.put("database", "H2");
        health.put("javaVersion", System.getProperty("java.version"));
        health.put("osName", System.getProperty("os.name"));
        health.put("osVersion", System.getProperty("os.version"));
        health.put("totalUsers", userService.getAllUsers().size());
        
        // VULNÉRABILITÉ : Expose la mémoire JVM
        Runtime runtime = Runtime.getRuntime();
        health.put("freeMemory", runtime.freeMemory());
        health.put("totalMemory", runtime.totalMemory());
        health.put("maxMemory", runtime.maxMemory());
        
        return health;
    }

    /**
     * VULNÉRABLE : Mise à jour de profil avec Mass Assignment
     */
    @PutMapping("/users/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, 
                                          @RequestBody User userUpdate) {
        User existingUser = userService.findById(id);
        if (existingUser == null) {
            return ResponseEntity.notFound().build();
        }

        // VULNÉRABILITÉ : Mass Assignment
        // Accepte tous les champs y compris role et balance
        if (userUpdate.getUsername() != null) {
            existingUser.setUsername(userUpdate.getUsername());
        }
        if (userUpdate.getEmail() != null) {
            existingUser.setEmail(userUpdate.getEmail());
        }
        if (userUpdate.getRole() != null) {
            existingUser.setRole(userUpdate.getRole());
        }
        if (userUpdate.getBalance() != null) {
            existingUser.setBalance(userUpdate.getBalance());
        }
        if (userUpdate.getPassword() != null) {
            existingUser.setPassword(userUpdate.getPassword());
        }

        return ResponseEntity.ok(userService.updateUser(existingUser));
    }

    /**
     * VULNÉRABLE : Suppression sans authentification
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        // VULNÉRABILITÉ : Pas d'authentification
        User user = userService.findById(id);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * VULNÉRABLE : Endpoint de debug
     */
    @GetMapping("/debug/env")
    public Map<String, String> getEnvironment() {
        // VULNÉRABILITÉ : Expose toutes les variables d'environnement
        return System.getenv();
    }

    /**
     * VULNÉRABLE : Endpoint de debug système
     */
    @GetMapping("/debug/system")
    public Map<String, String> getSystemProperties() {
        // VULNÉRABILITÉ : Expose les propriétés système
        Map<String, String> props = new HashMap<>();
        System.getProperties().forEach((key, value) -> {
            props.put(key.toString(), value.toString());
        });
        return props;
    }
}
