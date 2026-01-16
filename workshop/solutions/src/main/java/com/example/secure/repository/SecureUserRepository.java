package com.example.secure.repository;

import com.example.secure.model.User;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import java.util.List;
import java.util.Optional;

/**
 * Repository SÉCURISÉ pour la gestion des utilisateurs.
 * 
 * CORRECTIONS APPLIQUÉES :
 * - Utilisation de requêtes préparées (paramètres nommés)
 * - Utilisation de l'ORM JPA/JPQL au lieu de SQL natif
 * - Validation des entrées
 */
@Repository
public class SecureUserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * SÉCURISÉ : Recherche par nom d'utilisateur avec paramètres liés
     */
    public Optional<User> findByUsername(String username) {
        // Validation d'entrée
        if (username == null || username.isBlank()) {
            return Optional.empty();
        }

        // Requête JPQL avec paramètre nommé (protection contre l'injection SQL)
        String jpql = "SELECT u FROM User u WHERE u.username = :username";
        TypedQuery<User> query = entityManager.createQuery(jpql, User.class);
        query.setParameter("username", username);
        
        return query.getResultStream().findFirst();
    }

    /**
     * SÉCURISÉ : Authentification avec paramètres liés
     * Note: En production, utiliser Spring Security avec BCrypt
     */
    public Optional<User> authenticate(String username, String passwordHash) {
        // Validation des entrées
        if (username == null || username.isBlank() || 
            passwordHash == null || passwordHash.isBlank()) {
            return Optional.empty();
        }

        String jpql = "SELECT u FROM User u WHERE u.username = :username AND u.passwordHash = :passwordHash AND u.active = true";
        TypedQuery<User> query = entityManager.createQuery(jpql, User.class);
        query.setParameter("username", username);
        query.setParameter("passwordHash", passwordHash);
        
        return query.getResultStream().findFirst();
    }

    /**
     * SÉCURISÉ : Recherche avec LIKE et paramètres liés
     */
    public List<User> searchUsers(String searchTerm) {
        // Validation et nettoyage de l'entrée
        if (searchTerm == null || searchTerm.isBlank()) {
            return List.of();
        }

        // Échapper les caractères spéciaux LIKE
        String sanitizedTerm = searchTerm
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");

        String jpql = "SELECT u FROM User u WHERE " +
                     "LOWER(u.username) LIKE LOWER(:term) OR " +
                     "LOWER(u.email) LIKE LOWER(:term)";
        
        TypedQuery<User> query = entityManager.createQuery(jpql, User.class);
        query.setParameter("term", "%" + sanitizedTerm + "%");
        
        // Limiter le nombre de résultats
        query.setMaxResults(50);
        
        return query.getResultList();
    }

    /**
     * SÉCURISÉ : Mise à jour du solde avec validation
     */
    public void updateBalance(Long userId, Double amount) {
        // Validation des entrées
        if (userId == null || userId <= 0) {
            throw new IllegalArgumentException("ID utilisateur invalide");
        }
        if (amount == null) {
            throw new IllegalArgumentException("Montant invalide");
        }

        // Utiliser une requête JPQL avec paramètres
        String jpql = "UPDATE User u SET u.balance = u.balance + :amount WHERE u.id = :userId";
        int updated = entityManager.createQuery(jpql)
                .setParameter("amount", amount)
                .setParameter("userId", userId)
                .executeUpdate();
        
        if (updated == 0) {
            throw new IllegalStateException("Utilisateur non trouvé");
        }
    }

    /**
     * Recherche par ID
     */
    public Optional<User> findById(Long id) {
        if (id == null || id <= 0) {
            return Optional.empty();
        }
        return Optional.ofNullable(entityManager.find(User.class, id));
    }

    /**
     * Sauvegarde d'un utilisateur
     */
    public User save(User user) {
        if (user == null) {
            throw new IllegalArgumentException("L'utilisateur ne peut pas être null");
        }
        
        if (user.getId() == null) {
            entityManager.persist(user);
            return user;
        } else {
            return entityManager.merge(user);
        }
    }

    /**
     * Liste tous les utilisateurs (avec pagination)
     */
    public List<User> findAll(int page, int size) {
        // Validation de la pagination
        if (page < 0) page = 0;
        if (size <= 0 || size > 100) size = 20;
        
        String jpql = "SELECT u FROM User u ORDER BY u.username";
        return entityManager.createQuery(jpql, User.class)
                .setFirstResult(page * size)
                .setMaxResults(size)
                .getResultList();
    }

    /**
     * Suppression d'un utilisateur
     */
    public void delete(User user) {
        if (user != null) {
            entityManager.remove(entityManager.contains(user) ? user : entityManager.merge(user));
        }
    }

    /**
     * Vérifie si un nom d'utilisateur existe déjà
     */
    public boolean existsByUsername(String username) {
        if (username == null || username.isBlank()) {
            return false;
        }
        
        String jpql = "SELECT COUNT(u) FROM User u WHERE u.username = :username";
        Long count = entityManager.createQuery(jpql, Long.class)
                .setParameter("username", username)
                .getSingleResult();
        
        return count > 0;
    }

    /**
     * Vérifie si un email existe déjà
     */
    public boolean existsByEmail(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        
        String jpql = "SELECT COUNT(u) FROM User u WHERE u.email = :email";
        Long count = entityManager.createQuery(jpql, Long.class)
                .setParameter("email", email)
                .getSingleResult();
        
        return count > 0;
    }
}
