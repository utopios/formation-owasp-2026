package com.example.vulnerable.repository;

import com.example.vulnerable.model.User;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.List;
import java.util.Optional;

/**
 * Repository pour la gestion des utilisateurs.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Injection SQL dans plusieurs méthodes
 * - Pas d'utilisation de requêtes préparées
 */
@Repository
public class UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * VULNÉRABLE : Injection SQL via concaténation de chaînes
     * Exemple d'attaque : username = "' OR '1'='1"
     */
    public User findByUsernameUnsafe(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        List<User> results = query.getResultList();
        return results.isEmpty() ? null : results.get(0);
    }

    /**
     * VULNÉRABLE : Injection SQL dans l'authentification
     * Exemple d'attaque : username = "admin'--"
     */
    public User authenticateUnsafe(String username, String password) {
        String sql = "SELECT * FROM users WHERE username = '" + username 
                   + "' AND password = '" + password + "'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        List<User> results = query.getResultList();
        return results.isEmpty() ? null : results.get(0);
    }

    /**
     * VULNÉRABLE : Injection SQL dans la recherche
     * Exemple d'attaque : searchTerm = "' UNION SELECT * FROM users WHERE '1'='1"
     */
    @SuppressWarnings("unchecked")
    public List<User> searchUsersUnsafe(String searchTerm) {
        String sql = "SELECT * FROM users WHERE username LIKE '%" + searchTerm 
                   + "%' OR email LIKE '%" + searchTerm + "%'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        return query.getResultList();
    }

    /**
     * VULNÉRABLE : Injection SQL dans la mise à jour du solde
     */
    public void updateBalanceUnsafe(Long userId, String amount) {
        String sql = "UPDATE users SET balance = balance + " + amount 
                   + " WHERE id = " + userId;
        entityManager.createNativeQuery(sql).executeUpdate();
    }

    /**
     * Méthode sécurisée pour comparaison (à implémenter dans les corrections)
     */
    public User findByUsernameSafe(String username) {
        String sql = "SELECT u FROM User u WHERE u.username = :username";
        return entityManager.createQuery(sql, User.class)
                .setParameter("username", username)
                .getResultList()
                .stream()
                .findFirst()
                .orElse(null);
    }

    public User save(User user) {
        if (user.getId() == null) {
            entityManager.persist(user);
            return user;
        } else {
            return entityManager.merge(user);
        }
    }

    public Optional<User> findById(Long id) {
        return Optional.ofNullable(entityManager.find(User.class, id));
    }

    @SuppressWarnings("unchecked")
    public List<User> findAll() {
        return entityManager.createNativeQuery("SELECT * FROM users", User.class)
                .getResultList();
    }

    public void delete(User user) {
        entityManager.remove(entityManager.contains(user) ? user : entityManager.merge(user));
    }
}
