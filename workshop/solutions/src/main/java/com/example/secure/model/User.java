package com.example.secure.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.*;
import javax.validation.constraints.*;
import java.time.LocalDateTime;

/**
 * Entité User SÉCURISÉE.
 * 
 * CORRECTIONS APPLIQUÉES :
 * - Pas d'implémentation Serializable (évite insecure deserialization)
 * - Mot de passe haché (pas en clair)
 * - Données sensibles masquées dans JSON
 * - Validation des champs
 * - toString() ne révèle pas de données sensibles
 * - Chiffrement des données sensibles en base
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_username", columnList = "username"),
    @Index(name = "idx_email", columnList = "email")
})
public class User {
    // Note: PAS d'implements Serializable pour éviter les attaques de désérialisation

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Le nom d'utilisateur est obligatoire")
    @Size(min = 3, max = 50, message = "Le nom d'utilisateur doit faire entre 3 et 50 caractères")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Le nom d'utilisateur ne peut contenir que des lettres, chiffres et underscores")
    @Column(nullable = false, unique = true, length = 50)
    private String username;

    /**
     * Mot de passe HACHÉ avec BCrypt.
     * @JsonIgnore empêche la sérialisation dans les réponses JSON.
     * @JsonProperty(access = WRITE_ONLY) permet de le recevoir dans les requêtes.
     */
    @JsonIgnore
    @NotBlank(message = "Le mot de passe est obligatoire")
    @Column(name = "password_hash", nullable = false, length = 60)
    private String passwordHash;

    @NotBlank(message = "L'email est obligatoire")
    @Email(message = "Format d'email invalide")
    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false, length = 20)
    private String role = "USER";

    /**
     * Données sensibles - chiffrées en base de données.
     */
    @JsonIgnore
    @Column(name = "ssn_encrypted", length = 255)
    private String ssnEncrypted;

    @JsonIgnore
    @Column(name = "credit_card_encrypted", length = 255)
    private String creditCardEncrypted;

    @DecimalMin(value = "0.0", message = "Le solde ne peut pas être négatif")
    @Column(nullable = false)
    private Double balance = 0.0;

    @Column(nullable = false)
    private boolean active = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "failed_login_attempts")
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    // ========================================
    // CONSTRUCTEURS
    // ========================================

    public User() {
        this.createdAt = LocalDateTime.now();
    }

    public User(String username, String email) {
        this();
        this.username = username;
        this.email = email;
    }

    // ========================================
    // CALLBACKS JPA
    // ========================================

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // ========================================
    // MÉTHODES MÉTIER
    // ========================================

    /**
     * Vérifie si le compte est verrouillé.
     */
    public boolean isLocked() {
        return lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
    }

    /**
     * Incrémente le compteur d'échecs de connexion.
     * Verrouille le compte après 5 tentatives.
     */
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= 5) {
            int lockMinutes = 15 * (int) Math.pow(2, this.failedLoginAttempts - 5);
            this.lockedUntil = LocalDateTime.now().plusMinutes(Math.min(lockMinutes, 1440));
        }
    }

    /**
     * Réinitialise le compteur après une connexion réussie.
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
        this.lastLogin = LocalDateTime.now();
    }

    /**
     * Vérifie si l'utilisateur a un rôle admin.
     */
    public boolean isAdmin() {
        return "ADMIN".equalsIgnoreCase(this.role);
    }

    // ========================================
    // GETTERS ET SETTERS
    // ========================================

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    protected String getPasswordHash() {
        return passwordHash;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        if (role != null && (role.equals("USER") || role.equals("ADMIN"))) {
            this.role = role;
        }
    }

    public Double getBalance() {
        return balance;
    }

    public void setBalance(Double balance) {
        if (balance != null && balance >= 0) {
            this.balance = balance;
        }
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    public void setSsnEncrypted(String ssnEncrypted) {
        this.ssnEncrypted = ssnEncrypted;
    }

    public void setCreditCardEncrypted(String creditCardEncrypted) {
        this.creditCardEncrypted = creditCardEncrypted;
    }

    // ========================================
    // MÉTHODES SÉCURISÉES
    // ========================================

    /**
     * toString() sécurisé - NE RÉVÈLE PAS de données sensibles.
     */
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + maskEmail(email) + '\'' +
                ", role='" + role + '\'' +
                ", active=" + active +
                '}';
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        String[] parts = email.split("@");
        String local = parts[0];
        String domain = parts[1];
        
        if (local.length() <= 2) {
            return "**@" + domain;
        }
        return local.charAt(0) + "***" + local.charAt(local.length() - 1) + "@" + domain;
    }

    public String getMaskedCreditCard() {
        return "****-****-****-XXXX";
    }

    public String getMaskedSsn() {
        return "***-**-XXXX";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id != null && id.equals(user.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
