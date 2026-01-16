package com.example.vulnerable.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;

/**
 * Entité représentant un utilisateur.
 * 
 * VULNÉRABILITÉS :
 * - Mot de passe stocké en clair (pas de hachage)
 * - Implémente Serializable sans contrôle (insecure deserialization)
 * - Pas de validation des données
 * - toString() expose des données sensibles
 */
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    // VULNÉRABILITÉ : Mot de passe stocké en clair !
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    private String role;

    // VULNÉRABILITÉ : Numéro de sécurité sociale stocké en clair
    private String ssn;

    // VULNÉRABILITÉ : Numéro de carte bancaire stocké en clair
    private String creditCard;

    private Double balance;

    private boolean active;

    // VULNÉRABILITÉ : toString() expose des données sensibles dans les logs
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", email='" + email + '\'' +
                ", ssn='" + ssn + '\'' +
                ", creditCard='" + creditCard + '\'' +
                ", balance=" + balance +
                '}';
    }
}
