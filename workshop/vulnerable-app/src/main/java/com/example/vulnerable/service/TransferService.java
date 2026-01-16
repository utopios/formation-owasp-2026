package com.example.vulnerable.service;

import com.example.vulnerable.model.Transaction;
import com.example.vulnerable.model.User;
import com.example.vulnerable.repository.TransactionRepository;
import com.example.vulnerable.repository.UserRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service de gestion des transferts.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Broken Access Control (IDOR)
 * - Pas de vérification du propriétaire du compte
 * - Race condition possible
 * - Validation insuffisante des montants
 */
@Service
@Transactional
public class TransferService {

    private static final Logger logger = LogManager.getLogger(TransferService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    /**
     * VULNÉRABLE : IDOR - Pas de vérification que l'utilisateur
     * connecté est bien le propriétaire du compte source
     */
    public Transaction transfer(Long fromUserId, Long toUserId, Double amount, 
                                String description, Long currentUserId) {
        
        // VULNÉRABILITÉ : Pas de vérification que currentUserId == fromUserId
        // Un attaquant peut transférer depuis n'importe quel compte !
        
        User fromUser = userRepository.findById(fromUserId)
                .orElseThrow(() -> new RuntimeException("Compte source non trouvé"));
        
        User toUser = userRepository.findById(toUserId)
                .orElseThrow(() -> new RuntimeException("Compte destination non trouvé"));

        // VULNÉRABILITÉ : Validation insuffisante du montant
        // Pas de vérification si amount est négatif (transfert inversé)
        if (amount == null || amount == 0) {
            throw new RuntimeException("Montant invalide");
        }

        // VULNÉRABILITÉ : Race condition possible
        // Deux transferts simultanés peuvent dépasser le solde
        if (fromUser.getBalance() < amount) {
            throw new RuntimeException("Solde insuffisant");
        }

        // Effectuer le transfert
        fromUser.setBalance(fromUser.getBalance() - amount);
        toUser.setBalance(toUser.getBalance() + amount);

        userRepository.save(fromUser);
        userRepository.save(toUser);

        // Créer la transaction
        Transaction transaction = new Transaction();
        transaction.setFromUserId(fromUserId);
        transaction.setToUserId(toUserId);
        transaction.setAmount(amount);
        transaction.setDescription(description);

        return transactionRepository.save(transaction);
    }

    /**
     * VULNÉRABLE : IDOR - Permet de voir les transactions de n'importe qui
     */
    public List<Transaction> getTransactionHistory(Long userId) {
        // VULNÉRABILITÉ : Pas de vérification des droits d'accès
        // N'importe qui peut voir l'historique de n'importe qui
        return transactionRepository.findAllByUserId(userId);
    }

    /**
     * VULNÉRABLE : Permet de voir le solde de n'importe qui
     */
    public Double getBalance(Long userId) {
        // VULNÉRABILITÉ : IDOR
        User user = userRepository.findById(userId).orElse(null);
        if (user != null) {
            logger.info("Consultation du solde de " + user.getUsername() + ": " + user.getBalance());
            return user.getBalance();
        }
        return null;
    }

    /**
     * VULNÉRABLE : Permet de modifier le solde sans autorisation
     */
    public void adminUpdateBalance(Long userId, Double newBalance) {
        // VULNÉRABILITÉ : Pas de vérification des droits admin
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
        
        user.setBalance(newBalance);
        userRepository.save(user);
        
        logger.info("Admin: Solde de " + user.getUsername() + " modifié à " + newBalance);
    }
}
