package com.example.secure.service;

import com.example.secure.model.Transaction;
import com.example.secure.model.User;
import com.example.secure.repository.SecureTransactionRepository;
import com.example.secure.repository.SecureUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;

/**
 * Service de transfert SÉCURISÉ.
 * 
 * CORRECTIONS APPLIQUÉES :
 * - Vérification stricte des autorisations (pas d'IDOR)
 * - Validation complète des montants
 * - Protection contre les race conditions (isolation SERIALIZABLE)
 * - Logging sécurisé (pas de données sensibles)
 * - Limites de transfert
 */
@Service
public class SecureTransferService {

    private static final Logger logger = LoggerFactory.getLogger(SecureTransferService.class);

    // Limites de sécurité
    private static final BigDecimal MIN_TRANSFER_AMOUNT = new BigDecimal("0.01");
    private static final BigDecimal MAX_TRANSFER_AMOUNT = new BigDecimal("10000.00");
    private static final BigDecimal DAILY_TRANSFER_LIMIT = new BigDecimal("50000.00");

    @Autowired
    private SecureUserRepository userRepository;

    @Autowired
    private SecureTransactionRepository transactionRepository;

    /**
     * Effectue un transfert SÉCURISÉ.
     * 
     * @param fromUserId ID du compte source
     * @param toUserId ID du compte destination
     * @param amount Montant à transférer
     * @param description Description du transfert
     * @return Transaction créée
     * @throws AccessDeniedException si l'utilisateur n'est pas autorisé
     * @throws IllegalArgumentException si les paramètres sont invalides
     */
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public Transaction transfer(Long fromUserId, Long toUserId, BigDecimal amount, String description) {
        
        // 1. Récupérer l'utilisateur actuellement authentifié
        Long currentUserId = getCurrentAuthenticatedUserId();
        
        // 2. VÉRIFICATION D'AUTORISATION STRICTE
        // L'utilisateur ne peut transférer QUE depuis son propre compte
        if (!fromUserId.equals(currentUserId)) {
            logger.warn("Tentative de transfert non autorisé - User {} a tenté de transférer depuis le compte {}", 
                       currentUserId, fromUserId);
            throw new AccessDeniedException("Vous ne pouvez transférer que depuis votre propre compte");
        }

        // 3. Empêcher les auto-transferts
        if (fromUserId.equals(toUserId)) {
            throw new IllegalArgumentException("Impossible de transférer vers le même compte");
        }

        // 4. VALIDATION DU MONTANT
        validateAmount(amount);

        // 5. Récupérer les comptes
        User fromUser = userRepository.findById(fromUserId)
                .orElseThrow(() -> new IllegalArgumentException("Compte source non trouvé"));
        
        User toUser = userRepository.findById(toUserId)
                .orElseThrow(() -> new IllegalArgumentException("Compte destination non trouvé"));

        // 6. Vérifier que les comptes sont actifs
        if (!fromUser.isActive()) {
            throw new IllegalStateException("Votre compte est désactivé");
        }
        if (!toUser.isActive()) {
            throw new IllegalArgumentException("Le compte destination est désactivé");
        }

        // 7. Vérifier le solde (avec BigDecimal pour la précision)
        BigDecimal currentBalance = BigDecimal.valueOf(fromUser.getBalance());
        if (currentBalance.compareTo(amount) < 0) {
            logger.info("Transfert refusé - Solde insuffisant pour user {}", currentUserId);
            throw new IllegalStateException("Solde insuffisant");
        }

        // 8. Vérifier la limite quotidienne
        BigDecimal dailyTotal = transactionRepository.getDailyTransferTotal(fromUserId);
        if (dailyTotal.add(amount).compareTo(DAILY_TRANSFER_LIMIT) > 0) {
            throw new IllegalStateException("Limite de transfert quotidienne atteinte");
        }

        // 9. Effectuer le transfert
        BigDecimal newFromBalance = currentBalance.subtract(amount).setScale(2, RoundingMode.HALF_UP);
        BigDecimal newToBalance = BigDecimal.valueOf(toUser.getBalance()).add(amount).setScale(2, RoundingMode.HALF_UP);

        fromUser.setBalance(newFromBalance.doubleValue());
        toUser.setBalance(newToBalance.doubleValue());

        userRepository.save(fromUser);
        userRepository.save(toUser);

        // 10. Créer la transaction
        Transaction transaction = new Transaction();
        transaction.setFromUserId(fromUserId);
        transaction.setToUserId(toUserId);
        transaction.setAmount(amount.doubleValue());
        transaction.setDescription(sanitizeDescription(description));
        transaction.setStatus("COMPLETED");

        Transaction savedTransaction = transactionRepository.save(transaction);

        // 11. Log sécurisé (pas de montant ni d'infos sensibles)
        logger.info("Transfert effectué - Transaction ID: {}", savedTransaction.getId());

        return savedTransaction;
    }

    /**
     * Récupère l'historique des transactions de l'utilisateur AUTHENTIFIÉ.
     * 
     * Protection IDOR : seul l'utilisateur connecté peut voir son historique.
     */
    @Transactional(readOnly = true)
    public List<Transaction> getMyTransactionHistory() {
        Long currentUserId = getCurrentAuthenticatedUserId();
        return transactionRepository.findAllByUserId(currentUserId);
    }

    /**
     * Récupère l'historique des transactions d'un utilisateur.
     * 
     * Protection IDOR : vérifie que l'utilisateur demande ses propres transactions
     * ou est un admin.
     */
    @Transactional(readOnly = true)
    public List<Transaction> getTransactionHistory(Long userId) {
        Long currentUserId = getCurrentAuthenticatedUserId();
        
        // Vérifier les droits d'accès
        if (!userId.equals(currentUserId) && !isCurrentUserAdmin()) {
            logger.warn("Tentative d'accès non autorisé à l'historique - User {} a tenté d'accéder à {}", 
                       currentUserId, userId);
            throw new AccessDeniedException("Accès non autorisé");
        }
        
        return transactionRepository.findAllByUserId(userId);
    }

    /**
     * Récupère le solde de l'utilisateur AUTHENTIFIÉ uniquement.
     */
    @Transactional(readOnly = true)
    public Double getMyBalance() {
        Long currentUserId = getCurrentAuthenticatedUserId();
        return userRepository.findById(currentUserId)
                .map(User::getBalance)
                .orElse(0.0);
    }

    /**
     * Récupère le solde d'un utilisateur (avec vérification des droits).
     */
    @Transactional(readOnly = true)
    public Double getBalance(Long userId) {
        Long currentUserId = getCurrentAuthenticatedUserId();
        
        // Seul l'utilisateur lui-même ou un admin peut voir le solde
        if (!userId.equals(currentUserId) && !isCurrentUserAdmin()) {
            throw new AccessDeniedException("Accès non autorisé");
        }
        
        return userRepository.findById(userId)
                .map(User::getBalance)
                .orElse(null);
    }

    // ========================================
    // MÉTHODES PRIVÉES
    // ========================================

    /**
     * Récupère l'ID de l'utilisateur actuellement authentifié.
     */
    private Long getCurrentAuthenticatedUserId() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Non authentifié");
        }
        
        // Supposons que le principal contient l'ID utilisateur
        // En pratique, adapter selon votre UserDetails
        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomUserDetails) {
            return ((CustomUserDetails) principal).getId();
        }
        
        throw new IllegalStateException("Impossible de déterminer l'utilisateur");
    }

    /**
     * Vérifie si l'utilisateur actuel est admin.
     */
    private boolean isCurrentUserAdmin() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && 
               authentication.getAuthorities().stream()
                   .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    /**
     * Valide le montant du transfert.
     */
    private void validateAmount(BigDecimal amount) {
        if (amount == null) {
            throw new IllegalArgumentException("Le montant est obligatoire");
        }
        
        if (amount.compareTo(MIN_TRANSFER_AMOUNT) < 0) {
            throw new IllegalArgumentException("Le montant minimum est " + MIN_TRANSFER_AMOUNT + "€");
        }
        
        if (amount.compareTo(MAX_TRANSFER_AMOUNT) > 0) {
            throw new IllegalArgumentException("Le montant maximum est " + MAX_TRANSFER_AMOUNT + "€");
        }
        
        // Vérifier que le montant a au maximum 2 décimales
        if (amount.scale() > 2) {
            throw new IllegalArgumentException("Le montant ne peut avoir plus de 2 décimales");
        }
    }

    /**
     * Nettoie la description pour éviter les injections.
     */
    private String sanitizeDescription(String description) {
        if (description == null) {
            return "";
        }
        
        // Limiter la longueur
        if (description.length() > 200) {
            description = description.substring(0, 200);
        }
        
        // Supprimer les caractères potentiellement dangereux
        return description
                .replaceAll("[<>\"'&]", "")
                .trim();
    }

    // Interface interne pour le UserDetails personnalisé
    public interface CustomUserDetails {
        Long getId();
    }
}
