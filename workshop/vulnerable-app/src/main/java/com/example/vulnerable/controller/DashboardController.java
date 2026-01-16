package com.example.vulnerable.controller;

import com.example.vulnerable.model.Transaction;
import com.example.vulnerable.model.User;
import com.example.vulnerable.service.TransferService;
import com.example.vulnerable.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.List;

/**
 * Contrôleur du tableau de bord utilisateur.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Broken Access Control (IDOR)
 * - XSS stocké
 * - Pas de validation des entrées
 * - Mass Assignment
 */
@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    @Autowired
    private UserService userService;

    @Autowired
    private TransferService transferService;

    @GetMapping
    public String dashboard(HttpSession session, Model model) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return "redirect:/login";
        }

        User user = userService.findById(userId);
        if (user == null) {
            return "redirect:/login";
        }

        List<Transaction> transactions = transferService.getTransactionHistory(userId);
        
        model.addAttribute("user", user);
        model.addAttribute("transactions", transactions);
        
        return "dashboard";
    }

    /**
     * VULNÉRABLE : IDOR - Permet de voir le profil de n'importe qui
     */
    @GetMapping("/profile/{id}")
    public String viewProfile(@PathVariable Long id, 
                             HttpSession session,
                             Model model) {
        // VULNÉRABILITÉ : Pas de vérification que l'utilisateur
        // connecté a le droit de voir ce profil
        
        User user = userService.findById(id);
        if (user == null) {
            return "redirect:/dashboard";
        }
        
        // VULNÉRABILITÉ : Expose toutes les données sensibles
        model.addAttribute("profileUser", user);
        model.addAttribute("transactions", transferService.getTransactionHistory(id));
        
        return "profile";
    }

    /**
     * VULNÉRABLE : Mass Assignment
     */
    @PostMapping("/profile/update")
    public String updateProfile(@ModelAttribute User userUpdate,
                               HttpSession session,
                               Model model) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return "redirect:/login";
        }

        // VULNÉRABILITÉ : Mass Assignment
        // L'utilisateur peut modifier n'importe quel champ,
        // y compris role et balance !
        User currentUser = userService.findById(userId);
        if (currentUser != null) {
            // On accepte aveuglément tous les champs
            if (userUpdate.getUsername() != null) {
                currentUser.setUsername(userUpdate.getUsername());
            }
            if (userUpdate.getEmail() != null) {
                currentUser.setEmail(userUpdate.getEmail());
            }
            // VULNÉRABILITÉ : Un attaquant peut envoyer role=ADMIN
            if (userUpdate.getRole() != null) {
                currentUser.setRole(userUpdate.getRole());
            }
            // VULNÉRABILITÉ : Un attaquant peut modifier son solde
            if (userUpdate.getBalance() != null) {
                currentUser.setBalance(userUpdate.getBalance());
            }
            
            userService.updateUser(currentUser);
        }
        
        return "redirect:/dashboard";
    }

    /**
     * Page de transfert
     */
    @GetMapping("/transfer")
    public String transferPage(HttpSession session, Model model) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return "redirect:/login";
        }

        User user = userService.findById(userId);
        List<User> allUsers = userService.getAllUsers();
        
        model.addAttribute("user", user);
        model.addAttribute("users", allUsers);
        
        return "transfer";
    }

    /**
     * VULNÉRABLE : Transfert sans vérification d'autorisation
     */
    @PostMapping("/transfer")
    public String doTransfer(@RequestParam Long fromUserId,
                            @RequestParam Long toUserId,
                            @RequestParam Double amount,
                            @RequestParam(required = false) String description,
                            HttpSession session,
                            Model model) {
        
        Long currentUserId = (Long) session.getAttribute("userId");
        if (currentUserId == null) {
            return "redirect:/login";
        }

        try {
            // VULNÉRABILITÉ : IDOR - fromUserId peut être différent de currentUserId
            // Permet de voler depuis n'importe quel compte !
            Transaction tx = transferService.transfer(fromUserId, toUserId, 
                    amount, description, currentUserId);
            
            model.addAttribute("success", "Transfert effectué: " + amount + "€");
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
        }

        return "redirect:/dashboard";
    }

    /**
     * VULNÉRABLE : Recherche d'utilisateurs avec XSS
     */
    @GetMapping("/search")
    public String searchUsers(@RequestParam(required = false) String query,
                             HttpSession session,
                             Model model) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return "redirect:/login";
        }

        if (query != null && !query.isEmpty()) {
            // VULNÉRABILITÉ : Injection SQL via searchUsers
            // VULNÉRABILITÉ : XSS si query affiché sans échappement
            List<User> results = userService.searchUsers(query);
            model.addAttribute("results", results);
            model.addAttribute("query", query); // XSS potentiel
        }
        
        return "search";
    }

    /**
     * VULNÉRABLE : Historique accessible sans vérification
     */
    @GetMapping("/history/{userId}")
    @ResponseBody
    public List<Transaction> getHistory(@PathVariable Long userId) {
        // VULNÉRABILITÉ : IDOR - pas de vérification des droits
        return transferService.getTransactionHistory(userId);
    }

    /**
     * VULNÉRABLE : API de solde accessible à tous
     */
    @GetMapping("/api/balance/{userId}")
    @ResponseBody
    public Double getBalance(@PathVariable Long userId) {
        // VULNÉRABILITÉ : IDOR
        return transferService.getBalance(userId);
    }
}
