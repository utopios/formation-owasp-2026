package com.example.vulnerable.controller;

import com.example.vulnerable.model.User;
import com.example.vulnerable.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Contrôleur d'authentification.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Session Fixation
 * - Cookies non sécurisés
 * - Pas de protection CSRF
 * - XSS réfléchi
 * - Information Disclosure
 */
@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @GetMapping("/")
    public String home() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(required = false) String error,
                           @RequestParam(required = false) String message,
                           Model model) {
        // VULNÉRABILITÉ : XSS réfléchi - le message est affiché sans échappement
        model.addAttribute("error", error);
        model.addAttribute("message", message);
        return "login";
    }

    /**
     * VULNÉRABLE : Authentification non sécurisée
     */
    @PostMapping("/login")
    public String login(@RequestParam String username,
                       @RequestParam String password,
                       HttpServletRequest request,
                       HttpServletResponse response,
                       Model model) {
        
        User user = userService.login(username, password);
        
        if (user != null) {
            // VULNÉRABILITÉ : Session Fixation
            // La session n'est pas régénérée après authentification
            HttpSession session = request.getSession();
            session.setAttribute("user", user);
            session.setAttribute("userId", user.getId());
            session.setAttribute("username", user.getUsername());
            session.setAttribute("role", user.getRole());

            // VULNÉRABILITÉ : Cookie non sécurisé
            Cookie userCookie = new Cookie("username", user.getUsername());
            userCookie.setMaxAge(86400); // 24 heures
            // VULNÉRABILITÉ : HttpOnly et Secure non définis !
            // userCookie.setHttpOnly(true);  // Absent !
            // userCookie.setSecure(true);    // Absent !
            response.addCookie(userCookie);

            // VULNÉRABILITÉ : Cookie avec données sensibles
            Cookie roleCookie = new Cookie("role", user.getRole());
            roleCookie.setMaxAge(86400);
            response.addCookie(roleCookie);

            return "redirect:/dashboard";
        } else {
            // VULNÉRABILITÉ : Information Disclosure
            // Révèle si l'utilisateur existe ou non
            model.addAttribute("error", "Identifiants incorrects pour l'utilisateur: " + username);
            return "login";
        }
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    /**
     * VULNÉRABLE : Inscription sans validation
     */
    @PostMapping("/register")
    public String register(@RequestParam String username,
                          @RequestParam String password,
                          @RequestParam String email,
                          @RequestParam(required = false) String ssn,
                          @RequestParam(required = false) String creditCard,
                          Model model) {
        
        // VULNÉRABILITÉ : Pas de validation des entrées
        // Pas de vérification de la force du mot de passe
        // Pas de validation de l'email
        
        User existingUser = userService.findByUsername(username);
        if (existingUser != null) {
            model.addAttribute("error", "L'utilisateur " + username + " existe déjà");
            return "register";
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(password);  // VULNÉRABILITÉ : Stocké en clair !
        user.setEmail(email);
        user.setSsn(ssn);            // VULNÉRABILITÉ : Données sensibles non chiffrées
        user.setCreditCard(creditCard);
        user.setBalance(1000.0);     // Solde initial

        userService.register(user);
        
        return "redirect:/login?message=Inscription réussie, connectez-vous";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        
        // Supprimer les cookies
        Cookie userCookie = new Cookie("username", null);
        userCookie.setMaxAge(0);
        response.addCookie(userCookie);
        
        Cookie roleCookie = new Cookie("role", null);
        roleCookie.setMaxAge(0);
        response.addCookie(roleCookie);
        
        return "redirect:/login?message=Déconnexion réussie";
    }

    /**
     * VULNÉRABLE : Endpoint d'import via désérialisation
     */
    @PostMapping("/import-user")
    @ResponseBody
    public String importUser(@RequestParam String data) {
        // VULNÉRABILITÉ : Insecure Deserialization
        User user = userService.deserializeUser(data);
        if (user != null) {
            userService.register(user);
            return "Utilisateur importé: " + user.getUsername();
        }
        return "Erreur d'import";
    }

    /**
     * VULNÉRABLE : Export utilisateur
     */
    @GetMapping("/export-user/{id}")
    @ResponseBody
    public String exportUser(@PathVariable Long id) {
        // VULNÉRABILITÉ : IDOR - pas de vérification des droits
        User user = userService.findById(id);
        if (user != null) {
            return userService.serializeUser(user);
        }
        return "Utilisateur non trouvé";
    }
}
