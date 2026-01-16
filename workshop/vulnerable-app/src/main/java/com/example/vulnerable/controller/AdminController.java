package com.example.vulnerable.controller;

import com.example.vulnerable.model.User;
import com.example.vulnerable.service.FileService;
import com.example.vulnerable.service.TransferService;
import com.example.vulnerable.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.List;

/**
 * Contrôleur d'administration.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Broken Access Control
 * - Privilege Escalation
 * - Path Traversal
 * - Command Injection
 */
@Controller
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    private UserService userService;

    @Autowired
    private TransferService transferService;

    @Autowired
    private FileService fileService;

    /**
     * VULNÉRABLE : Vérification d'admin basée sur cookie
     */
    @GetMapping
    public String adminDashboard(HttpSession session,
                                @CookieValue(value = "role", defaultValue = "") String role,
                                Model model) {
        
        // VULNÉRABILITÉ : Vérification basée sur cookie client !
        // Un attaquant peut modifier le cookie role=ADMIN
        if (!"ADMIN".equals(role) && !"ADMIN".equals(session.getAttribute("role"))) {
            // Vérification faible, facilement contournable
            return "redirect:/dashboard";
        }

        List<User> users = userService.getAllUsers();
        model.addAttribute("users", users);
        model.addAttribute("files", fileService.listFiles());
        
        return "admin";
    }

    /**
     * VULNÉRABLE : Modification de solde sans vérification admin
     */
    @PostMapping("/update-balance")
    @ResponseBody
    public String updateBalance(@RequestParam Long userId,
                               @RequestParam Double newBalance,
                               @CookieValue(value = "role", defaultValue = "") String role) {
        
        // VULNÉRABILITÉ : Même vérification faible
        if (!"ADMIN".equals(role)) {
            return "Non autorisé";
        }

        transferService.adminUpdateBalance(userId, newBalance);
        return "Solde mis à jour";
    }

    /**
     * VULNÉRABLE : Suppression d'utilisateur sans vérification
     */
    @PostMapping("/delete-user/{id}")
    @ResponseBody
    public String deleteUser(@PathVariable Long id,
                            @CookieValue(value = "role", defaultValue = "") String role) {
        
        // VULNÉRABILITÉ : Vérification par cookie
        if (!"ADMIN".equals(role)) {
            return "Non autorisé";
        }

        userService.deleteUser(id);
        return "Utilisateur supprimé";
    }

    /**
     * VULNÉRABLE : Promotion admin sans vérification
     */
    @PostMapping("/promote/{id}")
    @ResponseBody
    public String promoteToAdmin(@PathVariable Long id) {
        // VULNÉRABILITÉ : Pas de vérification du tout !
        User user = userService.findById(id);
        if (user != null) {
            user.setRole("ADMIN");
            userService.updateUser(user);
            return "Utilisateur promu admin";
        }
        return "Utilisateur non trouvé";
    }

    /**
     * VULNÉRABLE : Lecture de fichier avec Path Traversal
     */
    @GetMapping("/file")
    @ResponseBody
    public String readFile(@RequestParam String filename,
                          @CookieValue(value = "role", defaultValue = "") String role) {
        
        // VULNÉRABILITÉ : Path Traversal
        // filename = "../../../etc/passwd" expose le fichier système
        return fileService.readFile(filename);
    }

    /**
     * VULNÉRABLE : Écriture de fichier avec Path Traversal
     */
    @PostMapping("/file")
    @ResponseBody
    public String writeFile(@RequestParam String filename,
                           @RequestParam String content,
                           @CookieValue(value = "role", defaultValue = "") String role) {
        
        // VULNÉRABILITÉ : Path Traversal en écriture
        boolean success = fileService.writeFile(filename, content);
        return success ? "Fichier écrit" : "Erreur";
    }

    /**
     * VULNÉRABLE : Command Injection via info fichier
     */
    @GetMapping("/file-info")
    @ResponseBody
    public String getFileInfo(@RequestParam String filename) {
        // VULNÉRABILITÉ : Command Injection
        // filename = "test.txt; cat /etc/passwd"
        return fileService.getFileInfo(filename);
    }

    /**
     * VULNÉRABLE : Command Injection via traitement d'image
     */
    @PostMapping("/process-image")
    @ResponseBody
    public String processImage(@RequestParam String filename,
                              @RequestParam String format) {
        // VULNÉRABILITÉ : Command Injection
        boolean success = fileService.processImage(filename, format);
        return success ? "Image traitée" : "Erreur";
    }

    /**
     * VULNÉRABLE : SSRF via téléchargement
     */
    @PostMapping("/download")
    @ResponseBody
    public String downloadFile(@RequestParam String url,
                              @RequestParam String filename) {
        // VULNÉRABILITÉ : SSRF
        // url = "http://169.254.169.254/latest/meta-data/"
        boolean success = fileService.downloadFromUrl(url, filename);
        return success ? "Fichier téléchargé" : "Erreur";
    }

    /**
     * VULNÉRABLE : Debug endpoint exposé
     */
    @GetMapping("/debug")
    @ResponseBody
    public String debug() {
        // VULNÉRABILITÉ : Information Disclosure
        StringBuilder info = new StringBuilder();
        info.append("=== DEBUG INFO ===\n");
        info.append("Java Version: ").append(System.getProperty("java.version")).append("\n");
        info.append("OS: ").append(System.getProperty("os.name")).append("\n");
        info.append("User: ").append(System.getProperty("user.name")).append("\n");
        info.append("Home: ").append(System.getProperty("user.home")).append("\n");
        info.append("Working Dir: ").append(System.getProperty("user.dir")).append("\n");
        
        // VULNÉRABILITÉ : Expose les variables d'environnement
        info.append("\n=== ENVIRONMENT ===\n");
        System.getenv().forEach((key, value) -> {
            info.append(key).append("=").append(value).append("\n");
        });
        
        return info.toString();
    }

    /**
     * VULNÉRABLE : Exécution de commande arbitraire
     */
    @PostMapping("/exec")
    @ResponseBody
    public String executeCommand(@RequestParam String cmd,
                                @CookieValue(value = "role", defaultValue = "") String role) {
        // VULNÉRABILITÉ : Remote Code Execution !
        if (!"ADMIN".equals(role)) {
            return "Non autorisé";
        }

        try {
            Process process = Runtime.getRuntime().exec(cmd);
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (Exception e) {
            return "Erreur: " + e.getMessage();
        }
    }
}
