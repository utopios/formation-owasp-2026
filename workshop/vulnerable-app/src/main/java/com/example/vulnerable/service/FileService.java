package com.example.vulnerable.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Service de gestion des fichiers.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - Path Traversal
 * - Arbitrary File Read
 * - Arbitrary File Write
 * - Command Injection
 */
@Service
public class FileService {

    private static final Logger logger = LogManager.getLogger(FileService.class);
    
    private static final String UPLOAD_DIR = "/tmp/uploads/";

    /**
     * VULNÉRABLE : Path Traversal
     * Exemple d'attaque : filename = "../../../etc/passwd"
     */
    public String readFile(String filename) {
        try {
            // VULNÉRABILITÉ : Pas de validation du chemin
            // Un attaquant peut lire n'importe quel fichier système
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            return new String(Files.readAllBytes(filePath));
        } catch (Exception e) {
            logger.error("Erreur lecture fichier: " + filename, e);
            return null;
        }
    }

    /**
     * VULNÉRABLE : Path Traversal en écriture
     * Exemple d'attaque : filename = "../../../tmp/malicious.sh"
     */
    public boolean writeFile(String filename, String content) {
        try {
            // VULNÉRABILITÉ : Pas de validation du chemin
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            
            // Créer le répertoire parent si nécessaire
            Files.createDirectories(filePath.getParent());
            
            Files.write(filePath, content.getBytes());
            logger.info("Fichier écrit: " + filePath);
            return true;
        } catch (Exception e) {
            logger.error("Erreur écriture fichier: " + filename, e);
            return false;
        }
    }

    /**
     * VULNÉRABLE : Command Injection
     * Exemple d'attaque : filename = "test.txt; cat /etc/passwd"
     */
    public String getFileInfo(String filename) {
        try {
            // VULNÉRABILITÉ : Injection de commande via Runtime.exec
            String command = "ls -la " + UPLOAD_DIR + filename;
            
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            process.waitFor();
            return output.toString();
        } catch (Exception e) {
            logger.error("Erreur info fichier: " + filename, e);
            return null;
        }
    }

    /**
     * VULNÉRABLE : Command Injection dans le traitement d'image
     */
    public boolean processImage(String filename, String format) {
        try {
            // VULNÉRABILITÉ : Injection de commande
            // format peut contenir "; rm -rf /"
            String command = "convert " + UPLOAD_DIR + filename + " -format " + format 
                           + " " + UPLOAD_DIR + "converted_" + filename;
            
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            
            return exitCode == 0;
        } catch (Exception e) {
            logger.error("Erreur traitement image", e);
            return false;
        }
    }

    /**
     * VULNÉRABLE : Téléchargement de fichier sans validation
     */
    public boolean downloadFromUrl(String url, String filename) {
        try {
            // VULNÉRABILITÉ : SSRF potentiel - pas de validation de l'URL
            // Un attaquant peut accéder à des services internes
            String command = "wget -O " + UPLOAD_DIR + filename + " " + url;
            
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            
            logger.info("Fichier téléchargé depuis " + url);
            return exitCode == 0;
        } catch (Exception e) {
            logger.error("Erreur téléchargement", e);
            return false;
        }
    }

    /**
     * Liste les fichiers uploadés
     */
    public String[] listFiles() {
        File uploadDir = new File(UPLOAD_DIR);
        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }
        return uploadDir.list();
    }

    /**
     * VULNÉRABLE : Suppression sans validation
     */
    public boolean deleteFile(String filename) {
        try {
            // VULNÉRABILITÉ : Path traversal
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            Files.deleteIfExists(filePath);
            logger.info("Fichier supprimé: " + filename);
            return true;
        } catch (Exception e) {
            logger.error("Erreur suppression fichier", e);
            return false;
        }
    }
}
