package com.example.vulnerable.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuration de l'application.
 * 
 * VULNÉRABILITÉS INTENTIONNELLES :
 * - CORS trop permissif
 * - Pas de configuration de sécurité
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * VULNÉRABLE : CORS ouvert à tous les domaines
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")  // VULNÉRABILITÉ : Autorise tous les domaines
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(false);
    }
}
