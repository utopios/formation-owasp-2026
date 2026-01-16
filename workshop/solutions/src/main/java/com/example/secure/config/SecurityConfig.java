package com.example.secure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration de sécurité Spring Security.
 * 
 * CORRECTIONS APPLIQUÉES :
 * - Protection CSRF activée
 * - Hachage des mots de passe avec BCrypt
 * - Headers de sécurité configurés
 * - CORS restrictif
 * - Session management sécurisé
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // ========================================
            // PROTECTION CSRF
            // ========================================
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringAntMatchers("/api/public/**") // API publique sans CSRF
            .and()

            // ========================================
            // CORS RESTRICTIF
            // ========================================
            .cors()
                .configurationSource(corsConfigurationSource())
            .and()

            // ========================================
            // HEADERS DE SÉCURITÉ
            // ========================================
            .headers()
                // Empêcher l'intégration dans une iframe (clickjacking)
                .frameOptions().deny()
                
                // Protection XSS
                .xssProtection()
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                .and()
                
                // Empêcher le sniffing de type MIME
                .contentTypeOptions()
                .and()
                
                // Content Security Policy
                .contentSecurityPolicy(
                    "default-src 'self'; " +
                    "script-src 'self'; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data:; " +
                    "font-src 'self'; " +
                    "frame-ancestors 'none'; " +
                    "form-action 'self';"
                )
                .and()
                
                // Referrer Policy
                .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                .and()
                
                // Permissions Policy (remplace Feature-Policy)
                .permissionsPolicy(policy -> policy
                    .policy("geolocation=(), microphone=(), camera=()")
                )
                .and()
                
                // HTTP Strict Transport Security (HSTS)
                .httpStrictTransportSecurity()
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000) // 1 an
                .and()
            .and()

            // ========================================
            // AUTORISATION DES REQUÊTES
            // ========================================
            .authorizeRequests()
                // Pages publiques
                .antMatchers("/", "/login", "/register", "/css/**", "/js/**", "/images/**").permitAll()
                .antMatchers("/api/public/**").permitAll()
                .antMatchers("/api/health").permitAll()
                
                // Pages admin
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                
                // Toutes les autres requêtes nécessitent une authentification
                .anyRequest().authenticated()
            .and()

            // ========================================
            // CONFIGURATION DU LOGIN
            // ========================================
            .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .usernameParameter("username")
                .passwordParameter("password")
                .permitAll()
            .and()

            // ========================================
            // CONFIGURATION DU LOGOUT
            // ========================================
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .permitAll()
            .and()

            // ========================================
            // GESTION DE SESSION
            // ========================================
            .sessionManagement()
                // Régénérer la session après authentification (protection session fixation)
                .sessionFixation().migrateSession()
                // Limiter à une session par utilisateur
                .maximumSessions(1)
                    .expiredUrl("/login?expired=true")
                .and()
                // Politique de création de session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED)
            .and()

            // ========================================
            // REMEMBER ME (optionnel)
            // ========================================
            .rememberMe()
                .key("uniqueAndSecretKey")
                .tokenValiditySeconds(86400) // 24 heures
                .rememberMeParameter("remember-me")
            .and()

            // ========================================
            // GESTION DES EXCEPTIONS
            // ========================================
            .exceptionHandling()
                .accessDeniedPage("/error/403");
    }

    /**
     * Encodeur de mot de passe BCrypt.
     * 
     * BCrypt :
     * - Génère automatiquement un salt unique
     * - Le coût (strength) ralentit les attaques brute-force
     * - Résistant aux rainbow tables
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Strength de 12 (2^12 = 4096 itérations)
        // Plus le nombre est élevé, plus c'est sécurisé mais lent
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Configuration CORS restrictive.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Domaines autorisés (à adapter selon l'environnement)
        configuration.setAllowedOrigins(List.of(
            "https://securebank.example.com",
            "https://www.securebank.example.com"
        ));
        
        // En développement uniquement
        // configuration.setAllowedOrigins(List.of("http://localhost:3000"));
        
        // Méthodes HTTP autorisées
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // Headers autorisés
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "X-CSRF-TOKEN"
        ));
        
        // Headers exposés au client
        configuration.setExposedHeaders(Arrays.asList(
            "X-CSRF-TOKEN",
            "Authorization"
        ));
        
        // Autoriser les credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);
        
        // Durée de cache du preflight
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
