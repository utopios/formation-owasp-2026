package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Application bancaire vulnérable pour formation DevSecOps.
 * 
 * ATTENTION: Cette application contient des vulnérabilités INTENTIONNELLES
 * à des fins pédagogiques. NE JAMAIS utiliser ce code en production !
 * 
 * Vulnérabilités présentes :
 * - Injection SQL
 * - Cross-Site Scripting (XSS)
 * - Broken Access Control
 * - Security Misconfiguration
 * - Sensitive Data Exposure
 * - Insecure Deserialization
 * - Logging injection
 * - Path Traversal
 */
@SpringBootApplication
public class VulnerableBankApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableBankApplication.class, args);
    }
}
