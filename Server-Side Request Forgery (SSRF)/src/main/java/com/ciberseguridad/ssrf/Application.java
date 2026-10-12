package com.ciberseguridad.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Aplicación de Demostración: Server-Side Request Forgery (SSRF) - OWASP Top 10:2021 (A10)
 * 
 * Diseñada para fines didácticos en la asignatura de Ciberseguridad Aplicada (UC2).
 */
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
