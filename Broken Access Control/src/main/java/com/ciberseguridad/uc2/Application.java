package com.ciberseguridad.uc2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Clase principal de arranque de Spring Boot.
 * Proyecto didáctico para la demostración de vulnerabilidad Broken Access Control (IDOR)
 * en la clase de Ciberseguridad Aplicada.
 */
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
