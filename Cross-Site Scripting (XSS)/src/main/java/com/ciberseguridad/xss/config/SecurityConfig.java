package com.ciberseguridad.xss.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de Spring Security para el laboratorio didáctico de XSS.
 * Permite el acceso público a los endpoints didácticos, la consola H2 y los recursos estáticos.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/",
                    "/index.html",
                    "/style.css",
                    "/app.js",
                    "/api/**",
                    "/vulnerable/**",
                    "/mitigado/**",
                    "/h2-console/**",
                    "/favicon.ico"
                ).permitAll()
                .anyRequest().permitAll()
            )
            .headers(headers -> headers
                // Permite el uso de iframe para la consola H2 y los visualizadores de prueba
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
            );

        return http.build();
    }
}
