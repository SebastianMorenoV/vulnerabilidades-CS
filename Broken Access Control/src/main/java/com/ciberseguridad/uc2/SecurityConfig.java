package com.ciberseguridad.uc2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de Spring Security con autenticación HTTP Basic.
 * 
 * Habilita:
 * 1. Usuarios en memoria ('erick', 'victima', y 'admin').
 * 2. Autenticación básica HTTP (-u usuario:password).
 * 3. @EnableMethodSecurity para activar expresiones @PreAuthorize en controladores/servicios.
 * 4. Deshabilitación de CSRF y sesiones sin estado (Stateless) para pruebas limpias con cURL.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Define los usuarios en memoria para la demostración en vivo:
     * - 'erick': password='password', rol='USER'
     * - 'victima': password='password', rol='USER'
     * - 'admin': password='password', rol='ADMIN'
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails erick = User.builder()
                .username("erick")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        UserDetails victima = User.builder()
                .username("victima")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("password"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(erick, victima, admin);
    }

    /**
     * Cadena de filtros de seguridad.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Deshabilitar CSRF para simplificar peticiones REST con herramientas como cURL / Postman
                .csrf(AbstractHttpConfigurer::disable)

                // Permitir visualización de consola H2 si es necesaria
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                // Configuración de sesiones sin estado para APIs REST
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Rutas autorizadas
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )

                // Autenticación HTTP Basic estándar
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
