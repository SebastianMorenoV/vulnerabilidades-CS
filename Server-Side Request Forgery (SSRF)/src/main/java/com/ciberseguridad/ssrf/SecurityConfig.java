package com.ciberseguridad.ssrf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de Spring Security para el laboratorio de SSRF.
 * 
 * Escenario de seguridad:
 * 1. Los endpoints públicos y de usuario (/api/**) requieren autenticación básica.
 * 2. El endpoint interno (/internal/**) simula un microservicio de la intranet o metadatos
 *    protegido por un firewall perimetral o rol ADMIN, no accesible directamente por usuarios estándar.
 * 3. Demuestra cómo un ataque SSRF permite que un atacante estándar (con rol USER) salte
 *    dicho perímetro de seguridad haciendo que el propio servidor consulte los datos confidenciales.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        // Alumno / Atacante: Usuario estándar sin privilegios de administración
        UserDetails alumno = User.builder()
                .username("alumno")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        // Administrador legítimo
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("password"))
                .roles("ADMIN")
                .build();

        // Credencial de servicio interno del sistema
        UserDetails sistemaInterno = User.builder()
                .username("sistema-interno")
                .password(passwordEncoder.encode("internal-secret-token-xyz"))
                .roles("INTERNAL_SYSTEM")
                .build();

        return new InMemoryUserDetailsManager(alumno, admin, sistemaInterno);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Simulación de Cloud Metadata IMDS y servicios de Intranet:
                        // Solo accesible con credenciales de ADMIN o sistema interno
                        .requestMatchers("/internal/**").hasAnyRole("ADMIN", "INTERNAL_SYSTEM")
                        .requestMatchers("/latest/meta-data/**").hasAnyRole("ADMIN", "INTERNAL_SYSTEM")
                        // Endpoints de la API para pruebas
                        .requestMatchers("/api/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
