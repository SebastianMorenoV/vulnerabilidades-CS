package com.ciberseguridad.uc2.mitigado;

import com.ciberseguridad.uc2.Perfil;
import com.ciberseguridad.uc2.PerfilRepository;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * Servicio de autorización que implementa las reglas de control de acceso
 * basadas en el contexto del recurso (Object-Level Access Control).
 * 
 * Este bean está registrado como "autorizacionService" para ser invocado
 * dinámicamente desde expresiones SpEL en anotaciones como @PreAuthorize.
 */
@Service("autorizacionService")
public class AutorizacionService {

    private static final Logger log = LoggerFactory.getLogger(AutorizacionService.class);

    private final PerfilRepository perfilRepository;

    public AutorizacionService(PerfilRepository perfilRepository) {
        this.perfilRepository = perfilRepository;
    }

    /**
     * Valida si el usuario actualmente autenticado tiene permiso para acceder
     * al perfil identificado por 'id'.
     *
     * Regla de negocio y seguridad:
     * - Un usuario con rol ADMIN puede acceder a cualquier perfil.
     * - Un usuario estándar (USER) SOLO puede acceder a su propio perfil (su username debe coincidir
     *   con el username asociado al ID solicitado).
     *
     * @param id ID del perfil solicitado
     * @param authentication Datos del usuario autenticado en la sesión
     * @return true si el acceso es legítimo, false si es un intento de IDOR no autorizado
     */
    public boolean puedeAccederAPerfil(Long id, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("[CONTROL DE ACCESO] Rechazado: Petición anónima o no autenticada.");
            return false;
        }

        String usuarioLogueado = authentication.getName();

        // 1. Verificar si el usuario tiene rol de Administrador
        boolean esAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        if (esAdmin) {
            log.info("[CONTROL DE ACCESO] Acceso permitido: El usuario '{}' es ADMIN.", usuarioLogueado);
            return true;
        }

        // 2. Buscar el perfil objetivo en la base de datos
        Optional<Perfil> perfilOpt = perfilRepository.findById(id);
        if (perfilOpt.isEmpty()) {
            // Si no existe, se permite pasar al controlador para que responda con 404 Not Found
            return true;
        }

        Perfil perfilObjetivo = perfilOpt.get();

        // 3. Verificación de propiedad (Ownership Check): ¿El usuario logueado es el dueño del perfil?
        boolean esPropietario = perfilObjetivo.getUsername().equalsIgnoreCase(usuarioLogueado);

        if (!esPropietario) {
            log.warn("[ALERTA DE SEGURIDAD - IDOR DETECTADO] El usuario '{}' intentó acceder sin autorización al perfil ID {} perteneciente a '{}'. Acceso Bloqueado.",
                    usuarioLogueado, id, perfilObjetivo.getUsername());
            return false;
        }

        log.info("[CONTROL DE ACCESO] Acceso permitido: El usuario '{}' es el propietario legítimo del perfil ID {}.",
                usuarioLogueado, id);
        return true;
    }
}
