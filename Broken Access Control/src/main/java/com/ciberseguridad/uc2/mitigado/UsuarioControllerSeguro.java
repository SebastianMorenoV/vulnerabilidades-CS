package com.ciberseguridad.uc2.mitigado;

import com.ciberseguridad.uc2.Perfil;
import com.ciberseguridad.uc2.PerfilRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * =========================================================================================
 * CONTROLADOR MITIGADO: SOLUCIÓN A BROKEN ACCESS CONTROL (IDOR) - OWASP TOP 1:2021
 * =========================================================================================
 * 
 * MECANISMOS DE MITIGACIÓN IMPLEMENTADOS:
 * 1. Control de Acceso a Nivel de Objeto (Object-Level Authorization):
 *    No basta con saber que la petición proviene de un usuario autenticado (HTTP Basic).
 *    El sistema valida expresamente que el recurso solicitado pertenezca al usuario en sesión.
 * 
 * 2. Anotaciones Declarativas con SpEL (@PreAuthorize):
 *    Se evalúan las políticas de seguridad ANTES de ejecutar el método del controlador.
 *    - Para acceso por ID: Delegación en @autorizacionService.puedeAccederAPerfil(#id, authentication).
 *    - Para acceso por Username: Validación directa de SpEL 'authentication.name == #usernameSolicitado'.
 * 
 * 3. Principio de Menor Privilegio (Least Privilege):
 *    Solo el usuario propietario o un administrador tienen acceso a información sensible.
 *    Cualquier intento no autorizado se corta de inmediato con HTTP 403 Forbidden.
 * =========================================================================================
 */
@RestController
@RequestMapping("/api/mitigado")
public class UsuarioControllerSeguro {

    private final PerfilRepository perfilRepository;

    public UsuarioControllerSeguro(PerfilRepository perfilRepository) {
        this.perfilRepository = perfilRepository;
    }

    /**
     * ENDPOINT MITIGADO POR ID: GET /api/mitigado/perfil/{id}
     * 
     * Utiliza @PreAuthorize delegando la verificación de propiedad al bean 'autorizacionService'.
     * Si "erick" intenta consultar el perfil ID=2 (perteneciente a "victima"), la expresión
     * evaluará 'false' y Spring Security interceptará la llamada arrojando un HTTP 403 Forbidden.
     */
    @GetMapping("/perfil/{id}")
    @PreAuthorize("hasRole('ADMIN') or @autorizacionService.puedeAccederAPerfil(#id, authentication)")
    public ResponseEntity<Perfil> obtenerPerfilSeguroPorId(@PathVariable Long id) {
        Perfil perfil = perfilRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil no encontrado"));

        return ResponseEntity.ok(perfil);
    }

    /**
     * ENDPOINT MITIGADO POR USERNAME: GET /api/mitigado/perfil/usuario/{usernameSolicitado}
     * 
     * Implementación directa con la sintaxis de SpEL requerida:
     * @PreAuthorize("hasRole('ADMIN') or authentication.name == #usernameSolicitado")
     * 
     * Valida que el nombre de usuario autenticado en la sesión (authentication.name)
     * coincida exactamente con el parámetro #usernameSolicitado enviado en la URL.
     */
    @GetMapping("/perfil/usuario/{usernameSolicitado}")
    @PreAuthorize("hasRole('ADMIN') or authentication.name == #usernameSolicitado")
    public ResponseEntity<Perfil> obtenerPerfilSeguroPorUsername(@PathVariable String usernameSolicitado) {
        Perfil perfil = perfilRepository.findByUsername(usernameSolicitado)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil no encontrado para el usuario: " + usernameSolicitado));

        return ResponseEntity.ok(perfil);
    }
}
