package com.ciberseguridad.uc2.vulnerable;

import com.ciberseguridad.uc2.Perfil;
import com.ciberseguridad.uc2.PerfilRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * =========================================================================================
 * DEMOSTRACIÓN DE VULNERABILIDAD: BROKEN ACCESS CONTROL (IDOR) - OWASP TOP 1:2021
 * =========================================================================================
 * 
 * ¿QUÉ ES IDOR (Insecure Direct Object Reference)?
 * Ocurre cuando una aplicación expone una referencia directa a un objeto interno (en este
 * caso, la clave primaria de la base de datos {id}) en un parámetro de la URL, y el backend
 * confía ciegamente en dicha entrada sin validar si el usuario autenticado tiene permisos
 * legítimos para acceder a dicho objeto.
 * 
 * FALLO EN ESTE CONTROLADOR:
 * 1. El endpoint requiere autenticación (Spring Security valida que el usuario esté logueado).
 * 2. Sin embargo, confunde AUTENTICACIÓN (saber quién eres) con AUTORIZACIÓN (saber a qué tienes acceso).
 * 3. NO se realiza ninguna comprobación entre el usuario logueado en la sesión (por ejemplo, "erick")
 *    y el propietario del perfil con identificador {id}.
 * 
 * ESCENARIO DE ATAQUE EN VIVO:
 * - El atacante "erick" se loguea legítimamente con sus credenciales (-u erick:password).
 * - Su perfil personal tiene el ID = 1.
 * - Simplemente cambiando el identificador en la URL a GET /api/vulnerable/perfil/2, el servidor
 *   consulta directamente el ID 2 en la base de datos y le entrega a "erick" el perfil completo
 *   de la "victima", incluyendo su 'datoSecreto' ("Contraseñas corporativas").
 * =========================================================================================
 */
@RestController
@RequestMapping("/api/vulnerable")
public class UsuarioControllerVulnerable {

    private final PerfilRepository perfilRepository;

    public UsuarioControllerVulnerable(PerfilRepository perfilRepository) {
        this.perfilRepository = perfilRepository;
    }

    /**
     * ENDPOINT VULNERABLE A IDOR.
     * 
     * Recibe un ID numérico secuencial directamente por la ruta /{id} y devuelve el objeto sin
     * verificar la identidad del emisor de la petición.
     */
    @GetMapping("/perfil/{id}")
    public ResponseEntity<Perfil> obtenerPerfilVulnerable(@PathVariable Long id) {
        // [VULNERABILIDAD CRÍTICA]
        // Se busca el registro por ID directamente en el repositorio.
        // Falta la verificación de pertenencia: "¿El usuario autenticado es dueño del perfil con este ID?"
        Perfil perfil = perfilRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil no encontrado"));

        // Se expone la información confidencial de cualquier usuario
        return ResponseEntity.ok(perfil);
    }
}
