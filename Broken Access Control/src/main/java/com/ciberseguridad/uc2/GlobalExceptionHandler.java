package com.ciberseguridad.uc2;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ResponseStatusException;

/**
 * Manejador global de excepciones para proporcionar respuestas JSON claras
 * y didácticas durante la demostración en vivo.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Captura las violaciones de seguridad lanzadas por @PreAuthorize (AccessDeniedException)
     * y retorna explícitamente HTTP 403 Forbidden con un mensaje descriptivo.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> manejarAccesoDenegado(AccessDeniedException ex, WebRequest request) {
        Map<String, Object> errorDetails = new LinkedHashMap<>();
        errorDetails.put("timestamp", LocalDateTime.now().toString());
        errorDetails.put("status", HttpStatus.FORBIDDEN.value());
        errorDetails.put("error", "Forbidden");
        errorDetails.put("alertaSeguridad", "VULNERABILIDAD IDOR BLOQUEADA");
        errorDetails.put("mensaje", "Acceso denegado (HTTP 403): El usuario autenticado no tiene autorización para acceder al recurso solicitado.");
        errorDetails.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorDetails);
    }

    /**
     * Captura ResponseStatusException (por ejemplo 404 NOT FOUND si el ID no existe).
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> manejarResponseStatusException(ResponseStatusException ex, WebRequest request) {
        Map<String, Object> errorDetails = new LinkedHashMap<>();
        errorDetails.put("timestamp", LocalDateTime.now().toString());
        errorDetails.put("status", ex.getStatusCode().value());
        errorDetails.put("error", ex.getStatusCode().toString());
        errorDetails.put("mensaje", ex.getReason());
        errorDetails.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(ex.getStatusCode()).body(errorDetails);
    }
}
