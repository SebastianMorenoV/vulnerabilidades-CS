package com.ciberseguridad.ssrf.mitigado;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * =========================================================================================
 * CONTROLADOR MITIGADO: SOLUCIÓN A SERVER-SIDE REQUEST FORGERY (SSRF) - OWASP TOP 10:2021
 * =========================================================================================
 * 
 * MECANISMOS DE MITIGACIÓN IMPLEMENTADOS:
 * 1. Validación en Profundidad (SsrfValidatorService):
 *    - Whitelist estricta de protocolos (solo HTTP y HTTPS).
 *    - Resolución DNS y bloqueo de IPs privadas (RFC 1918), Loopback (127.0.0.1, ::1)
 *      y Cloud Metadata (169.254.169.254).
 * 
 * 2. Desactivación de Redirecciones HTTP Automáticas:
 *    - Se deshabilita 'setInstanceFollowRedirects(false)' para prevenir ataques por rebote
 *      donde un servidor externo redirecciona (302) a un endpoint interno.
 * 
 * 3. Aislamiento de Credenciales:
 *    - El cliente HTTP saliente NO adjunta credenciales internas ni tokens corporativos.
 * 
 * 4. Timeouts Estrictos:
 *    - Se establecen límites de tiempo de conexión y lectura para mitigar ataques DoS.
 * =========================================================================================
 */
@RestController
@RequestMapping("/api/mitigado")
public class SsrfControllerSeguro {

    private static final Logger log = LoggerFactory.getLogger(SsrfControllerSeguro.class);

    private final SsrfValidatorService ssrfValidatorService;

    public SsrfControllerSeguro(SsrfValidatorService ssrfValidatorService) {
        this.ssrfValidatorService = ssrfValidatorService;
    }

    /**
     * ENDPOINT SEGURO: GET /api/mitigado/preview?url=...
     */
    @GetMapping("/preview")
    public ResponseEntity<Map<String, Object>> obtenerVistaPreviaSegura(@RequestParam("url") String urlObjetivo) {
        return procesarPeticionSegura(urlObjetivo);
    }

    /**
     * ENDPOINT SEGURO: POST /api/mitigado/fetch-url
     */
    @PostMapping("/fetch-url")
    public ResponseEntity<Map<String, Object>> descargarRecursoSeguro(@RequestBody Map<String, String> payload) {
        String urlObjetivo = payload.get("url");
        if (urlObjetivo == null || urlObjetivo.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El parámetro 'url' es requerido.");
        }
        return procesarPeticionSegura(urlObjetivo);
    }

    private ResponseEntity<Map<String, Object>> procesarPeticionSegura(String urlObjetivo) {
        // [PASO 1: VALIDACIÓN INTEGRAL CONTRA SSRF]
        // Si la URL apunta a localhost, redes privadas, metadata o esquemas no autorizados,
        // el validador arroja una excepción que devuelve HTTP 400 Bad Request.
        URI uriSegura = ssrfValidatorService.validarUrlSegura(urlObjetivo);

        log.info("[PETICIÓN MITIGADA] URL validada y autorizada para descarga: {}", uriSegura);

        StringBuilder contenidoRespuesta = new StringBuilder();
        int codigoRespuestaHttp = 200;

        try {
            HttpURLConnection conexion = (HttpURLConnection) uriSegura.toURL().openConnection();
            conexion.setRequestMethod("GET");
            conexion.setConnectTimeout(3000);
            conexion.setReadTimeout(3000);

            // [MITIGACIÓN CRÍTICA]: Deshabilitar seguimiento automático de redirecciones
            conexion.setInstanceFollowRedirects(false);

            codigoRespuestaHttp = conexion.getResponseCode();

            // Si el servidor remoto intenta redireccionar hacia otra URL, se corta la petición
            if (codigoRespuestaHttp == HttpURLConnection.HTTP_MOVED_PERM ||
                codigoRespuestaHttp == HttpURLConnection.HTTP_MOVED_TEMP ||
                codigoRespuestaHttp == HttpURLConnection.HTTP_SEE_OTHER) {
                log.warn("[ALERTA SEGURIDAD] Servidor remoto intentó redirección HTTP {}. Petición abortada.", codigoRespuestaHttp);
                Map<String, Object> errorRedirect = new LinkedHashMap<>();
                errorRedirect.put("estado", "REDIRECCION_BLOQUEADA");
                errorRedirect.put("mensaje", "Por políticas de seguridad contra SSRF, las redirecciones HTTP no están permitidas.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorRedirect);
            }

            InputStream is = (codigoRespuestaHttp >= 200 && codigoRespuestaHttp < 400)
                    ? conexion.getInputStream()
                    : conexion.getErrorStream();

            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    String linea;
                    int lineasLeidas = 0;
                    while ((linea = reader.readLine()) != null && lineasLeidas < 100) {
                        contenidoRespuesta.append(linea).append("\n");
                        lineasLeidas++;
                    }
                }
            }

            Map<String, Object> resultado = new LinkedHashMap<>();
            resultado.put("estado", "ÉXITO_SEGURO");
            resultado.put("urlConsultada", urlObjetivo);
            resultado.put("codigoHttpRemoto", codigoRespuestaHttp);
            resultado.put("contenidoRecuperado", contenidoRespuesta.toString().trim());
            resultado.put("proteccion", "🛡️ Destino analizado y certificado: IP externa y pública permitida.");

            return ResponseEntity.ok(resultado);

        } catch (Exception e) {
            log.error("[ERROR EN PETICIÓN SEGURA] No fue posible conectar con {}: {}", urlObjetivo, e.getMessage());
            Map<String, Object> errorMap = new LinkedHashMap<>();
            errorMap.put("estado", "ERROR_CONEXION_SEGURA");
            errorMap.put("urlConsultada", urlObjetivo);
            errorMap.put("detalleError", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(errorMap);
        }
    }
}
