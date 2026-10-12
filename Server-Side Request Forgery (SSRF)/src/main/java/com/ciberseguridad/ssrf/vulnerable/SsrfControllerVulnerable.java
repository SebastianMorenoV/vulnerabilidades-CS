package com.ciberseguridad.ssrf.vulnerable;

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
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * =========================================================================================
 * DEMOSTRACIÓN DE VULNERABILIDAD: SERVER-SIDE REQUEST FORGERY (SSRF) - OWASP TOP 10:2021
 * =========================================================================================
 * 
 * ¿QUÉ ES SSRF (Server-Side Request Forgery)?
 * Ocurre cuando un servidor web obtiene recursos remotos (como imágenes, vistas previas de
 * enlaces, webhooks o importación de datos) a partir de una URL suministrada por el usuario,
 * SIN validar previamente la dirección de destino ni el protocolo utilizado.
 * 
 * FALLO EN ESTE CONTROLADOR:
 * 1. Confía ciegamente en el parámetro 'url' proporcionado por el usuario en la petición.
 * 2. NO restringe protocolos (permite HTTP, HTTPS, FILE, etc.).
 * 3. NO verifica si el destino apunta a la red interna (localhost, 127.0.0.1, 192.168.x.x).
 * 4. NO bloquea el acceso al servicio de metadatos de Cloud (169.254.169.254 / AWS IMDS).
 * 5. Reutiliza un cliente HTTP configurado con credenciales internas del sistema, provocando
 *    que el atacante se salte todas las políticas de firewall perimetral.
 * 
 * IMPACTO DEL ATAQUE:
 * - Robo de credenciales de bases de datos y tokens confidenciales de la intranet.
 * - Extracción de credenciales de infraestructura en la nube (AWS EC2 IAM Keys).
 * - Lectura arbitraria de archivos del servidor mediante el esquema 'file://'.
 * - Escaneo de puertos y servicios internos no expuestos a Internet.
 * =========================================================================================
 */
@RestController
@RequestMapping("/api/vulnerable")
public class SsrfControllerVulnerable {

    private static final Logger log = LoggerFactory.getLogger(SsrfControllerVulnerable.class);

    /**
     * ENDPOINT VULNERABLE A SSRF: GET /api/vulnerable/preview?url=...
     * 
     * Simula un servicio de vista previa de páginas web o descarga de avatares.
     */
    @GetMapping("/preview")
    public ResponseEntity<Map<String, Object>> obtenerVistaPreviaVulnerable(@RequestParam("url") String urlObjetivo) {
        return procesarPeticionVulnerable(urlObjetivo);
    }

    /**
     * ENDPOINT VULNERABLE A SSRF: POST /api/vulnerable/fetch-url
     * 
     * Recibe la URL en el cuerpo JSON: { "url": "..." }
     */
    @PostMapping("/fetch-url")
    public ResponseEntity<Map<String, Object>> descargarRecursoVulnerable(@RequestBody Map<String, String> payload) {
        String urlObjetivo = payload.get("url");
        if (urlObjetivo == null || urlObjetivo.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El parámetro 'url' es requerido.");
        }
        return procesarPeticionVulnerable(urlObjetivo);
    }

    private ResponseEntity<Map<String, Object>> procesarPeticionVulnerable(String urlObjetivo) {
        log.warn("[PETICIÓN VULNERABLE PROCESADA] El servidor intentará consultar la URL sin validación: {}", urlObjetivo);

        StringBuilder contenidoRespuesta = new StringBuilder();
        int codigoRespuestaHttp = 200;

        try {
            URL url = new URL(urlObjetivo);

            // [VULNERABILIDAD CRÍTICA]:
            // Si el protocolo es 'file://', se leen directamente archivos locales del servidor
            if ("file".equalsIgnoreCase(url.getProtocol())) {
                try (InputStream inputStream = url.openStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    String linea;
                    int lineasLeidas = 0;
                    while ((linea = reader.readLine()) != null && lineasLeidas < 50) {
                        contenidoRespuesta.append(linea).append("\n");
                        lineasLeidas++;
                    }
                }
            } else {
                // Conexión HTTP / HTTPS sin filtrado de IP
                HttpURLConnection conexion = (HttpURLConnection) url.openConnection();
                conexion.setRequestMethod("GET");
                conexion.setConnectTimeout(4000);
                conexion.setReadTimeout(4000);

                // El cliente del backend propaga automáticamente credenciales del sistema interno
                String basicAuth = Base64.getEncoder().encodeToString("sistema-interno:internal-secret-token-xyz".getBytes(StandardCharsets.UTF_8));
                conexion.setRequestProperty("Authorization", "Basic " + basicAuth);

                codigoRespuestaHttp = conexion.getResponseCode();

                InputStream is = (codigoRespuestaHttp >= 200 && codigoRespuestaHttp < 400)
                        ? conexion.getInputStream()
                        : conexion.getErrorStream();

                if (is != null) {
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                        String linea;
                        while ((linea = reader.readLine()) != null) {
                            contenidoRespuesta.append(linea).append("\n");
                        }
                    }
                }
            }

            Map<String, Object> resultado = new LinkedHashMap<>();
            resultado.put("estado", "ÉXITO_VULNERABLE");
            resultado.put("urlConsultada", urlObjetivo);
            resultado.put("codigoHttpRemoto", codigoRespuestaHttp);
            resultado.put("contenidoRecuperado", contenidoRespuesta.toString().trim());
            resultado.put("advertencia", "⚠️ EL SERVIDOR EJECUTÓ LA PETICIÓN INTERNA SIN VERIFICAR EL DESTINO.");

            return ResponseEntity.ok(resultado);

        } catch (Exception e) {
            log.error("[ERROR EN PETICIÓN SSRF] Fallo al consultar {}: {}", urlObjetivo, e.getMessage());
            Map<String, Object> errorMap = new LinkedHashMap<>();
            errorMap.put("estado", "ERROR_CONEXION");
            errorMap.put("urlConsultada", urlObjetivo);
            errorMap.put("detalleError", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
        }
    }
}
