package com.ciberseguridad.ssrf.internal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * =========================================================================================
 * SIMULACIÓN DE SERVICIOS INTERNOS PRIVADOS / INTRANET Y METADATOS CLOUD
 * =========================================================================================
 * 
 * En una infraestructura real, estos endpoints corresponden a:
 * 1. Microservicios internos de la intranet que no están expuestos a Internet.
 * 2. Servicios de metadatos de la nube (como el servicio IMDS de AWS: 169.254.169.254).
 * 3. Paneles de administración interna para orquestación de bases de datos.
 * 
 * PROTECCIÓN PERIMETRAL:
 * - Un usuario estándar (como 'alumno') NO tiene acceso directo a estos endpoints debido a
 *   las reglas de firewall / Spring Security (recibe HTTP 403 Forbidden).
 * - Sin embargo, a través de una vulnerabilidad SSRF en un servicio del backend, el atacante
 *   obliga al SERVIDOR a realizar la petición en su nombre, vulnerando el perímetro.
 * =========================================================================================
 */
@RestController
public class InternalAdminController {

    /**
     * Endpoint interno con credenciales críticas del sistema.
     * Solo debería ser accesible internamente por el sistema o por administradores.
     */
    @GetMapping("/internal/admin/claves-api")
    public ResponseEntity<Map<String, Object>> obtenerClavesInternas() {
        Map<String, Object> respuesta = new LinkedHashMap<>();
        respuesta.put("servicio", "Bóveda de Credenciales Corporativas (Intranet Interna)");
        respuesta.put("estado", "CONFIDENCIAL - USO EXCLUSIVO INTERNO");
        respuesta.put("database_host", "db-prod.internal.corp:5432");
        respuesta.put("database_password", "SuperSecretPostgres2026!#");
        respuesta.put("stripe_api_key", "sk_live_51M0xDemoSecretKeyProd999");
        respuesta.put("jwt_secret_signing_key", "ultra-secret-hmac-sha256-key-ciberseguridad");
        return ResponseEntity.ok(respuesta);
    }

    /**
     * Endpoint que simula el servicio de metadatos de instancias Cloud (AWS EC2 / GCP Metadata).
     * En ataques reales a la nube (como el famoso hackeo de Capital One), el atacante usa SSRF
     * hacia http://169.254.169.254/latest/meta-data/iam/security-credentials para extraer tokens de IAM.
     */
    @GetMapping("/latest/meta-data/iam/security-credentials")
    public ResponseEntity<Map<String, Object>> obtenerMetadatosCloud() {
        Map<String, Object> credenciales = new LinkedHashMap<>();
        credenciales.put("Code", "Success");
        credenciales.put("Type", "AWS-HMAC");
        credenciales.put("RoleName", "Production-App-Server-Role");
        credenciales.put("AccessKeyId", "ASIAEXAMPLEACCESSKEY99");
        credenciales.put("SecretAccessKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        credenciales.put("Token", "IQoJb3JpZ2luX2VjEIz//////////wEaCXVzLWVhc3QtMSJGMEQCID8...[Token Temporal IAM]");
        credenciales.put("Expiration", "2026-10-12T23:59:59Z");
        return ResponseEntity.ok(credenciales);
    }
}
