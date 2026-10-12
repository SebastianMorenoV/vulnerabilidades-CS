package com.ciberseguridad.ssrf;

import com.ciberseguridad.ssrf.mitigado.SsrfValidatorService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SsrfDemonstrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private SsrfValidatorService validatorService;

    @Test
    @DisplayName("CONTROL PERIMETRAL: Alumno no puede acceder directamente a /internal/admin/claves-api (403 Forbidden)")
    void testDirectAccessAlumnoDenegado() {
        ResponseEntity<String> response = restTemplate
                .withBasicAuth("alumno", "password")
                .getForEntity("http://localhost:" + port + "/internal/admin/claves-api", String.class);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    @DisplayName("VULNERABLE (SSRF Cloud Metadata): Alumno extrae tokens de IAM explotando el endpoint vulnerable (200 OK)")
    void testVulnerableSsrfExtraeMetadatos() {
        String metadataUrl = "http://localhost:" + port + "/latest/meta-data/iam/security-credentials";

        ResponseEntity<String> response = restTemplate
                .withBasicAuth("alumno", "password")
                .getForEntity("http://localhost:" + port + "/api/vulnerable/preview?url=" + metadataUrl, String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("ASIAEXAMPLEACCESSKEY99"));
        assertTrue(response.getBody().contains("Production-App-Server-Role"));
        assertTrue(response.getBody().contains("ÉXITO_VULNERABLE"));
    }

    @Test
    @DisplayName("VULNERABLE (SSRF Intranet): Alumno extrae credenciales de base de datos y Stripe usando el servidor como puente")
    void testVulnerableSsrfExtraeClavesInternas() {
        String internalServiceUrl = "http://localhost:" + port + "/internal/admin/claves-api";

        ResponseEntity<String> response = restTemplate
                .withBasicAuth("alumno", "password")
                .getForEntity("http://localhost:" + port + "/api/vulnerable/preview?url=" + internalServiceUrl, String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("SuperSecretPostgres2026!#"));
        assertTrue(response.getBody().contains("sk_live_51M0xDemoSecretKeyProd999"));
    }

    @Test
    @DisplayName("MITIGADO: Bloquea intento de SSRF hacia localhost (400 Bad Request)")
    void testMitigadoBloqueaLocalhost() {
        String urlAtaque = "http://localhost:" + port + "/latest/meta-data/iam/security-credentials";

        ResponseEntity<String> response = restTemplate
                .withBasicAuth("alumno", "password")
                .getForEntity("http://localhost:" + port + "/api/mitigado/preview?url=" + urlAtaque, String.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("VULNERABILIDAD SSRF BLOQUEADA"));
    }

    @Test
    @DisplayName("MITIGADO: Bloquea intento de SSRF hacia IP de Loopback 127.0.0.1 (400 Bad Request)")
    void testMitigadoBloquea127001() {
        String urlAtaque = "http://127.0.0.1:" + port + "/internal/admin/claves-api";

        ResponseEntity<String> response = restTemplate
                .withBasicAuth("alumno", "password")
                .getForEntity("http://localhost:" + port + "/api/mitigado/preview?url=" + urlAtaque, String.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("VULNERABILIDAD SSRF BLOQUEADA"));
    }

    @Test
    @DisplayName("MITIGADO: Bloquea protocolo peligroso file:/// (400 Bad Request)")
    void testMitigadoBloqueaProtocoloFile() {
        String urlAtaque = "file:///etc/passwd";

        ResponseEntity<String> response = restTemplate
                .withBasicAuth("alumno", "password")
                .getForEntity("http://localhost:" + port + "/api/mitigado/preview?url=" + urlAtaque, String.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("Solo se aceptan HTTP y HTTPS"));
    }

    @Test
    @DisplayName("DEFENSA EN PROFUNDIDAD (Validador): Rechaza rangos privados RFC 1918 y Cloud Metadata IP 169.254.169.254")
    void testValidadorDetectaRangosPeligrosos() {
        // Cloud Metadata IP
        assertThrows(IllegalArgumentException.class, () ->
                validatorService.validarUrlSegura("http://169.254.169.254/latest/meta-data/")
        );

        // IP Privada 10.0.0.1
        assertThrows(IllegalArgumentException.class, () ->
                validatorService.validarUrlSegura("http://10.0.0.1/admin")
        );

        // IP Privada 192.168.1.1
        assertThrows(IllegalArgumentException.class, () ->
                validatorService.validarUrlSegura("http://192.168.1.1/router-login")
        );

        // Esquemas no permitidos (gopher, ftp, file)
        assertThrows(IllegalArgumentException.class, () ->
                validatorService.validarUrlSegura("gopher://127.0.0.1:6379/_flushall")
        );
        assertThrows(IllegalArgumentException.class, () ->
                validatorService.validarUrlSegura("ftp://servidor-interno/archivo.txt")
        );
    }
}
