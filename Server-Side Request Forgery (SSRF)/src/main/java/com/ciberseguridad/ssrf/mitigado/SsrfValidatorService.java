package com.ciberseguridad.ssrf.mitigado;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * =========================================================================================
 * SERVICIO DE VALIDACIÓN CONTRA SSRF (DEFENSA EN PROFUNDIDAD - OWASP CHEAT SHEET)
 * =========================================================================================
 * 
 * Implementa las recomendaciones oficiales de OWASP para prevenir Server-Side Request Forgery:
 * 
 * 1. LISTA BLANCA DE PROTOCOLOS (SCHEME WHITELISTING):
 *    Solo se autorizan 'http' y 'https'. Se rechazan de inmediato esquemas peligrosos
 *    como 'file://', 'gopher://', 'dict://', 'ftp://', 'ldap://'.
 * 
 * 2. RESOLUCIÓN DNS Y ANÁLISIS DE DIRECCIONES IP (ANTI-DNS REBINDING & IP VALIDATION):
 *    Se resuelve el nombre de host a sus direcciones IP reales y se verifica que NINGUNA
 *    pertenezca a rangos prohibidos:
 *    - Loopback: 127.0.0.1, localhost, ::1
 *    - AnyLocal: 0.0.0.0
 *    - Direcciones privadas (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 *    - Link-Local / Cloud Metadata: 169.254.0.0/16 (Utilizado por AWS, GCP, Azure, DigitalOcean)
 *    - Multicast y direcciones de difusión
 * 
 * 3. LISTA BLANCA DE DOMINIOS CONFIABLES (OPTATIVO / ENTORNO CORPORATIVO):
 *    Permite limitar el consumo exclusivamente a socios o APIs autorizadas (ej. api.github.com).
 * =========================================================================================
 */
@Service
public class SsrfValidatorService {

    private static final Logger log = LoggerFactory.getLogger(SsrfValidatorService.class);

    // Protocolos permitidos estrictamente
    private static final Set<String> PROTOCOLOS_PERMITIDOS = Set.of("http", "https");

    // Rango Link-Local reservado para Cloud Metadata (169.254.0.0/16)
    private static final String AWS_METADATA_IP = "169.254.169.254";

    // Dominios públicos de ejemplo permitidos para servicios de integración
    private static final List<String> DOMINIOS_PERMITIDOS = List.of(
            "api.github.com",
            "httpbin.org",
            "via.placeholder.com",
            "jsonplaceholder.typicode.com"
    );

    /**
     * Valida integralmente una URL contra vulnerabilidades de SSRF.
     * Lanza IllegalArgumentException si detecta cualquier vector de ataque.
     *
     * @param urlString URL recibida desde el cliente
     * @return URI validada y segura
     */
    public URI validarUrlSegura(String urlString) {
        if (urlString == null || urlString.trim().isEmpty()) {
            throw new IllegalArgumentException("La URL no puede ser nula ni estar vacía.");
        }

        URI uri;
        try {
            uri = new URI(urlString.trim());
        } catch (Exception e) {
            throw new IllegalArgumentException("Sintaxis de URL inválida: " + e.getMessage());
        }

        // 1. Validación del Protocolo / Esquema
        String scheme = uri.getScheme();
        if (scheme == null || !PROTOCOLOS_PERMITIDOS.contains(scheme.toLowerCase())) {
            log.warn("[ALERTA SSRF] Intento de acceso con protocolo no permitido: '{}'", scheme);
            throw new IllegalArgumentException("Protocolo '" + scheme + "' no permitido. Solo se aceptan HTTP y HTTPS.");
        }

        String host = uri.getHost();
        if (host == null || host.trim().isEmpty()) {
            throw new IllegalArgumentException("El host de la URL no es válido o está ausente.");
        }

        // 2. Comprobación de palabras clave de Loopback inmediatas
        if (host.equalsIgnoreCase("localhost") || host.equalsIgnoreCase("127.0.0.1") || host.equals("::1") || host.equals("0.0.0.0")) {
            log.warn("[ALERTA SSRF DETECTADO] Intento de consulta directa a Loopback/Localhost: '{}'", host);
            throw new IllegalArgumentException("Acceso bloqueado: No se permite realizar peticiones hacia localhost o loopback.");
        }

        // 3. Resolución DNS y verificación profunda de IPs
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (esIpPeligrosa(address)) {
                    log.warn("[ALERTA SSRF DETECTADO] El host '{}' resuelve a una IP interna no autorizada: {}", host, address.getHostAddress());
                    throw new IllegalArgumentException("Acceso bloqueado: El host '" + host + "' resuelve a una dirección interna o de metadatos (" + address.getHostAddress() + ").");
                }
            }
        } catch (UnknownHostException e) {
            log.warn("[VALIDACIÓN SSRF] No se pudo resolver el host DNS: {}", host);
            throw new IllegalArgumentException("Host no reconocido o no se puede resolver mediante DNS: " + host);
        }

        log.info("[CONTROL DE ACCESO SEGURO] URL validada correctamente y libre de SSRF: {}", urlString);
        return uri;
    }

    /**
     * Evalúa si una dirección IP pertenece a rangos internos, loopback, reservados o de metadatos cloud.
     */
    public boolean esIpPeligrosa(InetAddress address) {
        // Loopback (127.0.0.0/8 o ::1)
        if (address.isLoopbackAddress()) {
            return true;
        }

        // Cualquier dirección local comodín (0.0.0.0)
        if (address.isAnyLocalAddress()) {
            return true;
        }

        // Redes privadas (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if (address.isSiteLocalAddress()) {
            return true;
        }

        // Link-Local (169.254.0.0/16) - Utilizado por Cloud Metadata (ej. 169.254.169.254)
        if (address.isLinkLocalAddress()) {
            return true;
        }

        // Multicast
        if (address.isMulticastAddress()) {
            return true;
        }

        // Verificación específica contra Cloud Metadata IMDSv1
        String ipString = address.getHostAddress();
        if (AWS_METADATA_IP.equals(ipString) || ipString.startsWith("169.254.")) {
            return true;
        }

        return false;
    }

    /**
     * Valida adicionalmente si el host forma parte de la lista blanca de dominios corporativos.
     */
    public boolean estaEnListaBlancaDeDominios(String host) {
        if (host == null) return false;
        return DOMINIOS_PERMITIDOS.stream().anyMatch(d -> d.equalsIgnoreCase(host));
    }
}
