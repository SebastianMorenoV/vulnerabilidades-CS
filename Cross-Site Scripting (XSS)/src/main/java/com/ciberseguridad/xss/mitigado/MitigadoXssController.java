package com.ciberseguridad.xss.mitigado;

import com.ciberseguridad.xss.model.Comentario;
import com.ciberseguridad.xss.repository.ComentarioRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import java.util.List;
import java.util.Map;

/**
 * CONTROLADOR MITIGADO - PROTEGIDO CONTRA XSS
 *
 * Este archivo tiene el codigo CORREGIDO que previene Cross-Site Scripting.
 *
 * Usa 3 defensas:
 * 1. Escape de caracteres HTML: transforma < en &lt; y > en &gt;
 *    para que el navegador los muestre como texto y no los ejecute.
 * 2. Content Security Policy (CSP): una cabecera HTTP que le dice al navegador
 *    "no ejecutes ningun script que no sea un archivo .js de este servidor".
 * 3. Cookies HttpOnly: hace que JavaScript no pueda leer las cookies de sesion.
 */
@RestController
@CrossOrigin(origins = "*")
public class MitigadoXssController {

    private final ComentarioRepository comentarioRepository;

    public MitigadoXssController(ComentarioRepository comentarioRepository) {
        this.comentarioRepository = comentarioRepository;
    }

    // =========================================================================
    // DEFENSA 1: ESCAPE DE CARACTERES HTML
    //
    // Antes de guardar el comentario, transformamos los caracteres peligrosos:
    //   <  se convierte en  &lt;
    //   >  se convierte en  &gt;
    //   "  se convierte en  &quot;
    //   '  se convierte en  &#39;
    //
    // Asi, si alguien manda <script>alert('xss')</script>,
    // se guarda como &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;
    // y el navegador lo muestra como texto plano, sin ejecutarlo.
    //
    // En PHP esto se hace con: htmlspecialchars($input, ENT_QUOTES, 'UTF-8')
    // En Java se hace con: HtmlUtils.htmlEscape(input)
    // =========================================================================

    /**
     * Guardar un comentario LIMPIANDO el contenido primero.
     *
     * LA CORRECCION:
     * - Recibimos lo que el usuario escribio
     * - Antes de guardarlo, le aplicamos HtmlUtils.htmlEscape()
     * - Esto convierte los caracteres peligrosos en texto seguro
     */
    @PostMapping("/api/mitigado/comentarios")
    public ResponseEntity<?> crearComentarioSeguro(@RequestBody Map<String, String> body) {
        String autorOriginal = body.getOrDefault("autor", "Anónimo");
        String contenidoOriginal = body.getOrDefault("contenido", "");

        // CORRECCION: escapamos el contenido antes de guardarlo.
        // Si el contenido original es: <script>alert('xss')</script>
        // despues de escapar queda: &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;
        // Eso ya no se puede ejecutar, solo se muestra como texto.
        String autorEscapado = HtmlUtils.htmlEscape(autorOriginal);
        String contenidoEscapado = HtmlUtils.htmlEscape(contenidoOriginal);

        Comentario nuevo = new Comentario(autorEscapado, contenidoEscapado, "MITIGADO");
        comentarioRepository.save(nuevo);

        return ResponseEntity.ok(Map.of(
                "mensaje", "Comentario limpiado y guardado de forma segura.",
                "original", contenidoOriginal,
                "sanitizado", contenidoEscapado,
                "defensaAplicada", "Escape de caracteres HTML (HtmlUtils.htmlEscape / htmlspecialchars)"
        ));
    }

    /**
     * Devolver los comentarios mitigados (ya tienen el contenido escapado).
     */
    @GetMapping("/api/mitigado/comentarios")
    public List<Comentario> listarComentariosMitigados() {
        return comentarioRepository.findByTipoOrderByFechaDesc("MITIGADO");
    }

    /**
     * Generar una pagina HTML con los comentarios ya escapados.
     * Como el contenido ya fue limpiado al guardarse, el navegador
     * lo dibuja como texto y no lo ejecuta.
     */
    @GetMapping(value = "/mitigado/muro-escapado-html", produces = MediaType.TEXT_HTML_VALUE)
    public String renderizarMuroEscapado() {
        List<Comentario> comentarios = comentarioRepository.findByTipoOrderByFechaDesc("MITIGADO");

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n")
            .append("<html lang=\"es\">\n<head>\n")
            .append("  <meta charset=\"UTF-8\">\n")
            .append("  <title>Muro Protegido (Escape HTML)</title>\n")
            .append("  <style>\n")
            .append("    body { font-family: sans-serif; padding: 24px; }\n")
            .append("    .comentario { border: 1px solid #ddd; padding: 14px; margin-bottom: 12px; border-radius: 6px; }\n")
            .append("    .autor { font-weight: 600; margin-bottom: 4px; color: #00815a; }\n")
            .append("    .contenido { font-family: monospace; background: #f0fdf4; padding: 8px; border-radius: 4px; }\n")
            .append("  </style>\n")
            .append("</head>\n<body>\n")
            .append("  <h2>Muro de Comentarios (Protegido con Escape HTML)</h2>\n");

        for (Comentario c : comentarios) {
            html.append("  <div class=\"comentario\">\n")
                .append("    <div class=\"autor\">").append(c.getAutor()).append("</div>\n")
                // SEGURO: el contenido ya fue escapado cuando se guardo.
                // El navegador muestra el texto tal cual, sin ejecutar nada.
                .append("    <div class=\"contenido\">").append(c.getContenido()).append("</div>\n")
                .append("  </div>\n");
        }

        html.append("</body>\n</html>");
        return html.toString();
    }

    /**
     * Endpoint protegido contra Reflected XSS.
     * Escapa el parametro 'q' usando HtmlUtils.htmlEscape() antes de reflejarlo en el HTML.
     */
    @GetMapping(value = "/api/mitigado/buscar", produces = MediaType.TEXT_HTML_VALUE)
    public String buscarMitigado(@RequestParam(name = "q", defaultValue = "") String q) {
        String qEscapada = HtmlUtils.htmlEscape(q);
        return "<!DOCTYPE html>\n" +
                "<html lang=\"es\">\n<head>\n" +
                "  <meta charset=\"UTF-8\">\n" +
                "  <title>Resultados de Búsqueda (Mitigado)</title>\n" +
                "</head>\n<body>\n" +
                "  <h2>Resultados de búsqueda (Mitigado)</h2>\n" +
                "  <p>Resultados para: " + qEscapada + "</p>\n" +
                "</body>\n</html>";
    }

    // =========================================================================
    // DEFENSA 2: CONTENT SECURITY POLICY (CSP)
    //
    // Es una cabecera HTTP que el servidor manda al navegador.
    // Le dice: "solo puedes ejecutar archivos .js que vengan de mi mismo servidor".
    //
    // La cabecera es:
    //   Content-Security-Policy: default-src 'self'; script-src 'self';
    //
    // Con esto, aunque haya un <script>alert('xss')</script> en el HTML,
    // el navegador lo BLOQUEA porque no es un archivo .js del servidor,
    // es un script escrito directamente en el HTML (inline).
    // =========================================================================

    /**
     * Pagina con la cabecera CSP activa.
     * El navegador bloquea cualquier script inline que encuentre.
     */
    @GetMapping(value = "/mitigado/muro-csp-html", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> renderizarMuroConCsp() {
        // Esta es la cabecera que protege contra scripts inline:
        String cspHeader = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';";

        String html = "<!DOCTYPE html>\n" +
                "<html lang=\"es\">\n<head>\n" +
                "  <meta charset=\"UTF-8\">\n" +
                "  <title>Pagina Protegida con CSP</title>\n" +
                "  <style>\n" +
                "    body { font-family: sans-serif; padding: 24px; }\n" +
                "    .card { border: 1px solid #ddd; padding: 16px; border-radius: 8px; margin-bottom: 16px; }\n" +
                "    code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; }\n" +
                "    .error-demo { font-family: monospace; background: #fef0f0; color: #d63031; padding: 10px; border-radius: 4px; }\n" +
                "  </style>\n" +
                "</head>\n<body>\n" +
                "  <h2>Pagina con Content Security Policy activo</h2>\n" +
                "  <div class=\"card\">\n" +
                "    <h3>Cabecera enviada por el servidor:</h3>\n" +
                "    <code>Content-Security-Policy: " + cspHeader + "</code>\n" +
                "    <p style=\"margin-top:12px;\">Abre la consola del navegador (F12) para ver como se bloquea el script inline de abajo.</p>\n" +
                "    <div class=\"error-demo\">\n" +
                "      Esperado en consola: Refused to execute inline script because it violates the following Content Security Policy directive: \"script-src 'self'\"\n" +
                "    </div>\n" +
                "  </div>\n" +
                "  <!-- Este script existe en el HTML pero el navegador NO lo ejecuta gracias a CSP -->\n" +
                "  <script>alert('Este script fue bloqueado por CSP');</script>\n" +
                "</body>\n</html>";

        return ResponseEntity.ok()
                .header("Content-Security-Policy", cspHeader)
                .body(html);
    }

    /**
     * Info sobre la cabecera CSP.
     */
    @GetMapping("/api/mitigado/csp-info")
    public ResponseEntity<?> obtenerInformacionCsp() {
        return ResponseEntity.ok(Map.of(
                "cabeceraRecomendada", "Content-Security-Policy: default-src 'self'; script-src 'self';",
                "descripcion", "Le dice al navegador que solo ejecute scripts que sean archivos .js del mismo servidor. Bloquea scripts inline.",
                "beneficio", "Aunque haya un script inyectado en el HTML, el navegador no lo ejecuta."
        ));
    }

    // =========================================================================
    // DEFENSA 3: COOKIES CON HttpOnly
    //
    // El ataque XSS tipico roba la cookie de sesion con: document.cookie
    // Si la cookie tiene la bandera HttpOnly, JavaScript NO puede leerla.
    //
    // Ejemplo:
    //   Cookie normal:     document.cookie puede leerla    -> ROBABLE
    //   Cookie HttpOnly:   document.cookie NO la ve        -> PROTEGIDA
    // =========================================================================

    /**
     * Genera 2 cookies para comparar:
     * - Una SIN HttpOnly (el atacante puede robarla)
     * - Una CON HttpOnly (el atacante NO puede leerla desde JavaScript)
     */
    @GetMapping("/api/mitigado/generar-cookies")
    public ResponseEntity<?> generarCookiesDemostracion(HttpServletResponse response) {
        // Cookie SIN proteccion: JavaScript puede leerla con document.cookie
        ResponseCookie cookieInsegura = ResponseCookie.from("cookie_vulnerable_js", "TOKEN_EXPUESTO_12345")
                .path("/")
                .httpOnly(false)   // <-- SIN HttpOnly = JavaScript SI puede leerla
                .maxAge(3600)
                .build();

        // Cookie CON proteccion: JavaScript NO puede leerla
        ResponseCookie cookieSegura = ResponseCookie.from("cookie_segura_httponly", "TOKEN_SECRETO_ABCD")
                .path("/")
                .httpOnly(true)    // <-- CON HttpOnly = JavaScript NO puede leerla
                .sameSite("Strict")
                .maxAge(3600)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookieInsegura.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, cookieSegura.toString());

        return ResponseEntity.ok(Map.of(
                "mensaje", "Cookies generadas",
                "cookieInsegura", "cookie_vulnerable_js (HttpOnly=false, robable por XSS)",
                "cookieSegura", "cookie_segura_httponly (HttpOnly=true, protegida)"
        ));
    }

    /**
     * Reiniciar los comentarios mitigados.
     */
    @PostMapping("/api/mitigado/reset")
    public ResponseEntity<?> resetearComentariosMitigados() {
        List<Comentario> mitigados = comentarioRepository.findByTipoOrderByFechaDesc("MITIGADO");
        comentarioRepository.deleteAll(mitigados);

        comentarioRepository.save(new Comentario("Carlos Mendoza", "Ya quedaron listos los accesos para el nuevo equipo de desarrollo.", "MITIGADO"));
        comentarioRepository.save(new Comentario("Mariana Rios", "Recordatorio: la entrega del reporte mensual es este viernes a las 3:00 PM.", "MITIGADO"));

        return ResponseEntity.ok(Map.of("mensaje", "Muro mitigado reiniciado."));
    }
}
