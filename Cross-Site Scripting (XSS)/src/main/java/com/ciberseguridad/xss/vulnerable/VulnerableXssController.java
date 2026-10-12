package com.ciberseguridad.xss.vulnerable;

import com.ciberseguridad.xss.model.Comentario;
import com.ciberseguridad.xss.repository.ComentarioRepository;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * CONTROLADOR VULNERABLE A XSS
 *
 * Este archivo tiene el codigo que NO protege contra XSS.
 * Sirve para demostrar como un atacante puede inyectar scripts maliciosos.
 *
 * El problema principal: el servidor guarda y devuelve los datos del usuario
 * exactamente como los recibe, sin limpiarlos ni transformarlos.
 */
@RestController
@CrossOrigin(origins = "*")
public class VulnerableXssController {

    private final ComentarioRepository comentarioRepository;

    public VulnerableXssController(ComentarioRepository comentarioRepository) {
        this.comentarioRepository = comentarioRepository;
    }

    // =========================================================================
    // STORED XSS (XSS Persistente / Almacenado)
    //
    // El usuario manda un comentario por POST. El servidor lo guarda en la
    // base de datos TAL CUAL, sin revisar si tiene codigo malicioso.
    //
    // Cuando otro usuario pide ver los comentarios, el servidor se los devuelve
    // con el script adentro. El navegador del otro usuario lo ejecuta
    // pensando que es parte normal de la pagina.
    // =========================================================================

    /**
     * Guardar un comentario SIN limpiar el contenido.
     *
     * AQUI ESTA EL ERROR:
     * - Recibimos lo que el usuario escribio (variable "contenido")
     * - Lo guardamos directo en la base de datos sin quitarle las etiquetas HTML
     * - Si alguien manda <script>...</script>, se guarda asi tal cual
     */
    @PostMapping("/api/vulnerable/comentarios")
    public ResponseEntity<?> crearComentarioVulnerable(@RequestBody Map<String, String> body) {
        String autor = body.getOrDefault("autor", "Anónimo");
        String contenido = body.getOrDefault("contenido", "");

        // ERROR: Se guarda el contenido sin ninguna limpieza.
        // Si el contenido es: <script>alert('hola')</script>
        // se guarda exactamente asi en la base de datos.
        Comentario nuevo = new Comentario(autor, contenido, "VULNERABLE");
        comentarioRepository.save(nuevo);

        return ResponseEntity.ok(Map.of(
                "mensaje", "Comentario almacenado sin sanitizar",
                "comentario", nuevo
        ));
    }

    /**
     * Devolver todos los comentarios vulnerables.
     * Los devuelve como JSON con el contenido original (sin modificar).
     */
    @GetMapping("/api/vulnerable/comentarios")
    public List<Comentario> listarComentariosVulnerables() {
        return comentarioRepository.findByTipoOrderByFechaDesc("VULNERABLE");
    }

    /**
     * Generar una pagina HTML con los comentarios.
     *
     * AQUI ESTA EL SEGUNDO ERROR:
     * - Armamos el HTML concatenando directamente el contenido del comentario
     * - Si el contenido tiene <script>...</script>, queda dentro del HTML
     * - El navegador lo interpreta como codigo y lo ejecuta
     *
     * Lo correcto seria usar escape de caracteres (ver el controlador mitigado).
     */
    @GetMapping(value = "/vulnerable/muro-html", produces = MediaType.TEXT_HTML_VALUE)
    public String renderizarMuroVulnerable() {
        List<Comentario> comentarios = comentarioRepository.findByTipoOrderByFechaDesc("VULNERABLE");

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n")
            .append("<html lang=\"es\">\n<head>\n")
            .append("  <meta charset=\"UTF-8\">\n")
            .append("  <title>Muro Vulnerable</title>\n")
            .append("  <style>\n")
            .append("    body { font-family: sans-serif; padding: 24px; }\n")
            .append("    .comentario { border: 1px solid #ddd; padding: 14px; margin-bottom: 12px; border-radius: 6px; }\n")
            .append("    .autor { font-weight: 600; margin-bottom: 4px; }\n")
            .append("  </style>\n")
            .append("</head>\n<body>\n")
            .append("  <h2>Muro de Comentarios (Vulnerable)</h2>\n");

        for (Comentario c : comentarios) {
            html.append("  <div class=\"comentario\">\n")
                .append("    <div class=\"autor\">").append(c.getAutor()).append("</div>\n")
                // ERROR: pegamos el contenido directo en el HTML sin escapar.
                // Si c.getContenido() es "<script>alert('xss')</script>",
                // eso queda literalmente en el HTML y el navegador lo ejecuta.
                .append("    <div>").append(c.getContenido()).append("</div>\n")
                .append("  </div>\n");
        }

        html.append("</body>\n</html>");
        return html.toString();
    }

    /**
     * Reiniciar los comentarios del muro vulnerable.
     */
    @PostMapping("/api/vulnerable/reset")
    public ResponseEntity<?> resetearComentariosVulnerables() {
        List<Comentario> vulnerables = comentarioRepository.findByTipoOrderByFechaDesc("VULNERABLE");
        comentarioRepository.deleteAll(vulnerables);

        comentarioRepository.save(new Comentario("Carlos Mendoza", "Ya quedaron listos los accesos para el nuevo equipo de desarrollo.", "VULNERABLE"));
        comentarioRepository.save(new Comentario("Mariana Rios", "Recordatorio: la entrega del reporte mensual es este viernes a las 3:00 PM.", "VULNERABLE"));

        return ResponseEntity.ok(Map.of("mensaje", "Muro vulnerable reiniciado."));
    }
}
