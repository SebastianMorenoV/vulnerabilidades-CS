package com.ciberseguridad.xss;

import com.ciberseguridad.xss.model.Comentario;
import com.ciberseguridad.xss.repository.ComentarioRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * Carga de datos iniciales en H2 para la demostración de XSS y CSP en el laboratorio.
 */
@Component
public class DataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataLoader.class);

    private final ComentarioRepository comentarioRepository;

    public DataLoader(ComentarioRepository comentarioRepository) {
        this.comentarioRepository = comentarioRepository;
    }

    @Override
    public void run(String... args) {
        log.info("======================================================================");
        log.info("🛡️ INICIALIZANDO LABORATORIO: XSS (Cross-Site Scripting) y CSP");
        log.info("👥 Equipo: Erick Sebastian Moreno, Luciano Barcelo, Benjamin Soto");
        log.info("🌐 Servidor activo en: http://localhost:8081");
        log.info("======================================================================");

        // Comentarios legítimos precargados en el muro de la empresa
        comentarioRepository.save(new Comentario(
                "Carlos Mendoza",
                "Ya quedaron listos los accesos para el nuevo equipo de desarrollo.",
                "VULNERABLE"
        ));

        comentarioRepository.save(new Comentario(
                "Mariana Rios",
                "Recordatorio: la entrega del reporte mensual es este viernes a las 3:00 PM.",
                "VULNERABLE"
        ));

        // Comentarios precargados para la vista mitigada
        comentarioRepository.save(new Comentario(
                "Carlos Mendoza",
                "Ya quedaron listos los accesos para el nuevo equipo de desarrollo.",
                "MITIGADO"
        ));

        comentarioRepository.save(new Comentario(
                "Mariana Rios",
                "Recordatorio: la entrega del reporte mensual es este viernes a las 3:00 PM.",
                "MITIGADO"
        ));

        log.info("✅ Datos de prueba precargados exitosamente en base de datos H2.");
    }
}
