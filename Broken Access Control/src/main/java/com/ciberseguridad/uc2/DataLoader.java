package com.ciberseguridad.uc2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * Componente para cargar datos iniciales de prueba en la base de datos H2 en memoria.
 * Inserta los perfiles de demostración:
 * - Usuario A (id=1, username="erick", datoSecreto="Mis tarjetas de crédito")
 * - Usuario B (id=2, username="victima", datoSecreto="Contraseñas corporativas")
 */
@Component
public class DataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataLoader.class);

    private final PerfilRepository perfilRepository;

    public DataLoader(PerfilRepository perfilRepository) {
        this.perfilRepository = perfilRepository;
    }

    @Override
    public void run(String... args) {
        log.info("==================================================================");
        log.info(" CARGANDO DATOS DE PRUEBA EN BASE DE DATOS H2 EN MEMORIA");
        log.info("==================================================================");

        // Limpiar tabla por seguridad
        perfilRepository.deleteAll();

        // Usuario A (Atacante en el escenario de prueba)
        Perfil usuarioA = new Perfil("erick", "Mis tarjetas de crédito");
        perfilRepository.save(usuarioA);

        // Usuario B (Víctima en el escenario de prueba)
        Perfil usuarioB = new Perfil("victima", "Contraseñas corporativas");
        perfilRepository.save(usuarioB);

        log.info("✓ Perfil creado -> ID: {}, Usuario: '{}', Dato Secreto: '{}'",
                usuarioA.getId(), usuarioA.getUsername(), usuarioA.getDatoSecreto());
        log.info("✓ Perfil creado -> ID: {}, Usuario: '{}', Dato Secreto: '{}'",
                usuarioB.getId(), usuarioB.getUsername(), usuarioB.getDatoSecreto());
        log.info("==================================================================");
    }
}
