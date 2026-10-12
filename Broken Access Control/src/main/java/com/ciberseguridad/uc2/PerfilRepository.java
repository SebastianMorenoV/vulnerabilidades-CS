package com.ciberseguridad.uc2;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repositorio Spring Data JPA para la entidad Perfil.
 */
@Repository
public interface PerfilRepository extends JpaRepository<Perfil, Long> {

    /**
     * Busca un perfil por el nombre de usuario (username).
     *
     * @param username Nombre del usuario autenticado o solicitado
     * @return Perfil correspondiente si existe
     */
    Optional<Perfil> findByUsername(String username);
}
