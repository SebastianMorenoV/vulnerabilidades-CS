package com.ciberseguridad.xss.repository;

import com.ciberseguridad.xss.model.Comentario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ComentarioRepository extends JpaRepository<Comentario, Long> {
    List<Comentario> findByTipoOrderByFechaDesc(String tipo);
    List<Comentario> findAllByOrderByFechaDesc();
}
