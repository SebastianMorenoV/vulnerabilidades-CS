package com.ciberseguridad.xss.repository;

import com.ciberseguridad.xss.model.RoboRegistro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoboRegistroRepository extends JpaRepository<RoboRegistro, Long> {
    List<RoboRegistro> findAllByOrderByFechaDesc();
}
