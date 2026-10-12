package com.ciberseguridad.xss.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import java.time.LocalDateTime;

/**
 * Entidad que representa un comentario o publicación en el muro/foro.
 * Se utiliza para ilustrar Stored XSS (Persistente) y su mitigación.
 */
@Entity
public class Comentario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String autor;

    @Lob
    private String contenido;

    private String tipo; // "VULNERABLE" o "MITIGADO"

    private LocalDateTime fecha;

    public Comentario() {
        this.fecha = LocalDateTime.now();
    }

    public Comentario(String autor, String contenido, String tipo) {
        this.autor = autor;
        this.contenido = contenido;
        this.tipo = tipo;
        this.fecha = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAutor() {
        return autor;
    }

    public void setAutor(String autor) {
        this.autor = autor;
    }

    public String getContenido() {
        return contenido;
    }

    public void setContenido(String contenido) {
        this.contenido = contenido;
    }

    public String getTipo() {
        return tipo;
    }

    public void setTipo(String tipo) {
        this.tipo = tipo;
    }

    public LocalDateTime getFecha() {
        return fecha;
    }

    public void setFecha(LocalDateTime fecha) {
        this.fecha = fecha;
    }
}
