package com.ciberseguridad.xss.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import java.time.LocalDateTime;

/**
 * Entidad que registra los datos exfiltrados por el script malicioso
 * hacia el servidor del atacante (C2 / Command & Control).
 * Simula https://attacker.com/steal?cookie= de la Diapositiva 6.
 */
@Entity
public class RoboRegistro {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Lob
    private String cookie;

    private String ip;

    private String userAgent;

    private LocalDateTime fecha;

    public RoboRegistro() {
        this.fecha = LocalDateTime.now();
    }

    public RoboRegistro(String cookie, String ip, String userAgent) {
        this.cookie = cookie;
        this.ip = ip;
        this.userAgent = userAgent;
        this.fecha = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public LocalDateTime getFecha() {
        return fecha;
    }

    public void setFecha(LocalDateTime fecha) {
        this.fecha = fecha;
    }
}
