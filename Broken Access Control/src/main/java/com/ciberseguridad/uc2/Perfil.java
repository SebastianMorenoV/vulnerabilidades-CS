package com.ciberseguridad.uc2;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Entidad Perfil que almacena los datos de un usuario en el sistema,
 * incluyendo información sensible / confidencial (datoSecreto).
 */
@Entity
@Table(name = "perfiles")
public class Perfil {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String datoSecreto;

    // Constructor por defecto requerido por JPA
    public Perfil() {
    }

    // Constructor de conveniencia
    public Perfil(Long id, String username, String datoSecreto) {
        this.id = id;
        this.username = username;
        this.datoSecreto = datoSecreto;
    }

    public Perfil(String username, String datoSecreto) {
        this.username = username;
        this.datoSecreto = datoSecreto;
    }

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDatoSecreto() {
        return datoSecreto;
    }

    public void setDatoSecreto(String datoSecreto) {
        this.datoSecreto = datoSecreto;
    }

    @Override
    public String toString() {
        return "Perfil{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", datoSecreto='" + datoSecreto + '\'' +
                '}';
    }
}
