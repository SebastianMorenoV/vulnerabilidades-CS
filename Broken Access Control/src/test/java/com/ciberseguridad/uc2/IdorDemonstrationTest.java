package com.ciberseguridad.uc2;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class IdorDemonstrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("VULNERABLE: Erick puede acceder al perfil de la víctima (IDOR exitoso)")
    @WithMockUser(username = "erick", roles = {"USER"})
    void testVulnerableEndpointPermiteIdor() throws Exception {
        // Erick solicita el perfil de 'victima' (id=2)
        mockMvc.perform(get("/api/vulnerable/perfil/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(2))
                .andExpect(jsonPath("$.username").value("victima"))
                .andExpect(jsonPath("$.datoSecreto").value("Contraseñas corporativas"));
    }

    @Test
    @DisplayName("MITIGADO: Erick puede acceder legítimamente a su propio perfil (ID 1)")
    @WithMockUser(username = "erick", roles = {"USER"})
    void testMitigadoPermiteAccesoPropio() throws Exception {
        mockMvc.perform(get("/api/mitigado/perfil/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.username").value("erick"))
                .andExpect(jsonPath("$.datoSecreto").value("Mis tarjetas de crédito"));
    }

    @Test
    @DisplayName("MITIGADO: Erick intenta acceder al perfil de la víctima (ID 2) -> 403 Forbidden")
    @WithMockUser(username = "erick", roles = {"USER"})
    void testMitigadoBloqueaIdor() throws Exception {
        mockMvc.perform(get("/api/mitigado/perfil/2"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    @Test
    @DisplayName("MITIGADO: Administrador puede acceder al perfil de cualquier usuario")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testMitigadoAdminPuedeAcceder() throws Exception {
        mockMvc.perform(get("/api/mitigado/perfil/2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(2))
                .andExpect(jsonPath("$.username").value("victima"));
    }

    @Test
    @DisplayName("MITIGADO (Por Username): Erick accede a su usuario -> 200 OK")
    @WithMockUser(username = "erick", roles = {"USER"})
    void testMitigadoUsernamePropio() throws Exception {
        mockMvc.perform(get("/api/mitigado/perfil/usuario/erick"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("erick"));
    }

    @Test
    @DisplayName("MITIGADO (Por Username): Erick intenta acceder al usuario de victima -> 403 Forbidden")
    @WithMockUser(username = "erick", roles = {"USER"})
    void testMitigadoUsernameVictimaBloqueado() throws Exception {
        mockMvc.perform(get("/api/mitigado/perfil/usuario/victima"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));
    }
}
