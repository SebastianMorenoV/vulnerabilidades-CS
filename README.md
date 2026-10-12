# Laboratorio de Ciberseguridad Aplicada

Repositorio de prácticas y demostraciones en vivo de vulnerabilidades web (OWASP Top 10) implementadas en **Java Spring Boot**.

---

## 📂 Módulos del Repositorio

### 1. [Broken Access Control (IDOR)](./Broken%20Access%20Control/)
Proyecto completo enfocado en **OWASP A01:2021 – Broken Access Control** (Insecure Direct Object References):
- **Código Vulnerable**: Endpoint sin validación a nivel de objeto que permite el robo de información confidencial.
- **Código Mitigado**: Control de acceso robusto mediante `@PreAuthorize`, SpEL y validación de propiedad.
- **Pruebas y Demostración**:
  - Colección de Postman lista para importar (`postman_collection.json`).
  - Pruebas automatizadas en Spring Boot (`mvn test`).
  - Comandos `curl` paso a paso para la clase.

👉 Para ver las instrucciones detalladas de ejecución y demostración, consulta el [README de Broken Access Control](./Broken%20Access%20Control/README.md).

---

### 2. [Server-Side Request Forgery (SSRF)](./Server-Side%20Request%20Forgery%20%28SSRF%29/)
Proyecto completo enfocado en **OWASP A10:2021 – Server-Side Request Forgery (Impacto y Mitigación)**:
- **Código Vulnerable**: Servicio de vista previa / descarga sin sanitización que permite consultar la intranet, extraer metadatos de Cloud (AWS EC2 / IMDS) y leer archivos locales mediante `file://`.
- **Código Mitigado**: Defensa en profundidad (*Defense in Depth*) con lista blanca de esquemas (HTTP/HTTPS), resolución DNS previa, bloqueo de direcciones Loopback, redes privadas RFC 1918 y Link-Local (Cloud Metadata), además de desactivación de redirecciones automáticas.
- **Pruebas y Demostración**:
  - Colección de Postman lista para importar (`postman_collection.json`).
  - Pruebas automatizadas en Spring Boot con JUnit 5 (`mvn test`).
  - Guía completa de explotación y remediación con comandos `curl` para la presentación en el laboratorio.

👉 Para ver las instrucciones detalladas de ejecución y demostración, consulta el [README de Server-Side Request Forgery](./Server-Side%20Request%20Forgery%20%28SSRF%29/README.md).
