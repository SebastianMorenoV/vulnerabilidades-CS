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
