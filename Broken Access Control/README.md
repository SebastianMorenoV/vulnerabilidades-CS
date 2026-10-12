# Demostración en Vivo: Broken Access Control (IDOR) - OWASP Top 1:2021

Proyecto didáctico en **Java Spring Boot 3** diseñado para la asignatura de **Ciberseguridad Aplicada**. Demuestra de manera práctica e interactiva la vulnerabilidad de **Control de Acceso Roto (Broken Access Control)** mediante **Referencias Directas Inseguras a Objetos (IDOR - Insecure Direct Object References)**, y su correspondiente mitigación a nivel de objeto utilizando **Spring Security**.

---

## 🎯 Objetivos de Aprendizaje

1. **Comprender la diferencia entre Autenticación y Autorización**:
   - *Autenticación* responde a: *¿Quién eres?* (HTTP Basic con `erick:password`).
   - *Autorización* responde a: *¿A qué recursos específicos tienes derecho de acceso?*
2. **Identificar la vulnerabilidad IDOR (A01:2021 - Broken Access Control)**:
   - Manipulación de identificadores directos (`/perfil/1` vs `/perfil/2`) en la URL para acceder a información confidencial de otros usuarios.
3. **Implementar y evaluar la mitigación**:
   - Uso de `@PreAuthorize` y validación de propiedad (Object-Level Authorization) para retornar `403 Forbidden` ante accesos no autorizados.

---

## 🏗️ Estructura del Proyecto

El código fuente está estrictamente dividido en dos paquetes conforme a los requerimientos:

```text
src/main/java/com/ciberseguridad/uc2/
│
├── Application.java               # Punto de entrada de la aplicación Spring Boot
├── Perfil.java                    # Entidad JPA (id, username, datoSecreto)
├── PerfilRepository.java          # Repositorio Spring Data JPA
├── DataLoader.java                # Carga de datos de prueba en H2 al arrancar
├── SecurityConfig.java            # Configuración Spring Security (HTTP Basic en memoria)
├── GlobalExceptionHandler.java    # Formateo amigable de errores HTTP 403 / 404
│
├── vulnerable/                    # 🔴 CÓDIGO VULNERABLE A IDOR
│   └── UsuarioControllerVulnerable.java   # Endpoint GET /api/vulnerable/perfil/{id}
│
└── mitigado/                      # 🟢 CÓDIGO MITIGADO Y SEGURO
    ├── AutorizacionService.java           # Servicio de validación de pertenencia
    └── UsuarioControllerSeguro.java       # Endpoint GET /api/mitigado/perfil/{id}
```

---

## 👥 Usuarios de Prueba Precargados

Al iniciar el proyecto, `DataLoader.java` y `SecurityConfig.java` inicializan los siguientes registros:

| Usuario | Contraseña | Rol | ID en BD | Dato Secreto Guardado | Rol en la Demostración |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `erick` | `password` | `USER` | `1` | `"Mis tarjetas de crédito"` | **Atacante (Usuario Autenticado)** |
| `victima` | `password` | `USER` | `2` | `"Contraseñas corporativas"` | **Víctima** |
| `admin` | `password` | `ADMIN` | - | - | **Administrador del Sistema** |

---

## 🚀 Requisitos Previos e Instalación

- **JDK 17 o superior** (compatible con JDK 21 y JDK 22).
- **Apache Maven 3.8+** (o el wrapper si está configurado).
- Terminal de comandos: **PowerShell**, **Bash** o **CMD** con soporte para `curl`.

### Paso 1: Clonar / Abrir el proyecto
Navega a la carpeta raíz del proyecto:
```bash
cd vulnerabilidades-CS
```

### Paso 2: Compilar el proyecto y ejecutar pruebas unitarias
```bash
mvn clean test
```

### Paso 3: Iniciar la aplicación Spring Boot
```bash
mvn spring-boot:run
```
La aplicación iniciará en `http://localhost:8080`.
En la consola verás los logs de `DataLoader` confirmando la carga de los usuarios `erick` (ID 1) y `victima` (ID 2).

---

## 🧪 Guía de Demostración en Vivo (Paso a Paso con cURL)

Abre una terminal adicional mientras el servidor está en ejecución.

### 🔴 PARTE 1: Demostración de la Vulnerabilidad (IDOR)

#### 1.1. Acceso Legítimo de Erick a su propio perfil
Erick se autentica con sus credenciales válidas y solicita su propio perfil (ID 1):
```bash
curl -i -u erick:password http://localhost:8080/api/vulnerable/perfil/1
```
**Resultado esperado:** HTTP `200 OK`.
```json
{
  "id": 1,
  "username": "erick",
  "datoSecreto": "Mis tarjetas de crédito"
}
```

#### 1.2. El Ataque IDOR: Erick roba los datos de la Víctima
Erick mantiene sus credenciales legítimas (`-u erick:password`), pero cambia maliciosamente el parámetro numérico en la URL a `2`:
```bash
curl -i -u erick:password http://localhost:8080/api/vulnerable/perfil/2
```
**Resultado vulnerable:** HTTP `200 OK` ⚠️
```json
{
  "id": 2,
  "username": "victima",
  "datoSecreto": "Contraseñas corporativas"
}
```
> **Explicación para la clase:** Aunque Erick no conoce la contraseña de "victima", el sistema no validó la relación de propiedad entre el usuario de la sesión (`erick`) y el ID solicitado (`2`). Esto es un fallo clásico de **Broken Access Control**.

---

### 🟢 PARTE 2: Demostración de la Mitigación (Control Seguro)

Ahora probamos los mismos escenarios contra el endpoint seguro `/api/mitigado/perfil/{id}`.

#### 2.1. Erick consulta legítimamente su propio perfil seguro
```bash
curl -i -u erick:password http://localhost:8080/api/mitigado/perfil/1
```
**Resultado:** HTTP `200 OK` ✅
```json
{
  "id": 1,
  "username": "erick",
  "datoSecreto": "Mis tarjetas de crédito"
}
```

#### 2.2. Erick intenta el ataque IDOR contra el perfil de la Víctima
Erick intenta acceder nuevamente al ID 2 en el endpoint mitigado:
```bash
curl -i -u erick:password http://localhost:8080/api/mitigado/perfil/2
```
**Resultado mitigado:** HTTP `403 Forbidden` 🛡️
```json
{
  "status": 403,
  "error": "Forbidden",
  "alertaSeguridad": "VULNERABILIDAD IDOR BLOQUEADA",
  "mensaje": "Acceso denegado (HTTP 403): El usuario autenticado no tiene autorización para acceder al recurso solicitado.",
  "path": "/api/mitigado/perfil/2"
}
```
> **Explicación para la clase:** `@PreAuthorize` ejecutó `autorizacionService.puedeAccederAPerfil(2, authentication)`. Al detectar que el propietario del perfil ID 2 es "victima" y quien consulta es "erick", el acceso fue bloqueado inmediatamente.

---

### 🔵 PARTE 3: Pruebas Adicionales (Administrador y Consulta por Username)

#### 3.1. Acceso de Administrador (Superusuario)
Un usuario con rol `ADMIN` sí puede auditar cualquier perfil:
```bash
curl -i -u admin:password http://localhost:8080/api/mitigado/perfil/2
```
**Resultado:** HTTP `200 OK`.

#### 3.2. Endpoint con validación declarativa SpEL por Username
El controlador mitigado también incluye el endpoint con la expresión solicitada:
`@PreAuthorize("hasRole('ADMIN') or authentication.name == #usernameSolicitado")`

- Acceso permitido (propio):
```bash
curl -i -u erick:password http://localhost:8080/api/mitigado/perfil/usuario/erick
```
- Acceso denegado (intento de suplantación a la víctima):
```bash
curl -i -u erick:password http://localhost:8080/api/mitigado/perfil/usuario/victima
```
**Resultado:** HTTP `403 Forbidden`.

---

## 🔍 Inspección de la Base de Datos (Consola H2)

Para visualizar los registros en vivo durante la clase:
- **URL**: `http://localhost:8080/h2-console`
- **JDBC URL**: `jdbc:h2:mem:ciberseguridaddb`
- **Usuario**: `sa`
- **Contraseña**: *(dejar en blanco)*

---

## 📮 Demostración desde Postman (Colección Lista para Usar)

¡Sí! Puedes realizar toda la demostración cómodamente desde **Postman** de dos formas:

### Opción A: Importar la colección preconfigurada (Recomendado ⚡)
El proyecto incluye el archivo `postman_collection.json` en la raíz.
1. Abre Postman.
2. Haz clic en **Import** (esquina superior izquierda).
3. Selecciona o arrastra el archivo `postman_collection.json`.
4. Tendrás organizadas en carpetas todas las peticiones con la autenticación HTTP Basic (`erick:password` y `admin:password`) listas para enviar con un solo clic.

### Opción B: Configuración manual en Postman
Si deseas configurar cada petición desde cero:
1. **Método**: Selecciona `GET`.
2. **URL**: Escribe `http://localhost:8080/api/vulnerable/perfil/1` (o la ruta a probar).
3. **Pestaña Authorization**:
   - **Type**: `Basic Auth`.
   - **Username**: `erick`
   - **Password**: `password`
4. Presiona **Send** y observa el Status Code (`200 OK` vs `403 Forbidden`) y el cuerpo JSON devuelto.

---

## 📚 Conclusiones Teóricas para la Exposición

1. **No confiar en entradas provistas por el cliente**: Los identificadores numéricos predecibles (1, 2, 3...) son vectores directos de ataque por fuerza bruta o escaneo.
2. **Defensa en Profundidad**: Emplear identificadores no secuenciales (UUID v4) y, crucialmente, verificar **siempre** la autorización a nivel de fila/objeto en la capa de servicios o controlador.
3. **OWASP Top 1:2021**: Broken Access Control ascendió al puesto #1 debido a que el 94% de las aplicaciones analizadas contenían alguna forma de control de acceso deficiente.

