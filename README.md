# ExxonMobil — Prevención de Inyecciones · Migración On-Premise → AWS

Proyecto de seguridad sobre la CMDB de servidores de ExxonMobil durante su migración a AWS.
Implementa defensa contra inyecciones SQL y de comandos (Punto 3) y un panel de seguimiento
de migración con control de acceso por roles (Punto 5).  
**Solo biblioteca estándar de Python. Sin dependencias externas. 100 % offline.**

---

## Estructura del proyecto

```
prevencion_inyecciones/
├── cmdb_exxonmobil.db          ← Base de datos CMDB compartida (Punto 3 y Punto 5)
│
├── Punto3/
│   ├── crear_bd_cmdb.py        ← Inicializa/resetea la CMDB
│   ├── buscador_cmdb.py        ← Demo de inyección SQL (vulnerable vs. seguro)
│   ├── seguridad_cmdb.log      ← Log de auditoría del Punto 3
│   └── README.md
│
└── Punto5/
    ├── panel_migracion.py      ← Panel de seguimiento con control de acceso (CCB)
    ├── usuarios_panel.db       ← Usuarios del panel (contraseñas hasheadas)
    ├── panel_auditoria.log     ← Log de auditoría del panel
    └── credenciales_iniciales.txt  ← Generado solo en la primera ejecución
```

---

## Requisitos

- Python 3.10 o superior (usa `str | None` y `match`)
- No requiere `pip install` de nada

---

## Puesta en marcha

### 1 · Inicializar la base de datos CMDB

Ejecutar **una sola vez** (o para resetear la DB a su estado original):

```bash
cd Punto3
python crear_bd_cmdb.py
```

Crea `cmdb_exxonmobil.db` con 5 servidores de prueba y la tabla `credenciales_criticas`.

### 2 · Punto 3 — Buscador CMDB (demo de inyección SQL)

```bash
cd Punto3
python buscador_cmdb.py
```

### 3 · Punto 5 — Panel de seguimiento de migración

```bash
cd Punto5
python panel_migracion.py
```

En la **primera ejecución** crea `usuarios_panel.db` y muestra las credenciales generadas.
Las credenciales actuales para la demo son:

| Usuario | Contraseña | Rol |
|---|---|---|
| `mbellini` | `1234` | analista |
| `rcrespo` | `1234` | analista |
| `lsanchez` | `1234` | CCB (puede aprobar migraciones) |
| `gfernandez` | `1234` | CCB (puede aprobar migraciones) |

> Si necesitás resetear las contraseñas o recrear los usuarios, eliminá el archivo
> `Punto5/usuarios_panel.db` y volvé a correr el panel.

---

## Punto 3 · Casos de prueba para la demo en vivo

> **Nota de ejecución:** Se recomienda ejecutar primero cada caso en la **Opción 1 (Modo Vulnerable)** y luego repetirlo en la **Opción 2 (Modo Seguro)** para contrastar el comportamiento.

### CP-01: Consulta legítima de un servidor (Flujo normal)
* **Objetivo:** Verificar el funcionamiento esperado ante una entrada válida y comprobar el recorte de información sensible mediante la vista de mínimo privilegio.
* **Precondiciones:** Base de datos `cmdb_exxonmobil.db` recién inicializada.
* **Entrada (`ID de Servidor`):**
  ```text
  1
  ```
* **Resultado en Modo Vulnerable (Opción 1):** Devuelve la tupla completa de la tabla `servidores`, exponiendo la dirección IP interna (`10.240.12.15`).
* **Resultado Esperado en Modo Seguro (Opción 2):** Devuelve únicamente los campos operativos habilitados por `vista_servidores_soporte` (`ID: 1 | CI: CI-AWS-VM-WEB-01 | Host: xom-ohio-web01.aws.internal | ...`), ocultando la IP privada.
* **Defensas validadas:** Defensa 1 (Parametrización), Defensa 2 (Lista blanca), Defensa 3 (Mínimo privilegio).

---

### CP-02: Consulta de un ID inexistente
* **Objetivo:** Confirmar que un ID numérico válido pero inexistente se maneja de forma limpia.
* **Precondiciones:** Base de datos inicializada (IDs existentes: `1` a `5`).
* **Entrada (`ID de Servidor`):**
  ```text
  99
  ```
* **Resultado en Modo Vulnerable (Opción 1):** Informa que no se encontraron servidores.
* **Resultado Esperado en Modo Seguro (Opción 2):** Supera la validación de formato, ejecuta la consulta parametrizada de forma segura e informa: `No se encontraron servidores para el ID ingresado.`
* **Defensas validadas:** Defensa 1 y Defensa 2.

---

### CP-03: Ataque de Bypass Lógico — Volcado total del inventario
* **Objetivo:** Simular un atacante interno que intenta evadir el filtro por ID inyectando una condición booleana siempre verdadera para listar todos los servidores de ExxonMobil.
* **Precondiciones:** Base de datos inicializada.
* **Entrada / Payload (`ID de Servidor`):**
  ```text
  1 OR 1=1
  ```
* **Resultado en Modo Vulnerable (Opción 1):** Ejecuta `SELECT * FROM servidores WHERE id = 1 OR 1=1` y expone los **5 servidores completos** de la CMDB (On-Premise y AWS) con sus IPs internas.
* **Resultado Esperado en Modo Seguro (Opción 2):** Bloqueado inmediatamente antes de conectar a la base de datos. Muestra `[BLOQUEADO - Defensa 1: Validación de Entrada]` y registra el intento en `seguridad_cmdb.log`.
* **Defensas validadas:** Defensa 2 (Validación de entradas por lista blanca).

---

### CP-04: Ataque `UNION SELECT` — Extracción de credenciales críticas
* **Objetivo:** Simular la lectura no autorizada de una tabla ajena (`credenciales_criticas`) que almacena tokens de AWS y ServiceNow Discovery.
* **Precondiciones:** Base de datos inicializada.
* **Entrada / Payload (`ID de Servidor`):**
  ```text
  1 UNION SELECT 1, sistema, usuario_servicio, token_api, 'LEAK', '0.0.0.0', 'N/A' FROM credenciales_criticas
  ```
* **Resultado en Modo Vulnerable (Opción 1):** Combina los resultados y filtra en pantalla los usuarios de servicio (`svc_terraform_deploy`, `svc_cmdb_sync`) junto con sus tokens de API en texto claro.
* **Resultado Esperado en Modo Seguro (Opción 2):** Rechazado por la validación de entrada (contiene espacios, letras y comillas). Incluso si se omitiera la validación, la consulta parametrizada trataría el payload como un literal y la vista restringida no otorga acceso a `credenciales_criticas`.
* **Defensas validadas:** Defensa 2 (Lista blanca), Defensa 1 (Parametrización) y Defensa 3 (Mínimo privilegio).

---

### CP-05: Ataque de Destrucción de Datos — `DROP TABLE` (Stacked Queries)
* **Objetivo:** Simular un ataque destructivo que intenta eliminar la tabla principal de servidores de la CMDB mediante sentencias encadenadas (`;`).
* **Precondiciones:** Base de datos inicializada. *(Nota: ejecutar primero en Modo Seguro y dejar el Modo Vulnerable para el final, ya que destruye la tabla).*
* **Entrada / Payload (`ID de Servidor`):**
  ```text
  1; DROP TABLE servidores;--
  ```
* **Resultado Esperado en Modo Seguro (Opción 2):** Bloqueado por la lista blanca al detectar el punto y coma (`;`) y caracteres no numéricos. Adicionalmente, la conexión `?mode=ro` impide cualquier operación DDL/DML (`DROP`, `DELETE`, `UPDATE`) a nivel motor SQLite.
* **Resultado en Modo Vulnerable (Opción 1):** Ejecuta el script completo (`ALERTA CRÍTICA`), eliminando permanentemente la tabla `servidores` de `cmdb_exxonmobil.db`.
* **Defensas validadas:** Defensa 2 (Lista blanca) y Defensa 3 (Mínimo privilegio en modo solo lectura).

---

### CP-06: Manejo de Errores Genéricos ante fallo de infraestructura
* **Objetivo:** Comprobar que ante una excepción interna del motor de base de datos, el sistema no filtra información estructural al operador.
* **Precondiciones:** Haber ejecutado previamente el **CP-05 en Modo Vulnerable** para que la tabla `servidores` no exista en `cmdb_exxonmobil.db`.
* **Entrada (`ID de Servidor`):**
  ```text
  1
  ```
* **Resultado en Modo Vulnerable (Opción 1):** Muestra en pantalla el error crudo de SQLite: `[ERROR INTERNO EXPUESTO AL USUARIO]: no such table: servidores`, revelando el motor utilizado y el nombre exacto de la tabla.
* **Resultado Esperado en Modo Seguro (Opción 2):** Captura la excepción y muestra un mensaje neutro al operador (`[ERROR GENÉRICO - Defensa 4] No fue posible completar la consulta en este momento. El incidente fue registrado para el equipo de Soporte N2.`), mientras guarda el detalle técnico (`no such table: vista_servidores_soporte`) en `seguridad_cmdb.log`.
* **Defensas validadas:** Defensa 4 (Errores genéricos y auditoría en log).

---

## Punto 5 · Casos de prueba para la demo en vivo

### ✅ Login exitoso como analista

```
Usuario : mbellini
Password: 1234
```

Muestra el menú con opciones 1 (ver todos) y 2 (buscar por ID).  
La opción 3 (aprobar migración) **no aparece** para analistas.

---

### ✅ Login exitoso como miembro CCB

```
Usuario : lsanchez
Password: 1234
```

Muestra el menú completo incluyendo la opción **3 · Aprobar migración [CCB]**.

---

### 💥 Login con credenciales incorrectas

```
Usuario : mbellini
Password: contraseña_incorrecta
```

Respuesta: `Credenciales incorrectas. Intentos restantes: 2`  
Tras **3 intentos fallidos** → bloqueo de 10 segundos. El error no revela si el usuario existe.

---

### 💥 Login con usuario inyectado

```
Usuario : mbellini' OR '1'='1
Password: (cualquiera)
```

Respuesta: `Credenciales incorrectas.`  
La validación de formato rechaza el username antes de llegar a la DB.

---

### ✅ Ver todos los servidores (cualquier rol)

Iniciar sesión con cualquier usuario → opción `1`.  
Muestra la tabla con ID, CI_ID, Hostname, Estado, Entorno y Ticket de los 5 servidores.

---

### ✅ Buscar servidor por ID (cualquier rol)

Opción `2` → ingresar `3`  
Muestra: `CI-AWS-EC2-SN-02 | xom-ohio-snbridge02.aws.internal | En Migración`

**Intentar inyección:**

```
ID numérico del servidor: 1 OR 1=1
```

Respuesta: `[!] ID numérico inválido: '1 OR 1=1'. Debe ser entero positivo.`

---

### 🔒 Aprobar migración — solo CCB (función sensible)

**Intentar con analista (mbellini):** la opción 3 directamente no existe en su menú.  
Si se llama a la función directamente, devuelve `PermissionError`.

**Con lsanchez (CCB):** opción `3`

```
CI_ID del servidor: CI-AWS-EC2-SN-02
Nuevo estado      : Migrado
Confirmar (s/n)   : s
```

Resultado: `✓ Aprobación registrada: CI-AWS-EC2-SN-02 → Migrado`  
El cambio queda guardado en `cmdb_exxonmobil.db` y auditado en `panel_auditoria.log`.

---

### 💥 Inyección SQL en la aprobación (función sensible)

**Con lsanchez (CCB):** opción `3`

```
CI_ID del servidor: CI-AWS-EC2-SN-02' OR '1'='1
Nuevo estado      : Migrado
```

Respuesta: `[!] CI_ID inválido: 'CI-AWS-EC2-SN-02' OR '1'='1'. Formato esperado: CI-XXX-...`  
El input es rechazado por `re.fullmatch` antes de tocar la DB.

---

### 💥 Estado inválido en la aprobación

```
CI_ID del servidor: CI-AWS-EC2-SN-02
Nuevo estado      : Migrado; DROP TABLE servidores;--
```

Respuesta: `[!] Estado inválido: 'Migrado; DROP TABLE servidores;--'. Válidos: Cancelado, En Migración, Migrado, ...`

---

## Checklist de seguridad — Punto 5

| # | Requisito | Implementación |
|---|-----------|----------------|
| 1 | Sin contraseñas en texto plano | PBKDF2-HMAC-SHA256, sal aleatoria de 16 bytes, 260.000 iteraciones |
| 2 | Sin secretos hardcodeados | Contraseñas via `os.environ`; tokens de sesión con `secrets.token_hex(32)` |
| 3 | Validación de inputs | `re.fullmatch` con allowlists en username, CI_ID, estado e ID numérico |
| 4 | Control de acceso (función sensible) | `aprobar_migracion()` verifica `rol == "ccb"` antes de actuar |

Extras: comparación en **tiempo constante** (`hmac.compare_digest`), bloqueo por intentos fallidos, sesiones con TTL de 15 min, CMDB en modo solo lectura salvo para aprobaciones CCB, auditoría completa en `panel_auditoria.log`.

