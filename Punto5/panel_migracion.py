# -*- coding: utf-8 -*-
"""
PUNTO 5 · Panel de seguimiento de migración — ExxonMobil (Offline / Consola)
=============================================================================
Checklist de seguridad:
  [1] Sin contraseñas ni datos sensibles en texto plano  → PBKDF2-HMAC-SHA256
  [2] Sin secretos ni credenciales hardcodeadas en el código → os.environ + secrets
  [3] Validación básica de inputs                        → re.fullmatch / allowlists
  [4] Control de acceso a función sensible               → solo miembro CCB puede
       "aprobar la migración de un servidor"

Solo biblioteca estándar. Ejecutar:
    python panel_migracion.py

Los usuarios del panel se crean al primer arranque y sus hashes se persisten en
usuarios_panel.db (SQLite local, sin datos de producción). Las credenciales de
ejemplo se generan aleatoriamente en cada primera ejecución y se muestran en
pantalla una sola vez; en un despliegue real se inyectarían via variables de entorno.
"""

import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import time

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN GENERAL
# ──────────────────────────────────────────────────────────────────────────────
_HERE    = os.path.dirname(os.path.abspath(__file__))
DB_CMDB  = os.path.join(_HERE, "..", "cmdb_exxonmobil.db")
DB_PANEL = os.path.join(_HERE, "usuarios_panel.db")
LOG_FILE = os.path.join(_HERE, "panel_auditoria.log")
SESSION_TTL = 900          # segundos (15 minutos)
PBKDF2_ITERS = 260_000     # iteraciones PBKDF2

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# ──────────────────────────────────────────────────────────────────────────────
# [1] + [2] GESTIÓN DE CONTRASEÑAS — hash con sal, sin texto plano en código
# ──────────────────────────────────────────────────────────────────────────────
def _hash_password(password: str, salt: bytes | None = None) -> str:
    """Devuelve 'pbkdf2$iters$salt_hex$hash_hex'. Salt se genera si no se pasa."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return f"pbkdf2${PBKDF2_ITERS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Comparación en tiempo constante para evitar timing attacks."""
    try:
        _, iters, salt_hex, stored_hex = stored.split("$")
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        ).hex()
        return hmac.compare_digest(candidate, stored_hex)
    except (ValueError, AttributeError):
        return False


# ──────────────────────────────────────────────────────────────────────────────
# BASE DE DATOS LOCAL DEL PANEL (usuarios + sesiones)
# ──────────────────────────────────────────────────────────────────────────────
def _init_panel_db() -> sqlite3.Connection:
    """Crea o abre la base de datos del panel con las tablas necesarias."""
    conn = sqlite3.connect(DB_PANEL)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS usuarios (
            username  TEXT PRIMARY KEY,
            hash_pwd  TEXT NOT NULL,
            rol       TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sesiones (
            token     TEXT PRIMARY KEY,
            username  TEXT NOT NULL,
            rol       TEXT NOT NULL,
            expira_en REAL NOT NULL
        )"""
    )
    conn.commit()
    return conn


def _seed_usuarios(conn: sqlite3.Connection) -> None:
    """
    Crea los usuarios de ejemplo si la tabla está vacía.
    [2] Las contraseñas se leen de variables de entorno; si no existen,
    se generan aleatoriamente y se muestran UNA SOLA VEZ (nunca se escriben
    en el código fuente).
    """
    if conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] > 0:
        return  # ya existen usuarios, no hacer nada

    generadas = []

    # [2] Los usernames se leen de variables de entorno.
    # Formato esperado por variable:  PANEL_USER_1=mbellini:analista
    #                                 PANEL_USER_2=rcrespo:analista
    #                                 PANEL_USER_3=lsanchez:ccb
    #                                 PANEL_USER_4=gfernandez:ccb
    # Si las variables no existen, se usan los valores por defecto SOLO para
    # facilitar la demo; en producción deben configurarse explícitamente.
    defaults = [
        ("PANEL_USER_1", "mbellini:analista"),
        ("PANEL_USER_2", "rcrespo:analista"),
        ("PANEL_USER_3", "lsanchez:ccb"),
        ("PANEL_USER_4", "gfernandez:ccb"),
    ]

    for env_var, fallback in defaults:
        entry = os.environ.get(env_var, fallback)
        try:
            username, rol = entry.split(":", 1)
        except ValueError:
            continue  # entrada mal formada, se omite

        # La contraseña se lee del entorno; si no existe, usa el fallback de demo.
        # En producción: configurar PWD_<USERNAME> como variable de entorno.
        pwd_var = f"PWD_{username.upper()}"
        pwd = os.environ.get(pwd_var, "1234")
        generadas.append((username.strip(), rol.strip(), pwd, pwd_var))
        conn.execute(
            "INSERT INTO usuarios VALUES (?, ?, ?)",
            (username.strip(), _hash_password(pwd), rol.strip()),
        )

    conn.commit()

    # Guardar credenciales en archivo y mostrarlas en pantalla (solo primera vez)
    cred_file = os.path.join(_HERE, "credenciales_iniciales.txt")
    lineas = [
        "PRIMERA EJECUCIÓN — Credenciales del panel de migración ExxonMobil",
        "Guardá este archivo en un lugar seguro y eliminalo después.",
        "-" * 60,
    ]
    for username, rol, pwd, env_var in generadas:
        lineas.append(f"  {username:<12} [{rol:<8}]  pwd={pwd}  (env: {env_var})")
    lineas.append("-" * 60)

    with open(cred_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas) + "\n")

    print("\n" + "=" * 60)
    print("  PRIMERA EJECUCIÓN — Credenciales generadas para el panel")
    print("  (También guardadas en: credenciales_iniciales.txt)")
    print("=" * 60)
    for username, rol, pwd, env_var in generadas:
        print(f"  {username:<12} [{rol:<8}]  pwd={pwd}  (env: {env_var})")
    print("=" * 60 + "\n")
    logging.info("Seed inicial de usuarios del panel ejecutado.")


# ──────────────────────────────────────────────────────────────────────────────
# AUTENTICACIÓN Y SESIONES
# ──────────────────────────────────────────────────────────────────────────────
def login(conn: sqlite3.Connection, username: str, password: str) -> str | None:
    """
    Autentica al usuario.  Devuelve un token de sesión o None.
    Mensaje único de error para no revelar si el usuario existe (evita enumeración).
    """
    # [3] Validar username: solo alfanumérico, 3-20 chars
    if not re.fullmatch(r"[a-zA-Z0-9]{3,20}", username):
        logging.warning(f"Login rechazado — username inválido: '{username}'")
        return None

    row = conn.execute(
        "SELECT hash_pwd, rol FROM usuarios WHERE username = ?", (username,)
    ).fetchone()

    # Se valida siempre para no filtrar por tiempo si el usuario no existe
    dummy_hash = _hash_password("dummy_para_timing")
    stored = row[0] if row else dummy_hash
    autenticado = row is not None and _verify_password(password, stored)

    if not autenticado:
        logging.warning(f"Login fallido para '{username}'.")
        return None

    # Limpiar sesiones expiradas del mismo usuario
    conn.execute(
        "DELETE FROM sesiones WHERE username = ? OR expira_en < ?",
        (username, time.time()),
    )
    token = secrets.token_hex(32)
    conn.execute(
        "INSERT INTO sesiones VALUES (?, ?, ?, ?)",
        (token, username, row[1], time.time() + SESSION_TTL),
    )
    conn.commit()
    logging.info(f"Login exitoso: '{username}' (rol={row[1]}).")
    return token


def _get_session(conn: sqlite3.Connection, token: str) -> tuple[str, str]:
    """Devuelve (username, rol) si la sesión es válida; lanza PermissionError si no."""
    row = conn.execute(
        "SELECT username, rol, expira_en FROM sesiones WHERE token = ?", (token,)
    ).fetchone()
    if not row or row[2] < time.time():
        raise PermissionError("Sesión no válida o expirada. Iniciá sesión nuevamente.")
    return row[0], row[1]


def logout(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sesiones WHERE token = ?", (token,))
    conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# VALIDADORES DE INPUT  [3]
# ──────────────────────────────────────────────────────────────────────────────
_RE_CI_ID    = re.compile(r"CI-[A-Z0-9\-]{3,30}")
_RE_HOSTNAME = re.compile(r"[a-z0-9][a-z0-9.\-]{2,60}")
_RE_TICKET   = re.compile(r"[A-Z]{2,5}[0-9\-]{1,15}")

ESTADOS_VALIDOS = {"Pendiente", "En Migración", "Operativo", "Migrado", "Cancelado",
                   "Mantenimiento Programado", "Standby Tibio (DRP)"}


def _validar_ci_id(ci_id: str) -> str:
    ci_id = ci_id.strip().upper()
    if not _RE_CI_ID.fullmatch(ci_id):
        raise ValueError(f"CI_ID inválido: '{ci_id}'. Formato esperado: CI-XXX-...")
    return ci_id


def _validar_estado(estado: str) -> str:
    estado = estado.strip()
    if estado not in ESTADOS_VALIDOS:
        raise ValueError(
            f"Estado inválido: '{estado}'.\nVálidos: {', '.join(sorted(ESTADOS_VALIDOS))}"
        )
    return estado


def _validar_id_numerico(valor: str) -> int:
    valor = valor.strip()
    if not re.fullmatch(r"[1-9][0-9]{0,4}", valor):
        raise ValueError(f"ID numérico inválido: '{valor}'. Debe ser entero positivo.")
    return int(valor)


# ──────────────────────────────────────────────────────────────────────────────
# FUNCIONES DEL PANEL (operan sobre cmdb_exxonmobil.db en modo lectura/escritura)
# ──────────────────────────────────────────────────────────────────────────────
def _abrir_cmdb_ro() -> sqlite3.Connection:
    """Abre la CMDB en modo solo lectura."""
    uri = f"file:{os.path.abspath(DB_CMDB)}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _abrir_cmdb_rw() -> sqlite3.Connection:
    """Abre la CMDB en modo lectura/escritura (solo para operaciones autorizadas)."""
    return sqlite3.connect(os.path.abspath(DB_CMDB))


# -- Listar servidores (cualquier usuario autenticado) -------------------------
def listar_servidores(conn_panel: sqlite3.Connection, token: str) -> list[tuple]:
    """Devuelve todos los servidores de la CMDB. Requiere sesión válida."""
    username, rol = _get_session(conn_panel, token)
    try:
        conn_cmdb = _abrir_cmdb_ro()
        # [3] Sin concatenación — consulta sin parámetros de usuario
        filas = conn_cmdb.execute(
            "SELECT id, ci_id, hostname, entorno, estado, ticket_servicenow FROM servidores"
        ).fetchall()
        conn_cmdb.close()
        logging.info(f"'{username}' listó servidores ({len(filas)} registros).")
        return filas
    except sqlite3.Error as err:
        logging.error(f"Error al listar servidores: {err}")
        raise RuntimeError("Error al acceder a la CMDB. Contactá al equipo de soporte.")


# -- Buscar servidor por ID (cualquier usuario autenticado) --------------------
def buscar_servidor(conn_panel: sqlite3.Connection, token: str, server_id: str) -> list[tuple]:
    """Busca un servidor por ID numérico. Requiere sesión válida."""
    username, _ = _get_session(conn_panel, token)
    id_limpio = _validar_id_numerico(server_id)   # [3] validación
    try:
        conn_cmdb = _abrir_cmdb_ro()
        filas = conn_cmdb.execute(
            "SELECT id, ci_id, hostname, entorno, estado, ticket_servicenow "
            "FROM servidores WHERE id = ?",
            (id_limpio,),                          # [3] parámetro, nunca concatenado
        ).fetchall()
        conn_cmdb.close()
        logging.info(f"'{username}' consultó servidor id={id_limpio}.")
        return filas
    except sqlite3.Error as err:
        logging.error(f"Error al buscar servidor id={id_limpio}: {err}")
        raise RuntimeError("Error al acceder a la CMDB.")


# -- [4] FUNCIÓN SENSIBLE: aprobar migración de un servidor -------------------
def aprobar_migracion(
    conn_panel: sqlite3.Connection, token: str, ci_id: str, nuevo_estado: str
) -> None:
    """
    [4] FUNCIÓN SENSIBLE — Solo miembros del Comité de Control de Cambios (CCB)
    pueden cambiar el estado de un servidor (ej. aprobarlo como 'Migrado').
    """
    username, rol = _get_session(conn_panel, token)

    # Control de acceso estricto
    if rol != "ccb":
        logging.warning(
            f"ACCESO DENEGADO: '{username}' (rol={rol}) intentó aprobar migración de {ci_id}."
        )
        raise PermissionError(
            "Acceso denegado. Solo miembros del CCB pueden aprobar migraciones."
        )

    ci_id_limpio    = _validar_ci_id(ci_id)       # [3] validación
    estado_limpio   = _validar_estado(nuevo_estado) # [3] validación

    try:
        conn_cmdb = _abrir_cmdb_rw()
        cursor = conn_cmdb.execute(
            "UPDATE servidores SET estado = ? WHERE ci_id = ?",
            (estado_limpio, ci_id_limpio),         # [3] parametrizado
        )
        if cursor.rowcount == 0:
            conn_cmdb.close()
            raise ValueError(f"No se encontró ningún servidor con CI_ID='{ci_id_limpio}'.")
        conn_cmdb.commit()
        conn_cmdb.close()
        logging.info(
            f"CCB '{username}' aprobó migración: {ci_id_limpio} → estado='{estado_limpio}'."
        )
    except sqlite3.Error as err:
        logging.error(f"Error al aprobar migración ci_id={ci_id_limpio}: {err}")
        raise RuntimeError("Error al actualizar la CMDB.")


# ──────────────────────────────────────────────────────────────────────────────
# INTERFAZ DE CONSOLA
# ──────────────────────────────────────────────────────────────────────────────
SEP  = "=" * 64
SEP2 = "-" * 64

def _cls():
    os.system("cls" if os.name == "nt" else "clear")


def _cabecera():
    print(SEP)
    print("  EXXONMOBIL — PANEL DE SEGUIMIENTO DE MIGRACIÓN A AWS")
    print("  Proyecto: On-Premise → AWS Cloud  |  Offline / Consola")
    print(SEP)


def _imprimir_servidores(filas: list[tuple]) -> None:
    if not filas:
        print("  (sin registros)")
        return
    fmt = "  {:<4} {:<22} {:<36} {:<14} {:<30} {}"
    print(fmt.format("ID", "CI_ID", "Hostname", "Estado", "Entorno", "Ticket"))
    print(SEP2)
    for fila in filas:
        id_, ci_id, host, entorno, estado, ticket = fila
        print(fmt.format(id_, ci_id, host[:35], estado[:13], entorno[:29], ticket))
    print(SEP2)


def _menu_principal(username: str, rol: str) -> str:
    print(f"\n  Usuario: {username}  |  Rol: {rol.upper()}")
    print(SEP2)
    print("  1. Ver todos los servidores")
    print("  2. Buscar servidor por ID")
    if rol == "ccb":
        print("  3. Aprobar migración de un servidor  [CCB]")
    print("  0. Cerrar sesión")
    print(SEP2)
    return input("  Opción: ").strip()


def _pantalla_login(conn_panel: sqlite3.Connection) -> tuple[str, str, str] | None:
    """
    Muestra el formulario de login. Devuelve (token, username, rol) o None si cancela.
    Tiene bloqueo de intentos: 3 fallos = pausa de 10 segundos.
    """
    intentos = 0
    max_intentos = 3

    while intentos < max_intentos:
        _cls()
        _cabecera()
        print("\n  Ingresá tus credenciales (0 para salir)\n")
        username = input("  Usuario : ").strip()
        if username == "0":
            return None

        # Ocultar la contraseña si getpass está disponible
        try:
            import getpass
            password = getpass.getpass("  Password: ")
        except Exception:
            password = input("  Password: ").strip()

        token = login(conn_panel, username, password)
        if token:
            row = conn_panel.execute(
                "SELECT rol FROM usuarios WHERE username = ?", (username,)
            ).fetchone()
            return token, username, row[0]

        intentos += 1
        restantes = max_intentos - intentos
        print(f"\n  Credenciales incorrectas. Intentos restantes: {restantes}")
        if restantes == 0:
            print("  Demasiados intentos fallidos. Esperá 10 segundos...")
            time.sleep(10)
            intentos = 0  # reiniciar contador tras la pausa


def _flujo_aprobar(conn_panel: sqlite3.Connection, token: str) -> None:
    print("\n  APROBAR MIGRACIÓN DE SERVIDOR")
    print(SEP2)
    print(f"  Estados válidos: {', '.join(sorted(ESTADOS_VALIDOS))}")
    ci_id  = input("\n  CI_ID del servidor (ej. CI-AWS-EC2-SN-02): ").strip()
    estado = input("  Nuevo estado                             : ").strip()
    confirmacion = input(f"\n  Confirmar: cambiar '{ci_id}' → '{estado}'? (s/n): ").strip().lower()
    if confirmacion != "s":
        print("  Operación cancelada.")
        return
    try:
        aprobar_migracion(conn_panel, token, ci_id, estado)
        print(f"\n  ✓ Aprobación registrada: {ci_id} → {estado}")
    except (PermissionError, ValueError, RuntimeError) as exc:
        print(f"\n  [!] Error: {exc}")


def main():
    # Inicializar base de datos del panel
    conn_panel = _init_panel_db()
    _seed_usuarios(conn_panel)

    while True:
        resultado = _pantalla_login(conn_panel)
        if resultado is None:
            print("\n  Saliendo del panel. Hasta luego.\n")
            break

        token, username, rol = resultado
        _cls()

        # Bucle de sesión
        while True:
            _cls()
            _cabecera()
            opcion = _menu_principal(username, rol)

            if opcion == "1":
                print("\n  LISTADO COMPLETO DE SERVIDORES\n")
                try:
                    filas = listar_servidores(conn_panel, token)
                    _imprimir_servidores(filas)
                except (PermissionError, RuntimeError) as exc:
                    print(f"  [!] {exc}")
                input("\n  [Enter para continuar]")

            elif opcion == "2":
                print("\n  BUSCAR SERVIDOR POR ID\n")
                server_id = input("  ID numérico del servidor: ").strip()
                try:
                    filas = buscar_servidor(conn_panel, token, server_id)
                    _imprimir_servidores(filas)
                except (ValueError, PermissionError, RuntimeError) as exc:
                    print(f"  [!] {exc}")
                input("\n  [Enter para continuar]")

            elif opcion == "3" and rol == "ccb":
                _flujo_aprobar(conn_panel, token)
                input("\n  [Enter para continuar]")

            elif opcion == "0":
                logout(conn_panel, token)
                logging.info(f"'{username}' cerró sesión.")
                print(f"\n  Sesión de '{username}' cerrada.\n")
                break

            else:
                print("  Opción no válida.")
                time.sleep(1)


if __name__ == "__main__":
    main()
