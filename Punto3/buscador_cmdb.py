import logging
import os
import re
import sqlite3

DB_NAME = "cmdb_exxonmobil.db"
LOG_FILE = "seguridad_cmdb.log"

# Configuración del registro interno de auditoría (para errores genéricos)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


def imprimir_resultados(filas, modo_seguro=False):
    if not filas:
        print("-> No se encontraron servidores para el ID ingresado.")
        return

    print(f"\n--- Resultados encontrados ({len(filas)}) ---")
    for fila in filas:
        if modo_seguro:
            # La vista restringida no expone la IP interna
            print(
                f"ID: {fila[0]} | CI: {fila[1]} | Host: {fila[2]} | "
                f"Entorno: {fila[3]} | Estado: {fila[4]} | Ticket: {fila[5]}"
            )
        else:
            print(fila)
    print("-" * 55)


def buscar_vulnerable(server_id: str):
    """
    MODO INSEGURO: Concatena directamente la entrada del usuario en la consulta SQL.
    El dato ingresado se interpreta como parte de la instrucción SQL.
    """
    print("\n[!] Ejecutando en MODO VULNERABLE (sin defensas)...")
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # VULNERABILIDAD: Concatenación directa de strings
        consulta_sql = f"SELECT * FROM servidores WHERE id = {server_id}"
        print(f"[SQL Ejecutado]: {consulta_sql}")

        # Si el atacante inyecta múltiples sentencias separadas por ';', ejecuta el script completo
        if ";" in server_id:
            cursor.executescript(consulta_sql)
            conn.commit()
            print("[!] ALERTA CRÍTICA: Se ejecutaron múltiples sentencias SQL en la base.")
        else:
            cursor.execute(consulta_sql)
            resultados = cursor.fetchall()
            imprimir_resultados(resultados, modo_seguro=False)

        conn.close()
    except sqlite3.Error as err:
        # VULNERABILIDAD EXTRA: Expone el error interno de SQLite al usuario final
        print(f"[ERROR INTERNO EXPUESTO AL USUARIO]: {err}")


def buscar_seguro(server_id: str):
    """
    MODO SEGURO: Aplica las 4 defensas combinadas contra inyección de código.
    """
    print("\n[OK] Ejecutando en MODO SEGURO (4 defensas activas)...")

    # DEFENSA 1: Validación de entradas mediante lista blanca (Allowlist)
    # Solo se aceptan dígitos enteros positivos (1 a 5 caracteres). Rechaza comillas, espacios, OR, ';', etc.
    if not re.fullmatch(r"[1-9]\d{0,4}", server_id.strip()):
        print(
            "[BLOQUEADO - Defensa 1: Validación de Entrada] "
            "Formato inválido. El ID de servidor debe ser un número entero positivo."
        )
        logging.warning(f"Intento de entrada rechazada por lista blanca: '{server_id}'")
        return

    server_id_limpio = int(server_id.strip())

    try:
        # DEFENSA 2 (Parte A): Mínimo privilegio a nivel conexión (Solo Lectura / Read-Only)
        # Incluso si existiera otra falla, el motor bloquea DROP, DELETE, UPDATE e INSERT.
        uri_solo_lectura = f"file:{DB_NAME}?mode=ro"
        conn = sqlite3.connect(uri_solo_lectura, uri=True)
        cursor = conn.cursor()

        # DEFENSA 2 (Parte B) + DEFENSA 3: Consulta parametrizada (?) sobre vista restringida
        # La instrucción SQL y el dato viajan separados; el dato nunca se interpreta como código.
        consulta_parametrizada = """
            SELECT id, ci_id, hostname, entorno, estado, ticket_servicenow
            FROM vista_servidores_soporte
            WHERE id = ?
        """
        cursor.execute(consulta_parametrizada, (server_id_limpio,))
        resultados = cursor.fetchall()

        imprimir_resultados(resultados, modo_seguro=True)
        conn.close()

    except sqlite3.Error as err:
        # DEFENSA 4: Errores genéricos
        # El usuario recibe un mensaje neutro; el detalle técnico va exclusivamente al log interno.
        logging.error(f"Error de base de datos al consultar ID={server_id_limpio}: {err}")
        print(
            "[ERROR GENÉRICO - Defensa 4] No fue posible completar la consulta en este momento. "
            "El incidente fue registrado para el equipo de Soporte N2."
        )


def menu():
    if not os.path.exists(DB_NAME):
        print(f"[!] No se encontró '{DB_NAME}'. Ejecutá primero 'crear_bd_cmdb.py'.")
        return

    while True:
        print("\n=======================================================")
        print("  PORTAL INTERNO EXXONMOBIL (BSC ARGENTINA) - CMDB")
        print("=======================================================")
        print("1. Consultar servidor (MODO VULNERABLE - Concatenación)")
        print("2. Consultar servidor (MODO SEGURO - 4 Defensas)")
        print("3. Salir")
        opcion = input("\nSeleccioná una opción (1/2/3): ").strip()

        if opcion == "1":
            server_id = input("Ingresá el ID de Servidor a consultar: ")
            buscar_vulnerable(server_id)
        elif opcion == "2":
            server_id = input("Ingresá el ID de Servidor a consultar: ")
            buscar_seguro(server_id)
        elif opcion == "3":
            print("Cerrando sesión del portal CMDB.")
            break
        else:
            print("Opción no válida.")


if __name__ == "__main__":
    menu()