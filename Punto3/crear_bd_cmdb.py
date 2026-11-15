import os
import sqlite3

DB_NAME = "cmdb_exxonmobil.db"


def inicializar_base_datos():
    # Si la base ya existe (por ejemplo, tras una demo de DROP TABLE), se recrea limpia
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 1. Tabla principal de Configuración (CIs de ServiceNow CMDB)
    cursor.execute("""
        CREATE TABLE servidores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ci_id TEXT NOT NULL UNIQUE,
            hostname TEXT NOT NULL,
            entorno TEXT NOT NULL,
            estado TEXT NOT NULL,
            ip_interna TEXT NOT NULL,
            ticket_servicenow TEXT NOT NULL
        )
    """)

    # 2. Tabla sensible ajena a la consulta de soporte N1 (para probar mínimo privilegio)
    cursor.execute("""
        CREATE TABLE credenciales_criticas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sistema TEXT NOT NULL,
            usuario_servicio TEXT NOT NULL,
            token_api TEXT NOT NULL
        )
    """)

    # 3. Vista de mínimo privilegio: expone solo datos no sensibles al portal de operadores
    cursor.execute("""
        CREATE VIEW vista_servidores_soporte AS
        SELECT id, ci_id, hostname, entorno, estado, ticket_servicenow
        FROM servidores
    """)

    # Carga de servidores de prueba (On-Premise + AWS Ohio)
    servidores_prueba = [
        (
            "CI-AWS-VM-WEB-01",
            "xom-ohio-web01.aws.internal",
            "AWS Cloud (Ohio - us-east-2)",
            "Operativo",
            "10.240.12.15",
            "RFC-XOM-2026-089",
        ),
        (
            "CI-ONPREM-HOU-DB01",
            "xom-hou-sql01.corp.internal",
            "On-Premise (Houston DC)",
            "Operativo",
            "172.16.40.10",
            "INC0045120",
        ),
        (
            "CI-AWS-EC2-SN-02",
            "xom-ohio-snbridge02.aws.internal",
            "AWS Cloud (Ohio - us-east-2)",
            "En Migración",
            "10.240.18.22",
            "RFC-XOM-2026-089",
        ),
        (
            "CI-ONPREM-HUN-APP04",
            "xom-hun-app04.corp.internal",
            "On-Premise (Hungría DC)",
            "Mantenimiento Programado",
            "172.19.88.41",
            "CHG0019834",
        ),
        (
            "CI-AWS-RDS-DRP-05",
            "xom-ohio-drp05.aws.internal",
            "AWS Cloud (Warm Standby)",
            "Standby Tibio (DRP)",
            "10.240.99.5",
            "RFC-XOM-2026-092",
        ),
    ]

    cursor.executemany(
        """
        INSERT INTO servidores (ci_id, hostname, entorno, estado, ip_interna, ticket_servicenow)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        servidores_prueba,
    )

    # Carga de credenciales internas restringidas
    credenciales_prueba = [
        ("AWS Account 734191771", "svc_terraform_deploy", "AKIAIOSFODNN7EXAMPLEKEY"),
        ("ServiceNow Discovery", "svc_cmdb_sync", "sn_tok_99812a7f4e21b00c"),
    ]

    cursor.executemany(
        """
        INSERT INTO credenciales_criticas (sistema, usuario_servicio, token_api)
        VALUES (?, ?, ?)
        """,
        credenciales_prueba,
    )

    conn.commit()
    conn.close()
    print(f"[OK] Base de datos '{DB_NAME}' inicializada con éxito.")
    print("[OK] Registros cargados: 5 servidores en CMDB + vista de mínimo privilegio creada.")


if __name__ == "__main__":
    inicializar_base_datos()