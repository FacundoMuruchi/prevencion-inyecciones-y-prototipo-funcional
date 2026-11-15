# -*- coding: utf-8 -*-
"""Tests de lógica del panel (sin interacción de consola)."""
import importlib.util, os, secrets, sqlite3, sys

sys.path.insert(0, os.path.dirname(__file__))
spec = importlib.util.spec_from_file_location("panel", os.path.join(os.path.dirname(__file__), "panel_migracion.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

conn = mod._init_panel_db()

print("=" * 55)
print("  TEST DE LÓGICA — PANEL DE MIGRACIÓN EXXONMOBIL")
print("=" * 55)

# 1. Hash round-trip
pwd = secrets.token_urlsafe(8)
h = mod._hash_password(pwd)
assert mod._verify_password(pwd, h),     "FALLA: hash correcto no verifica"
assert not mod._verify_password("mal", h), "FALLA: hash incorrecto verifica"
print("[OK] [1] Hash PBKDF2 round-trip y comparación en tiempo constante")

# 2. Login con username inválido (inyección)
result = mod.login(conn, "x' OR '1'='1", "pass")
assert result is None, "FALLA: login debería rechazar username inválido"
print("[OK] [3] Login rechaza username con caracteres inválidos")

# 3. Validación CI_ID - inyección bloqueada
malo = "CI-AWS-EC2' OR '1'='1"
try:
    mod._validar_ci_id(malo)
    print("FALLA: CI_ID inyectado no fue bloqueado")
except ValueError:
    print("[OK] [3] Inyección en CI_ID bloqueada")

# 4. CI_ID válido pasa
try:
    r = mod._validar_ci_id("CI-AWS-EC2-SN-02")
    assert r == "CI-AWS-EC2-SN-02"
    print("[OK] [3] CI_ID válido aceptado")
except ValueError as e:
    print(f"FALLA: CI_ID válido rechazado: {e}")

# 5. Estado inválido bloqueado
try:
    mod._validar_estado("Migrado'; DROP TABLE servidores;--")
    print("FALLA: Estado inválido no bloqueado")
except ValueError:
    print("[OK] [3] Inyección en estado bloqueada")

# 6. Estado válido pasa
try:
    r = mod._validar_estado("Migrado")
    assert r == "Migrado"
    print("[OK] [3] Estado válido aceptado")
except ValueError as e:
    print(f"FALLA: estado válido rechazado: {e}")

# 7. Control de acceso: analista no puede aprobar
usuarios = conn.execute("SELECT username, rol FROM usuarios").fetchall()
analistas = [u[0] for u in usuarios if u[1] == "analista"]
ccbs      = [u[0] for u in usuarios if u[1] == "ccb"]

if analistas:
    # Crear sesión falsa de analista para test
    import time
    fake_token = secrets.token_hex(32)
    conn.execute(
        "INSERT INTO sesiones VALUES (?, ?, ?, ?)",
        (fake_token, analistas[0], "analista", time.time() + 900)
    )
    conn.commit()
    try:
        mod.aprobar_migracion(conn, fake_token, "CI-AWS-EC2-SN-02", "Migrado")
        print("FALLA: analista pudo aprobar migración (debería estar bloqueado)")
    except PermissionError as e:
        print(f"[OK] [4] Analista bloqueado de aprobar migración: {e}")

# 8. Validación ID numérico
try:
    mod._validar_id_numerico("1 OR 1=1")
    print("FALLA: ID inyectado no bloqueado")
except ValueError:
    print("[OK] [3] Inyección en ID numérico bloqueada")

try:
    r = mod._validar_id_numerico("3")
    assert r == 3
    print("[OK] [3] ID numérico válido aceptado")
except ValueError as e:
    print(f"FALLA: {e}")

print("=" * 55)
print("  Todos los tests completados.")
print("=" * 55)
