import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location(
    "panel",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel_migracion.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
conn = mod._init_panel_db()
mod._seed_usuarios(conn)
print("Seed completo. Ver credenciales_iniciales.txt")
