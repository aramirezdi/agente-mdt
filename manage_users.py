#!/usr/bin/env python3
"""
Gestor de usuarios — Agente MDT
Uso:
  python manage_users.py add    -> Agregar usuario
  python manage_users.py list   -> Listar usuarios
  python manage_users.py remove -> Eliminar usuario
  python manage_users.py reset  -> Cambiar contraseña
"""
import json, hashlib, secrets, sys, os, getpass
from datetime import datetime

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    print(f"  Guardado en {USERS_FILE}")

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(32)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000)
    return salt, hashed.hex()

def add_user():
    users = load_users()
    print("\n--- Agregar usuario ---")
    username = input("  Usuario: ").strip().lower()
    if not username:
        print("  Error: el usuario no puede estar vacío.")
        return
    if username in users:
        print(f"  Error: el usuario '{username}' ya existe.")
        return
    name = input("  Nombre completo: ").strip()
    role = input("  Rol (admin/user) [user]: ").strip().lower() or "user"
    if role not in ["admin", "user"]:
        role = "user"
    password = getpass.getpass("  Contraseña: ")
    if len(password) < 6:
        print("  Error: la contraseña debe tener al menos 6 caracteres.")
        return
    confirm = getpass.getpass("  Confirmar contraseña: ")
    if password != confirm:
        print("  Error: las contraseñas no coinciden.")
        return
    salt, hashed = hash_password(password)
    users[username] = {
        "name": name,
        "role": role,
        "salt": salt,
        "password": hashed,
        "created": datetime.now().isoformat(),
        "active": True
    }
    save_users(users)
    print(f"\n  ✓ Usuario '{username}' ({role}) creado correctamente.")

def list_users():
    users = load_users()
    if not users:
        print("\n  No hay usuarios registrados.")
        return
    print(f"\n  {'Usuario':<20} {'Nombre':<25} {'Rol':<8} {'Estado':<8} {'Creado'}")
    print("  " + "-"*75)
    for u, d in users.items():
        estado = "Activo" if d.get("active", True) else "Inactivo"
        fecha = d.get("created","")[:10]
        print(f"  {u:<20} {d.get('name',''):<25} {d.get('role',''):<8} {estado:<8} {fecha}")

def remove_user():
    users = load_users()
    list_users()
    print("\n--- Eliminar usuario ---")
    username = input("  Usuario a eliminar: ").strip().lower()
    if username not in users:
        print(f"  Error: el usuario '{username}' no existe.")
        return
    confirm = input(f"  ¿Eliminar '{username}'? (s/n): ").strip().lower()
    if confirm == "s":
        del users[username]
        save_users(users)
        print(f"  ✓ Usuario '{username}' eliminado.")

def reset_password():
    users = load_users()
    list_users()
    print("\n--- Cambiar contraseña ---")
    username = input("  Usuario: ").strip().lower()
    if username not in users:
        print(f"  Error: el usuario '{username}' no existe.")
        return
    password = getpass.getpass("  Nueva contraseña: ")
    if len(password) < 6:
        print("  Error: la contraseña debe tener al menos 6 caracteres.")
        return
    confirm = getpass.getpass("  Confirmar contraseña: ")
    if password != confirm:
        print("  Error: las contraseñas no coinciden.")
        return
    salt, hashed = hash_password(password)
    users[username]["salt"] = salt
    users[username]["password"] = hashed
    save_users(users)
    print(f"  ✓ Contraseña de '{username}' actualizada.")

def create_default():
    """Crear usuario admin por defecto si no existe ninguno"""
    users = load_users()
    if not users:
        print("\n  No hay usuarios. Creando usuario admin por defecto...")
        print("  Usuario: admin")
        password = getpass.getpass("  Contraseña para admin: ")
        if len(password) < 6:
            print("  Usando contraseña mínima de 6 caracteres requerida.")
            return
        salt, hashed = hash_password(password)
        users["admin"] = {
            "name": "Administrador MDT",
            "role": "admin",
            "salt": salt,
            "password": hashed,
            "created": datetime.now().isoformat(),
            "active": True
        }
        save_users(users)
        print("  ✓ Usuario admin creado.")

if __name__ == "__main__":
    print("=" * 48)
    print("  Gestor de Usuarios — Agente MDT")
    print("=" * 48)
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "add":
        add_user()
    elif cmd == "list":
        list_users()
    elif cmd == "remove":
        remove_user()
    elif cmd == "reset":
        reset_password()
    elif cmd == "init":
        create_default()
    else:
        print("\n  Comandos disponibles:")
        print("    python manage_users.py init    -> Crear primer usuario admin")
        print("    python manage_users.py add     -> Agregar usuario")
        print("    python manage_users.py list    -> Listar usuarios")
        print("    python manage_users.py remove  -> Eliminar usuario")
        print("    python manage_users.py reset   -> Cambiar contraseña")
