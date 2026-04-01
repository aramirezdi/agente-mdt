#!/usr/bin/env python3
"""
Servidor MDT Seguro v4
- Login con usuario y contrasena
- Credenciales persistentes (Zoho Refresh Token, SendPulse, Anthropic)
- Renovacion automatica de tokens
- Sesiones con expiracion de 8 horas
"""
import json, hashlib, secrets, hmac, os, time, base64, shutil, threading
import urllib.request, urllib.parse, urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta

USERS_FILE       = "users.json"
CREDENTIALS_FILE = "credentials.json"
BANNERS_DIR      = "banners"
HISTORY_FILE     = "history.json"
SCHEDULED_FILE   = "scheduled.json"

os.makedirs(BANNERS_DIR, exist_ok=True)
SESSION_TTL      = 8  # horas

# Sesiones en memoria
sessions = {}

# ── Credenciales persistentes ──
def load_creds():
    # En producción (Railway), leer desde variables de entorno
    env_creds = {}
    for key in ["zoho_client_id","zoho_client_secret","zoho_refresh_token",
                "zoho_access_token","zoho_account_id","sp_client_id",
                "sp_client_secret","anthropic_key","wa_token","wa_phone_id","wa_waba_id",
                "wati_endpoint","wati_token",
                "zepto_api_key"]:
        val = os.environ.get(key.upper(),"")
        if val: env_creds[key] = val
    if env_creds:
        file_creds = {}
        if os.path.exists(CREDENTIALS_FILE):
            try:
                with open(CREDENTIALS_FILE,"r") as f:
                    file_creds = json.load(f)
            except: pass
        return {**file_creds, **env_creds}
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_creds(creds):
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(creds, f, indent=2)

# ── Zoho: renovar access token con refresh token ──
def zoho_refresh(creds):
    r = _req_static(
        "https://accounts.zoho.com/oauth/v2/token",
        {"grant_type": "refresh_token",
         "client_id": creds.get("zoho_client_id"),
         "client_secret": creds.get("zoho_client_secret"),
         "refresh_token": creds.get("zoho_refresh_token")},
        {"Content-Type": "application/x-www-form-urlencoded"}
    )
    if r.get("access_token"):
        creds["zoho_access_token"] = r["access_token"]
        creds["zoho_token_time"] = time.time()
        save_creds(creds)
        return r["access_token"]
    return None

def get_zoho_token():
    creds = load_creds()
    # Si el token tiene menos de 50 minutos, reutilizarlo
    token_time = creds.get("zoho_token_time", 0)
    if creds.get("zoho_access_token") and (time.time() - token_time) < 3000:
        return creds["zoho_access_token"], creds.get("zoho_account_id")
    # Renovar
    if creds.get("zoho_refresh_token"):
        token = zoho_refresh(creds)
        if token:
            return token, creds.get("zoho_account_id")
    return None, None

# ── SendPulse: obtener token ──
def get_sp_token():
    creds = load_creds()
    # Soporte para API Key directa (sp_sk_...)
    api_key = creds.get("sp_api_key","")
    if api_key:
        return api_key
    # OAuth con Client ID y Secret
    sp_id  = creds.get("sp_client_id","")
    sp_sec = creds.get("sp_client_secret","")
    if not sp_id or not sp_sec:
        return None
    sp_time = creds.get("sp_token_time", 0)
    if creds.get("sp_access_token") and (time.time() - sp_time) < 3500:
        return creds["sp_access_token"]
    r = _req_static(
        "https://api.sendpulse.com/oauth/access_token",
        {"grant_type":"client_credentials","client_id":sp_id,"client_secret":sp_sec},
        {"Content-Type":"application/json"}
    )
    if r.get("access_token"):
        creds["sp_access_token"] = r["access_token"]
        creds["sp_token_time"] = time.time()
        save_creds(creds)
        return r["access_token"]
    return None

# ── HTTP helper estatico ──
def _req_static(url, data=None, headers=None):
    if data is not None:
        ct = (headers or {}).get("Content-Type","")
        if isinstance(data, dict):
            encoded = json.dumps(data).encode() if "json" in ct else urllib.parse.urlencode(data).encode()
        else:
            encoded = data if isinstance(data, bytes) else str(data).encode()
    else:
        encoded = None
    req = urllib.request.Request(url, data=encoded, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try: return json.loads(e.read().decode("utf-8"))
        except: return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

# ── Usuarios ──
def load_users():
    users_env = os.environ.get("USERS_JSON","")
    if users_env:
        try:
            return json.loads(users_env)
        except: pass
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def verify_password(stored, salt, password):
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return hmac.compare_digest(hashed, stored)

def create_session(username, user_data):
    token = secrets.token_urlsafe(48)
    sessions[token] = {
        "username": username,
        "name": user_data.get("name", username),
        "role": user_data.get("role","user"),
        "expires": (datetime.now() + timedelta(hours=SESSION_TTL)).isoformat()
    }
    return token

def get_session(token):
    if not token or token not in sessions:
        return None
    s = sessions[token]
    if datetime.now() > datetime.fromisoformat(s["expires"]):
        del sessions[token]
        return None
    return s

def clean_sessions():
    now = datetime.now()
    expired = [t for t,s in sessions.items() if now > datetime.fromisoformat(s["expires"])]
    for t in expired:
        del sessions[t]

LOGO_B64 = "iVBORw0KGgoAAAANSUhEUgAAB9AAAALCCAYAAACGHkhOAAABCGlDQ1BJQ0MgUHJvZmlsZQAAeJxjYGA8wQAELAYMDLl5JUVB7k4KEZFRCuwPGBiBEAwSk4sLGHADoKpv1yBqL+viUYcLcKakFicD6Q9ArFIEtBxopAiQLZIOYWuA2EkQtg2IXV5SUAJkB4DYRSFBzkB2CpCtkY7ETkJiJxcUgdT3ANk2uTmlyQh3M/Ck5oUGA2kOIJZhKGYIYnBncAL5H6IkfxEDg8VXBgbmCQixpJkMDNtbGRgkbiHEVBYwMPC3MDBsO48QQ4RJQWJRIliIBYiZ0tIYGD4tZ2DgjWRgEL7AwMAVDQsIHG5TALvNnSEfCNMZchhSgSKeDHkMyQx6QJYRgwGDIYMZAKbWPz9HbOBQAAAbsUlEQVR4nO3ZQQ0AIBDAsIF/z4cMSGgV7L9VTQAAAAAAAADwuX07AAAAAAAAAABeYKADAAAAAAAAQAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFR1ABGQBoM53VWzAAAAAElFTkSuQmCC"

LOGIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>MDT Agente — Acceso</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0f0f12;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#18181e;border:1px solid #2a2a36;border-radius:14px;padding:40px 36px;width:100%;max-width:380px}
.logo-wrap{text-align:center;margin-bottom:20px}
.logo-wrap img{height:52px;object-fit:contain}
h1{font-size:20px;font-weight:600;color:#eeeef5;text-align:center;margin-bottom:6px}
p{font-size:13px;color:#8a8aaa;text-align:center;margin-bottom:28px}
label{display:block;font-size:12px;color:#8a8aaa;font-weight:500;margin-bottom:5px}
input{width:100%;padding:10px 13px;background:#202028;border:1px solid #2a2a36;border-radius:8px;color:#eeeef5;font-size:13px;outline:none;transition:border-color .18s;margin-bottom:16px}
input:focus{border-color:#7c6ffc}
input::placeholder{color:#4a4a62}
button{width:100%;padding:11px;background:#7c6ffc;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;transition:background .15s;margin-top:4px}
button:hover{background:#6b5ef0}
.err{background:#2e0e0e;border:1px solid #5a2020;color:#f05252;padding:10px 13px;border-radius:7px;font-size:13px;margin-bottom:16px;display:none}
.err.show{display:block}
</style>
</head>
<body>
<div class="card">
  <div class="logo-wrap"><img src="https://merlin-global.com/assets/merlin-logo-BbzWVHUY.png" alt="Merlin"/></div>
  <h1>Agente MDT</h1>
  <p>Ingresa tus credenciales para continuar</p>
  <div class="err" id="err"></div>
  <form onsubmit="login(event)">
    <label>Usuario</label>
    <input id="u" type="text" placeholder="tu.usuario" autocomplete="username" required/>
    <label>Contrasena</label>
    <input id="p" type="password" placeholder="..." autocomplete="current-password" required/>
    <button type="submit" id="btn">Ingresar</button>
  </form>
</div>
<script>
async function login(e){
  e.preventDefault();
  const btn=document.getElementById('btn');
  const err=document.getElementById('err');
  btn.textContent='Verificando...';btn.disabled=true;err.classList.remove('show');
  try{
    const r=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:document.getElementById('u').value.trim().toLowerCase(),
        password:document.getElementById('p').value})});
    const d=await r.json();
    if(d.token){
      sessionStorage.setItem('mdt_session',d.token);
      sessionStorage.setItem('mdt_user',JSON.stringify({name:d.name,role:d.role,username:d.username}));
      window.location.href='/app';
    }else{
      err.textContent=d.error||'Credenciales incorrectas.';
      err.classList.add('show');
      btn.textContent='Ingresar';btn.disabled=false;
    }
  }catch(ex){
    err.textContent='Error de conexion.';err.classList.add('show');
    btn.textContent='Ingresar';btn.disabled=false;
  }
}
const t=sessionStorage.getItem('mdt_session');
if(t) fetch('/auth/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})})
  .then(r=>r.json()).then(d=>{if(d.valid)window.location.href='/app';});
</script>
</body>
</html>"""

LOGIN_HTML = LOGIN_HTML.replace("iVBORw0KGgoAAAANSUhEUgAAB9AAAALCCAYAAACGHkhOAAABCGlDQ1BJQ0MgUHJvZmlsZQAAeJxjYGA8wQAELAYMDLl5JUVB7k4KEZFRCuwPGBiBEAwSk4sLGHADoKpv1yBqL+viUYcLcKakFicD6Q9ArFIEtBxopAiQLZIOYWuA2EkQtg2IXV5SUAJkB4DYRSFBzkB2CpCtkY7ETkJiJxcUgdT3ANk2uTmlyQh3M/Ck5oUGA2kOIJZhKGYIYnBncAL5H6IkfxEDg8VXBgbmCQixpJkMDNtbGRgkbiHEVBYwMPC3MDBsO48QQ4RJQWJRIliIBYiZ0tIYGD4tZ2DgjWRgEL7AwMAVDQsIHG5TALvNnSEfCNMZchhSgSKeDHkMyQx6QJYRgwGDIYMZAKbWPz9HbOBQAAAbsUlEQVR4nO3ZQQ0AIBDAsIF/z4cMSGgV7L9VTQAAAAAAAADwuX07AAAAAAAAAABeYKADAAAAAAAAQAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFQGOgAAAAAAAABUBjoAAAAAAAAAVAY6AAAAAAAAAFR1ABGQBoM53VWzAAAAAElFTkSuQmCC", LOGO_B64)

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        status = args[1] if len(args)>1 else ""
        path = args[0].split(" ")[1] if " " in str(args[0]) else ""
        if path not in ["/auth/verify"]:
            print(f"  {status}  {path}")

    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type, X-Session-Token")

    def send_sec(self):
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","SAMEORIGIN")

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_cors(); self.send_sec()
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, content):
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.send_response(200)
        self.send_cors(); self.send_sec()
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ["/", "/login"]:
            self.send_html(LOGIN_HTML)
            return
        if path == "/app":
            for name in ["index.html","index_v2.html"]:
                try:
                    with open(name,"rb") as f:
                        content = f.read()
                    sec = """<script>
(function(){
  var t=sessionStorage.getItem('mdt_session');
  if(!t){window.location.href='/';return;}
  var orig=window.fetch;
  window.fetch=function(url,opts){
    opts=opts||{};opts.headers=opts.headers||{};
    opts.headers['X-Session-Token']=t;
    return orig(url,opts);
  };
  try{
    var u=JSON.parse(sessionStorage.getItem('mdt_user')||'{}');
    document.addEventListener('DOMContentLoaded',function(){
      var h=document.querySelector('.hdr p');
      if(h&&u.name) h.innerHTML+=' - <span style="color:#7c6ffc">'+u.name+'</span> <button onclick="logout()" style="background:none;border:none;color:#8a8aaa;cursor:pointer;font-size:12px;margin-left:4px">[Salir]</button>';
    });
  }catch(e){}
  window.logout=function(){
    var t=sessionStorage.getItem('mdt_session');
    fetch('/auth/logout',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':t},body:JSON.stringify({token:t})});
    sessionStorage.clear();window.location.href='/';
  };
})();
</script>""".encode("utf-8")
                    content = content.replace(b"<head>", b"<head>" + sec, 1)
                    self.send_html(content)
                    return
                except FileNotFoundError:
                    continue
            self.send_json({"error":"HTML no encontrado"},404)
            return
        # Estado de credenciales (para que la app sepa qué está configurado)
        if path == "/api/creds-status":
            creds = load_creds()
            self.send_json({
                "zoho": bool(creds.get("zoho_refresh_token")),
                "sendpulse": bool(creds.get("sp_api_key") or creds.get("sp_client_id")),
                "zeptomail": bool(creds.get("zepto_api_key")),
                "anthropic": bool(creds.get("anthropic_key")),
                "zoho_account_id": creds.get("zoho_account_id","")
            })
            return
        # Servir banners guardados
        if path.startswith("/banners/"):
            fname = os.path.basename(path)
            fpath = os.path.join(BANNERS_DIR, fname)
            if os.path.exists(fpath):
                ext = fname.rsplit(".",1)[-1].lower()
                mime = {"png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg","gif":"image/gif","webp":"image/webp"}.get(ext,"image/png")
                with open(fpath,"rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control","public, max-age=86400")
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_json({"error":"Banner no encontrado"},404)
            return
        self.send_json({"error":"Not found"},404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length",0))
            body = self.rfile.read(length)
            payload = json.loads(body) if body else {}
        except Exception as e:
            self.send_json({"error":f"JSON invalido: {e}"},400)
            return

        path = self.path.split("?")[0]

        if path == "/auth/login":   self._login(payload);  return
        if path == "/auth/verify":  self._verify(payload); return
        if path == "/auth/logout":  self._logout(payload); return

        # Verificar sesion
        token = self.headers.get("X-Session-Token","")
        if not get_session(token):
            self.send_json({"error":"Sesion invalida. Recarga la pagina."},401)
            return

        routes = {
            "/api/save-creds":      self._save_creds,
            "/api/zoho-connect":    self._zoho_connect,
            "/api/zoho-send":       self._zoho_send,
            "/api/claude":          self._claude,
            "/api/sp-send":         self._sp_send,
            "/api/zepto-send":      self._zepto_send,
            "/api/banner-upload":   self._banner_upload,
            "/api/banner-url":      self._banner_url,
            "/api/banners-list":    self._banners_list,
            "/api/banner-delete":   self._banner_delete,
            "/api/history-save":    self._history_save,
            "/api/history-load":    self._history_load,
            "/api/schedule-save":   self._schedule_save,
            "/api/schedule-list":   self._schedule_list,
            "/api/schedule-delete": self._schedule_delete,
            "/api/wa-send":         self._wa_send,
            "/api/wa-status":       self._wa_status,
        }
        h = routes.get(path)
        if h:
            try: h(payload)
            except Exception as e: self.send_json({"error":str(e)},500)
        else:
            self.send_json({"error":"Ruta no encontrada"},404)

    def _req(self, url, data=None, headers=None):
        return _req_static(url, data, headers)

    # ── Auth ──
    def _login(self, p):
        clean_sessions()
        username = (p.get("username") or "").strip().lower()
        password = p.get("password") or ""
        if not username or not password:
            self.send_json({"error":"Usuario y contrasena requeridos."})
            return
        users = load_users()
        user = users.get(username)
        if not user or not user.get("active",True):
            self.send_json({"error":"Usuario o contrasena incorrectos."})
            return
        if not verify_password(user["password"], user["salt"], password):
            self.send_json({"error":"Usuario o contrasena incorrectos."})
            return
        token = create_session(username, user)
        print(f"  Login: {username}")
        self.send_json({"token":token,"name":user.get("name",username),
                        "role":user.get("role","user"),"username":username})

    def _verify(self, p):
        s = get_session(p.get("token",""))
        self.send_json({"valid":bool(s),"name":s["name"] if s else "","role":s["role"] if s else ""})

    def _logout(self, p):
        t = p.get("token","")
        if t in sessions: del sessions[t]
        self.send_json({"ok":True})

    # ── Guardar credenciales ──
    def _save_creds(self, p):
        creds = load_creds()
        if p.get("anthropic_key"): creds["anthropic_key"] = p["anthropic_key"]
        if p.get("sp_api_key"):    creds["sp_api_key"]    = p["sp_api_key"]
        if p.get("sp_client_id"):  creds["sp_client_id"]  = p["sp_client_id"]
        if p.get("sp_client_secret"): creds["sp_client_secret"] = p["sp_client_secret"]
        if p.get("zepto_api_key"):   creds["zepto_api_key"]   = p["zepto_api_key"]
        if p.get("wati_endpoint"):   creds["wati_endpoint"]   = p["wati_endpoint"].rstrip("/")
        if p.get("wati_token"):      creds["wati_token"]      = p["wati_token"]
        save_creds(creds)
        self.send_json({"ok":True})

    # ── Zoho: conectar con codigo y guardar refresh token ──
    def _zoho_connect(self, p):
        creds = load_creds()
        cid  = p.get("client_id","")
        cs   = p.get("client_secret","")
        code = p.get("code","")
        if not cid or not cs or not code:
            self.send_json({"error":"Faltan datos de Zoho."}); return
        r = self._req(
            "https://accounts.zoho.com/oauth/v2/token",
            {"grant_type":"authorization_code","client_id":cid,
             "client_secret":cs,"code":code,"redirect_uri":"https://www.zoho.com/"},
            {"Content-Type":"application/x-www-form-urlencoded"}
        )
        if not r.get("access_token"):
            self.send_json({"error":"Error Zoho: "+(r.get("error","sin token"))}); return
        creds["zoho_client_id"]      = cid
        creds["zoho_client_secret"]  = cs
        creds["zoho_refresh_token"]  = r.get("refresh_token","")
        creds["zoho_access_token"]   = r["access_token"]
        creds["zoho_token_time"]     = time.time()
        # Obtener account ID
        ar = self._req("https://mail.zoho.com/api/accounts",
            headers={"Authorization":f"Zoho-oauthtoken {r['access_token']}"})
        acc_id = ar.get("data",[{}])[0].get("accountId","")
        creds["zoho_account_id"] = acc_id
        save_creds(creds)
        self.send_json({"ok":True,"account_id":acc_id,"has_refresh":bool(r.get("refresh_token"))})

    # ── Zoho: enviar ──
    def _zoho_send(self, p):
        token, acc_id = get_zoho_token()
        if not token:
            self.send_json({"error":"Token de Zoho no disponible. Reconecta Zoho en configuracion."}); return
        payload = p.get("payload",{})
        r = self._req(
            f"https://mail.zoho.com/api/accounts/{acc_id}/messages",
            payload,
            {"Content-Type":"application/json","Authorization":f"Zoho-oauthtoken {token}"}
        )
        self.send_json(r)

    # ── Claude ──
    def _claude(self, p):
        creds = load_creds()
        api_key = p.get("api_key") or creds.get("anthropic_key","")
        print(f"  DEBUG claude - api_key presente: {bool(api_key)}, creds keys: {list(creds.keys())}")
        if not api_key:
            self.send_json({"error":"Falta la API Key de Anthropic."}); return
        r = self._req(
            "https://api.anthropic.com/v1/messages",
            p.get("body"),
            {"Content-Type":"application/json","x-api-key":api_key,"anthropic-version":"2023-06-01"}
        )
        self.send_json(r)

    # ── SendPulse: enviar ──
    def _sp_send(self, p):
        creds = load_creds()
        print(f"  SP send - sp_id: {bool(creds.get('sp_client_id'))}, sp_sec: {bool(creds.get('sp_client_secret'))}")
        msg = p.get("message") or {}
        html_len = len(msg.get("html") or "")
        text_len = len(msg.get("text") or "")
        print(f"  SP msg keys: {list(msg.keys())}")
        print(f"  SP html_len: {html_len}, text_len: {text_len}")
        if html_len > 0:
            print(f"  SP html inicio: {(msg.get('html') or '')[:80]}")
        token = get_sp_token()
        print(f"  SP token obtenido: {bool(token)}")
        if not token:
            self.send_json({"error":"SendPulse no configurado o error al obtener token."}); return
        auth_header = f"Bearer {token}"
        r = self._req(
            "https://api.sendpulse.com/smtp/emails",
            {"email": msg},
            {"Content-Type":"application/json","Authorization":auth_header}
        )
        print(f"  SP response: {str(r)[:300]}")
        self.send_json(r)


    # ── ZeptoMail: enviar ──
    def _zepto_send(self, p):
        creds = load_creds()
        api_key = creds.get("zepto_api_key","")
        if not api_key:
            self.send_json({"error":"ZeptoMail no configurado. Agrega tu API key."}); return
        to_email = p.get("to_email","")
        to_name  = p.get("to_name","")
        subject  = p.get("subject","")
        html     = p.get("html","")
        text     = p.get("text","")
        if not to_email or not html:
            self.send_json({"error":"Faltan campos requeridos (to_email, html)."}); return
        payload = {
            "from": {"address": "support@mdt.edu.pe", "name": "Equipo MDT"},
            "to": [{"email_address": {"address": to_email, "name": to_name or to_email}}],
            "subject": subject,
            "htmlbody": html,
            "textbody": text
        }
        auth = api_key if api_key.startswith("Zoho-enczapikey") else f"Zoho-enczapikey {api_key}"
        r = self._req(
            "https://api.zeptomail.com/v1.1/email",
            payload,
            {"Content-Type":"application/json","Authorization":auth}
        )
        print(f"  Zepto response: {str(r)[:300]}")
        self.send_json(r)

    # ── Banners ──
    def _banner_upload(self, p):
        """Subir banner como base64"""
        name     = p.get("name","").strip()
        b64data  = p.get("data","")
        if not name or not b64data:
            self.send_json({"error":"Faltan nombre o datos."}); return
        # Limpiar nombre de archivo
        safe = "".join(c for c in name if c.isalnum() or c in "-_.")[:80]
        if not safe: safe = secrets.token_hex(8)
        fpath = os.path.join(BANNERS_DIR, safe)
        try:
            raw = base64.b64decode(b64data.split(",")[-1])
            with open(fpath,"wb") as f:
                f.write(raw)
            url = f"/banners/{safe}"
            self.send_json({"ok":True,"url":url,"name":safe})
        except Exception as e:
            self.send_json({"error":str(e)})

    def _banner_url(self, p):
        """Guardar referencia a banner por URL externa"""
        name = p.get("name","").strip()
        url  = p.get("url","").strip()
        if not name or not url:
            self.send_json({"error":"Faltan nombre o URL."}); return
        # Guardar en credentials como referencia
        creds = load_creds()
        if "banner_urls" not in creds:
            creds["banner_urls"] = {}
        creds["banner_urls"][name] = url
        save_creds(creds)
        self.send_json({"ok":True,"url":url,"name":name})

    def _banners_list(self, p):
        """Listar todos los banners (subidos + URLs externas)"""
        result = []
        # Banners subidos
        for fname in os.listdir(BANNERS_DIR):
            fpath = os.path.join(BANNERS_DIR, fname)
            size  = os.path.getsize(fpath)
            result.append({"name":fname,"url":f"/banners/{fname}","type":"upload","size":size})
        # URLs externas
        creds = load_creds()
        for name, url in creds.get("banner_urls",{}).items():
            result.append({"name":name,"url":url,"type":"url"})
        self.send_json({"banners":result})

    def _banner_delete(self, p):
        """Eliminar banner"""
        name  = p.get("name","")
        btype = p.get("type","upload")
        if btype == "upload":
            fpath = os.path.join(BANNERS_DIR, os.path.basename(name))
            if os.path.exists(fpath):
                os.remove(fpath)
                self.send_json({"ok":True})
            else:
                self.send_json({"error":"No encontrado"})
        else:
            creds = load_creds()
            if name in creds.get("banner_urls",{}):
                del creds["banner_urls"][name]
                save_creds(creds)
            self.send_json({"ok":True})

    # ── Historial persistente ──
    def _history_save(self, p):
        entries = p.get("entries",[])
        try:
            existing = []
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE,"r") as f:
                    existing = json.load(f)
            existing.extend(entries)
            # Mantener últimos 500
            existing = existing[-500:]
            with open(HISTORY_FILE,"w") as f:
                json.dump(existing, f, ensure_ascii=False)
            self.send_json({"ok":True})
        except Exception as e:
            self.send_json({"error":str(e)})

    def _history_load(self, p):
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE,"r") as f:
                    entries = json.load(f)
            else:
                entries = []
            self.send_json({"entries":entries})
        except Exception as e:
            self.send_json({"entries":[]})

    # ── Envíos programados ──
    def _schedule_save(self, p):
        try:
            tasks = []
            if os.path.exists(SCHEDULED_FILE):
                with open(SCHEDULED_FILE,"r") as f:
                    tasks = json.load(f)
            task = {
                "id": secrets.token_hex(8),
                "created": datetime.now().isoformat(),
                "scheduled_at": p.get("scheduled_at",""),
                "tipo": p.get("tipo",""),
                "programa": p.get("programa",""),
                "subject": p.get("subject",""),
                "evento": p.get("evento",{}),
                "students": p.get("students",[]),
                "service": p.get("service","auto"),
                "status": "pending"
            }
            tasks.append(task)
            with open(SCHEDULED_FILE,"w") as f:
                json.dump(tasks, f, ensure_ascii=False, indent=2)
            self.send_json({"ok":True,"id":task["id"],"scheduled_at":task["scheduled_at"]})
        except Exception as e:
            self.send_json({"error":str(e)})

    def _schedule_list(self, p):
        try:
            if os.path.exists(SCHEDULED_FILE):
                with open(SCHEDULED_FILE,"r") as f:
                    tasks = json.load(f)
            else:
                tasks = []
            self.send_json({"tasks":tasks})
        except:
            self.send_json({"tasks":[]})

    def _schedule_delete(self, p):
        try:
            task_id = p.get("id","")
            if os.path.exists(SCHEDULED_FILE):
                with open(SCHEDULED_FILE,"r") as f:
                    tasks = json.load(f)
                tasks = [t for t in tasks if t.get("id") != task_id]
                with open(SCHEDULED_FILE,"w") as f:
                    json.dump(tasks, f, ensure_ascii=False, indent=2)
            self.send_json({"ok":True})
        except Exception as e:
            self.send_json({"error":str(e)})


    # ── WhatsApp via WATI ──
    def _wa_send(self, p):
        creds    = load_creds()
        endpoint = creds.get("wati_endpoint","").rstrip("/")
        token    = creds.get("wati_token","")
        to       = p.get("to","").replace("+","").replace(" ","").replace("-","")
        msg_type = p.get("type","text")
        if not endpoint or not token or not to:
            self.send_json({"error":"Faltan credenciales WATI (endpoint/token) o número destino."}); return
        headers = {"Content-Type":"application/json","Authorization":f"Bearer {token}"}
        if msg_type == "template":
            payload = {
                "template_name": p.get("template_name","hello_world"),
                "broadcast_name": p.get("broadcast_name","mdt_broadcast"),
                "parameters": p.get("parameters",[])
            }
            r = self._req(f"{endpoint}/api/v1/sendTemplateMessage?whatsappNumber={to}", payload, headers)
        else:
            payload = {"message": p.get("message","Hola desde MDT")}
            r = self._req(f"{endpoint}/api/v1/sendSessionMessage/{to}", payload, headers)
        self.send_json(r)

    def _wa_status(self, p):
        creds = load_creds()
        self.send_json({
            "configured": bool(creds.get("wati_endpoint") and creds.get("wati_token")),
            "endpoint": creds.get("wati_endpoint",""),
        })

# ── Scheduler en background ──
def run_scheduled_tasks():
    """Ejecuta tareas programadas en un thread separado"""
    import urllib.request, urllib.parse
    while True:
        try:
            if os.path.exists(SCHEDULED_FILE):
                with open(SCHEDULED_FILE,"r") as f:
                    tasks = json.load(f)
                now = datetime.now()
                updated = False
                for task in tasks:
                    if task.get("status") != "pending":
                        continue
                    scheduled_at = task.get("scheduled_at","")
                    if not scheduled_at:
                        continue
                    try:
                        scheduled_dt = datetime.fromisoformat(scheduled_at)
                    except:
                        continue
                    if now >= scheduled_dt:
                        print(f"  Ejecutando tarea programada: {task['id']} - {task.get('tipo','')} - {len(task.get('students',[]))} estudiantes")
                        try:
                            execute_scheduled_task(task)
                            task["status"] = "done"
                            task["executed_at"] = now.isoformat()
                            print(f"  Tarea {task['id']} completada ok")
                        except Exception as e:
                            task["status"] = "error"
                            task["error"] = str(e)
                            print(f"  Tarea {task['id']} error: {e}")
                        updated = True
                if updated:
                    with open(SCHEDULED_FILE,"w") as f:
                        json.dump(tasks, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"  Scheduler error: {e}")
        time.sleep(30)  # Revisar cada 30 segundos

def execute_scheduled_task(task):
    """Ejecuta el envío de una tarea programada"""
    students  = task.get("students",[])
    evento    = task.get("evento",{})
    service   = task.get("service","auto")
    creds     = load_creds()
    api_key   = creds.get("anthropic_key","")
    if not api_key:
        raise Exception("Falta API Key de Anthropic")
    # Generar y enviar cada correo
    ok_count  = 0
    err_count = 0
    history   = []
    for st in students:
        try:
            # Llamar a Claude
            tipo_val=task.get("tipo","comunicacion");nombre_val=st.get("n","");prog_val=st.get("p","");ev_nombre=evento.get("nombre","");ev_fecha=evento.get("fecha","");ev_hora=evento.get("hora","");ev_link=evento.get("link","")
            tipo_val=task.get("tipo","comunicacion")
            nombre_val=st.get("n",""); prog_val=st.get("p","")
            ev_nombre=evento.get("nombre",""); ev_fecha=evento.get("fecha","")
            ev_hora=evento.get("hora",""); ev_link=evento.get("link","")
            prompt = ("Correo de "+tipo_val+" para estudiante: "+nombre_val
                     +" | Programa: "+prog_val+" | Evento: "+ev_nombre
                     +" | Fecha: "+ev_fecha+" | Hora: "+ev_hora+" | Link: "+ev_link
                     +'\nJSON: {"asunto":"...","cuerpo":"..."}')
            claude_r = _req_static(
                "https://api.anthropic.com/v1/messages",
                {"model":"claude-sonnet-4-20250514","max_tokens":1000,
                 "system":"Eres asistente de MDT. Genera correos en espanol. Responde solo JSON con asunto y cuerpo.",
                 "messages":[{"role":"user","content":prompt}]},
                {"Content-Type":"application/json","x-api-key":api_key,"anthropic-version":"2023-06-01"}
            )
            text = claude_r.get("content",[{}])[0].get("text","{}").replace("```json","").replace("```","").strip()
            correo = json.loads(text)
            asunto = correo.get("asunto","Sin asunto")
            cuerpo = correo.get("cuerpo","")
            # Enviar
            zepto_key = creds.get("zepto_api_key","")
            use_zepto = (service == "zeptomail") or (service == "auto" and zepto_key and len(students) > 20)
            if use_zepto:
                if not zepto_key:
                    raise Exception("ZeptoMail no configurado")
                text_body = cuerpo  # cuerpo ya es texto plano desde Claude
                zp = {
                    "from": {"address":"support@mdt.edu.pe","name":"Equipo MDT"},
                    "to": [{"email_address":{"address":st.get("e",""),"name":st.get("n","")}}],
                    "subject": asunto,
                    "htmlbody": cuerpo,
                    "textbody": text_body
                }
                zepto_auth = zepto_key if zepto_key.startswith("Zoho-enczapikey") else f"Zoho-enczapikey {zepto_key}"
                _req_static("https://api.zeptomail.com/v1.1/email", zp,
                    {"Content-Type":"application/json","Authorization":zepto_auth})
            else:
                zoho_token, acc_id = get_zoho_token()
                if not zoho_token:
                    raise Exception("No se pudo obtener token Zoho")
                payload = {"fromAddress":"support@mdt.edu.pe","toAddress":st.get("e",""),
                           "subject":asunto,"content":cuerpo,"mailFormat":"html"}
                _req_static(f"https://mail.zoho.com/api/accounts/{acc_id}/messages",payload,
                    {"Content-Type":"application/json","Authorization":f"Zoho-oauthtoken {zoho_token}"})
            ok_count += 1
            history.append({"ts":datetime.now().isoformat(),"n":st.get("n",""),"e":st.get("e",""),"ok":True,"asunto":asunto,"tipo":task.get("tipo",""),"via":"zepto" if use_zepto else "zoho"})
        except Exception as e:
            err_count += 1
            history.append({"ts":datetime.now().isoformat(),"n":st.get("n",""),"e":st.get("e",""),"ok":False,"det":str(e),"tipo":task.get("tipo",""),"via":service})
    # Guardar historial
    if history:
        existing = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE,"r") as f:
                existing = json.load(f)
        existing.extend(history)
        existing = existing[-500:]
        with open(HISTORY_FILE,"w") as f:
            json.dump(existing, f, ensure_ascii=False)
    print(f"  Resultado: {ok_count} enviados, {err_count} errores")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    if not load_users():
        print("\n  No hay usuarios. Configura USERS_JSON en Railway.\n")
        exit(1)
    print("=" * 50)
    print("  Agente MDT Seguro v4 — Produccion")
    print("=" * 50)
    creds = load_creds()
    print(f"  Zoho:       {'Conectado' if creds.get('zoho_refresh_token') else 'Pendiente'}")
    print(f"  SendPulse:  {'Configurado' if creds.get('sp_client_id') else 'Pendiente'}")
    print(f"  ZeptoMail: {'Configurado' if creds.get('zepto_api_key') else 'Pendiente'}")
    print(f"  Anthropic:  {'Configurado' if creds.get('anthropic_key') else 'Pendiente'}")
    print(f"  URL:        http://localhost:{port}")
    print("  Ctrl+C para detener\n")
    try:
        # Iniciar scheduler en background
        scheduler_thread = threading.Thread(target=run_scheduled_tasks, daemon=True)
        scheduler_thread.start()
        print("  Scheduler: activo (revisa cada 30s)")
        server = HTTPServer(("0.0.0.0", port), Handler)
        server.serve_forever()
    except OSError as e:
        print(f"\n  Error: {e}")
