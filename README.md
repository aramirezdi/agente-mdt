# Agente MDT — Comunicaciones

Agente de comunicaciones con IA para envío de correos personalizados desde support@mdt.edu.pe

## Archivos principales
- `server_prod.py` — servidor principal
- `index_v2.html` — interfaz de usuario
- `manage_users.py` — gestión de usuarios
- `requirements.txt` — dependencias Python

## Variables de entorno requeridas en Railway

| Variable | Descripción |
|----------|-------------|
| `ZOHO_CLIENT_ID` | Client ID de Zoho |
| `ZOHO_CLIENT_SECRET` | Client Secret de Zoho |
| `ZOHO_REFRESH_TOKEN` | Refresh Token de Zoho |
| `ZOHO_ACCOUNT_ID` | Account ID de Zoho Mail |
| `SP_CLIENT_ID` | API User ID de SendPulse |
| `SP_CLIENT_SECRET` | API Secret de SendPulse |
| `ANTHROPIC_KEY` | API Key de Anthropic |

## Uso local
```bash
python manage_users.py init
python server_prod.py
```
Abrir: http://localhost:8080
