import os
import requests
from datetime import datetime, timedelta

def run_servicenow_token_generator():
    """
    Skill: servicenow-token-generator
    Adquisición segura y controlada del ciclo de vida del Bearer Token de ServiceNow.
    """
    # Lista estricta de variables de entorno requeridas
    required_vars = [
        "SERVICENOW_INSTANCE",
        "SERVICENOW_CLIENT_ID",
        "SERVICENOW_CLIENT_SECRET",
        "SERVICENOW_USERNAME",
        "SERVICENOW_PASSWORD"
    ]
    
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    # Step 1 — Validar entorno
    if missing_vars:
        return {
            "status": "BLOCKED",
            "reason": f"Missing required environment variables: {', '.join(missing_vars)}",
            "missing": missing_vars,
            "report_data": None
        }

    instance = os.environ.get("SERVICENOW_INSTANCE")
    
    # Regla de Seguridad 5: Si el token existe y sigue vigente, reutilizarlo
    existing_token = os.environ.get("SERVICENOW_ACCESS_TOKEN")
    existing_expiry = os.environ.get("SERVICENOW_TOKEN_EXPIRY")
    
    if existing_token and existing_expiry:
        try:
            expiry_dt = datetime.fromisoformat(existing_expiry.replace("Z", "+00:00"))
            # Validar si expira en más de 5 minutos (evitar degradación recomendada)
            if (expiry_dt - datetime.now(expiry_dt.tzinfo)).total_seconds() > 300:
                return {
                    "status": "OK",
                    "reused": True,
                    "report_data": {
                        "instance": f"{instance}.service-now.com",
                        "expires_at": existing_expiry,
                        "last4": existing_token[-4:] if len(existing_token) >= 4 else "****"
                    }
                }
        except:
            pass # Si el parseo falla, se fuerza la solicitud de un nuevo token

    # Step 2 — Construir la petición de Token
    url = f"https://{instance}.service-now.com/oauth_token.do"
    payload = {
        "grant_type": "password",
        "client_id": os.environ.get("SERVICENOW_CLIENT_ID"),
        "client_secret": os.environ.get("SERVICENOW_CLIENT_SECRET"),
        "username": os.environ.get("SERVICENOW_USERNAME"),
        "password": os.environ.get("SERVICENOW_PASSWORD")
    }
    
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Step 3 — Validar la respuesta y controlar errores mapeados
    try:
        res = requests.post(url, data=payload, headers=headers, timeout=15)
        
        if res.status_code == 401:
            return {
                "status": "BLOCKED",
                "reason": "HTTP 401 Unauthorized. Credentials wrong. Please verify SERVICENOW_USERNAME, SERVICENOW_PASSWORD, and SERVICENOW_CLIENT_ID."
            }
        elif res.status_code == 400:
            return {
                "status": "BLOCKED",
                "reason": "HTTP 400 Bad Request. OAuth application misconfigured. Verify grant_type and scopes in System OAuth -> Application Registry."
            }
        
        res.raise_for_status()
        data = res.json()
        
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        expires_in = int(data.get("expires_in", 0))

        if not access_token:
            return {"status": "BLOCKED", "reason": "OAuth response missing access_token field."}

        # Calcular e inyectar variables en la sesión actual de manera volátil
        expiry_timestamp = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat() + "Z"
        
        os.environ["SERVICENOW_ACCESS_TOKEN"] = access_token
        os.environ["SERVICENOW_REFRESH_TOKEN"] = refresh_token or ""
        os.environ["SERVICENOW_TOKEN_EXPIRY"] = expiry_timestamp

        # Controlar si el token expira pronto de forma preventiva (< 5 minutos)
        status = "RECOMMENDED" if expires_in < 300 else "OK"

        return {
            "status": status,
            "reused": False,
            "report_data": {
                "instance": f"{instance}.service-now.com",
                "expires_at": expiry_timestamp,
                "last4": access_token[-4:] if len(access_token) >= 4 else "****"
            }
        }

    except requests.exceptions.ConnectionError:
        return {
            "status": "BLOCKED",
            "reason": f"DNS or network error: Unable to resolve host or connect to https://{instance}.service-now.com."
        }
    except Exception as e:
        return {
            "status": "RECOMMENDED",
            "reason": f"Unrecognized exception during OAuth workflow: {str(e)}" # Nota: requests sanitiza el payload de la traza de error
        }