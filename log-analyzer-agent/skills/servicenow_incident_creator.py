import os
import re
import json
import hashlib
import requests
from datetime import datetime

def run_servicenow_incident_creator(annotated_events, correlation_data=None, dedup_mode="pattern", log_source="unknown", time_range="unknown"):
    """
    Skill: servicenow-incident-creator
    Orquestación, deduplicación y apertura automatizada de incidentes en ServiceNow vía Table API.
    """
    # Verificación de Activación (Activation & CLI rules)
    create_incidents_flag = os.environ.get("SERVICENOW_CREATE_INCIDENTS", "false").lower() == "true"
    if not create_incidents_flag:
        return {"status": "INFO", "reason": "Incident creation is off by default. Set SERVICENOW_CREATE_INCIDENTS='true' to enable.", "incidents": [], "stats": {}}

    # --- Step 1: Validar Prerrequisitos de Seguridad e Infraestructura ---
    instance = os.environ.get("SERVICENOW_INSTANCE")
    access_token = os.environ.get("SERVICENOW_ACCESS_TOKEN")
    token_expiry_str = os.environ.get("SERVICENOW_TOKEN_EXPIRY") # Formato ISO u Epoch

    if not instance or not access_token:
        missing_var = "SERVICENOW_INSTANCE" if not instance else "SERVICENOW_ACCESS_TOKEN"
        return {"status": "BLOCKED", "reason": f"Missing required environment variable: {missing_var}. Run servicenow-token-generator first.", "incidents": [], "stats": {}}

    if token_expiry_str:
        try:
            # Validación estricta: Expiración debe ser > 1 minuto en el futuro
            expiry = datetime.fromisoformat(token_expiry_str.replace("Z", "+00:00"))
            time_left = (expiry - datetime.now(expiry.tzinfo)).total_seconds()
            if time_left < 60:
                return {"status": "BLOCKED", "reason": "SERVICENOW_ACCESS_TOKEN expired or expiring within 1 minute. Re-run servicenow-token-generator.", "incidents": [], "stats": {}}
        except:
            pass # Si el formato no es parseable, se continúa bajo reintentos del bloque HTTP 401

    # --- Step 2: Extraer Eventos de tipo ERROR ---
    error_levels = {'ERROR', 'FATAL', 'CRITICAL', 'SEVERE'}
    error_events = [e for e in annotated_events if str(e.get("category", e.get("level", ""))).upper() in error_levels]

    if not error_events:
        return {"status": "INFO", "reason": "No ERROR events detected — no incidents created.", "incidents": [], "stats": {}}

    # --- Step 3: Agrupación de errores por Modo de Deduplicación ---
    incident_groups = []

    if dedup_mode == "pattern":
        # Agrupación por (patternType, service, errorSignature)
        groups_map = {}
        for e in error_events:
            msg = e.get("message", "")
            # Normalizar los primeros 80 caracteres de la firma del mensaje
            sig = re.sub(r'\s+', ' ', msg[:80]).strip().lower()
            key = (e.get("patternType", "UNKNOWN"), e.get("service", "unknown"), sig)
            
            if key not in groups_map:
                groups_map[key] = []
            groups_map[key].append(e)
            
        for key, evts in groups_map.items():
            evts_sorted = sorted(evts, key=lambda x: x.get("timestamp", ""))
            # Obtener traza con mayor frecuencia o la primera disponible
            stack_evt = next((x for x in evts if x.get("stackTrace")), evts_sorted[0])
            
            incident_groups.append({
                "patternType": key[0],
                "service": key[1],
                "errorSignature": key[2] or "generic error message signature",
                "count": len(evts),
                "firstOccurrence": evts_sorted[0]["timestamp"],
                "lastOccurrence": evts_sorted[-1]["timestamp"],
                "sampleMessage": evts_sorted[0]["message"],
                "stackTrace": stack_evt.get("stackTrace", [])
            })

    elif dedup_mode == "chain" and correlation_data:
        # Agrupación por cadenas de falla (correlationId)
        chains_map = {}
        fallback_events = []
        
        # Mapear IDs válidos desde log-correlation-engine
        failed_chain_ids = {c["correlationId"] for c in correlation_data.get("chains", []) if c.get("status") == "FAILURE"}
        
        for e in error_events:
            c_id = e.get("correlationId")
            if c_id and c_id in failed_chain_ids:
                if c_id not in chains_map: chains_map[c_id] = []
                chains_map[c_id].append(e)
            else:
                fallback_events.append(e)
                
        for c_id, evts in chains_map.items():
            evts_sorted = sorted(evts, key=lambda x: x.get("timestamp", ""))
            incident_groups.append({
                "patternType": evts_sorted[0].get("patternType", "UNKNOWN"),
                "service": evts_sorted[0].get("service", "unknown"),
                "errorSignature": f"Cascading failure chain: {c_id}",
                "count": len(evts),
                "firstOccurrence": evts_sorted[0]["timestamp"],
                "lastOccurrence": evts_sorted[-1]["timestamp"],
                "sampleMessage": f"Chain failure with {len(evts)} affected events.",
                "stackTrace": [],
                "correlationId": c_id
            })
        # Si hay eventos sin ID de correlación, se procesan recursivamente bajo modo pattern
        if fallback_events:
            fallback_res = run_servicenow_incident_creator(fallback_events, None, "pattern", log_source, time_range)
            incident_groups.extend(fallback_res.get("groups_raw", []))

    elif dedup_mode == "all":
        # Sin agrupación: Cada evento genera un incidente independiente
        for idx, e in enumerate(error_events):
            incident_groups.append({
                "patternType": e.get("patternType", "UNKNOWN"),
                "service": e.get("service", "unknown"),
                "errorSignature": re.sub(r'\s+', ' ', e.get("message", "")[:80]).strip().lower(),
                "count": 1,
                "firstOccurrence": e["timestamp"],
                "lastOccurrence": e["timestamp"],
                "sampleMessage": e["message"],
                "stackTrace": e.get("stackTrace", [])
            })

    # --- Step 4 & 5: Mapeo de campos y ejecución contra Table API ---
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    })
    
    base_url = f"https://{instance}.service-now.com/api/now/table/incident"
    created_incidents = []
    skipped_duplicates = 0
    
    category = os.environ.get("SERVICENOW_INCIDENT_CATEGORY", "Software")
    assignment_group = os.environ.get("SERVICENOW_ASSIGNMENT_GROUP")

    for group in incident_groups:
        # Calcular ID de correlación determinista (SHA-256 prefix)
        string_token = f"{group['patternType']}|{group['service']}|{group['errorSignature']}"
        correlation_id = hashlib.sha256(string_token.encode('utf-8')).hexdigest()[:16]
        
        # 5.1 Duplicate Check (Evitar duplicación de incidentes abiertos state != 6)
        check_query = f"correlation_id={correlation_id}^state!=6"
        check_url = f"{base_url}?sysparm_query={requests.utils.quote(check_query)}&sysparm_fields=number,sys_id,state&sysparm_limit=1"
        
        try:
            check_res = session.get(check_url, timeout=15)
            if check_res.status_code == 401:
                return {"status": "BLOCKED", "reason": "HTTP 401 Unauthorized against ServiceNow API. Invalid credentials.", "incidents": created_incidents}
            
            check_res.raise_for_status()
            existing_records = check_res.json().get("result", [])
            
            if existing_records:
                # Duplicado encontrado, se descarta la creación
                skipped_duplicates += 1
                created_incidents.append({
                    "number": existing_records[0]["number"],
                    "sys_id": existing_records[0]["sys_id"],
                    "urgency": "Skipped (Duplicate)",
                    "patternType": group["patternType"],
                    "service": group["service"],
                    "firstOccurrence": group["firstOccurrence"],
                    "isDuplicate": True
                })
                continue
        except Exception as ex:
            # Fallback si falla el check: Se continúa con el flujo para priorizar la alerta
            pass

        # 5.2 Calcular Urgencia (Urgency Mapping)
        p_type = group["patternType"]
        if p_type in ["RESOURCE_EXHAUSTION", "AUTH_FAILURE"]:
            urgency_val = "1" # Critical
        elif p_type in ["DB_ERROR", "TIMEOUT", "EXCEPTION", "HTTP_ERROR"]:
            urgency_val = "2" # High
        else:
            urgency_val = "3" # Medium

        # Sanitizar PII de descripciones siguiendo las reglas globales
        clean_msg = redact_pii(group["sampleMessage"])
        clean_stack = "\n".join([redact_pii(line) for line in group["stackTrace"]]) if group["stackTrace"] else "None"

        # Construcción del Payload contractual
        payload = {
            "short_description": f"[{p_type}] {group['service']}: {group['errorSignature']}"[:160],
            "description": f"Message: {clean_msg}\nStack: {clean_stack}\nSource: {log_source}\nRange: {time_range}",
            "urgency": urgency_val,
            "impact": urgency_val,
            "category": category,
            "correlation_id": correlation_id,
            "work_notes": f"Auto-created by log-analyzer. Source: {log_source}. Range: {time_range}."
        }
        if assignment_group:
            payload["assignment_group"] = assignment_group

        # Envío del POST (Creación del Ticket)
        try:
            res = session.post(base_url, json=payload, timeout=20)
            
            if res.status_code == 429:
                # Regla de reintento ante Rate Limit (HTTP 429)
                retry_after = int(res.headers.get("Retry-After", 5))
                import time
                time.sleep(min(retry_after, 30))
                res = session.post(base_url, json=payload, timeout=20)

            res.raise_for_status()
            res_data = res.json().get("result", {})
            
            created_incidents.append({
                "number": res_data.get("number", "UNKNOWN"),
                "sys_id": res_data.get("sys_id"),
                "urgency": f"{urgency_val} (Mapped)",
                "patternType": p_type,
                "service": group["service"],
                "firstOccurrence": group["firstOccurrence"],
                "isDuplicate": False
            })
        except Exception as e:
            # Reportar fallas parciales sin abortar el resto de la cola (HTTP 5xx / 400 mitigation)
            created_incidents.append({
                "number": "FAILED_TO_CREATE",
                "sys_id": None,
                "urgency": "ERROR",
                "patternType": p_type,
                "service": group["service"],
                "firstOccurrence": group["firstOccurrence"],
                "isDuplicate": False,
                "errorDetails": str(e)
            })

    # Estadísticas para el reporte final
    stats = {
        "dedupMode": dedup_mode,
        "totalErrorsProcessed": len(error_events),
        "groupsCreated": len(incident_groups),
        "duplicatesSkipped": skipped_duplicates
    }

    return {"status": "OK", "incidents": created_incidents, "stats": stats, "groups_raw": incident_groups}

def redact_pii(text):
    if not isinstance(text, str): return text
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', r'****@domain.com', text) # Emails
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})\b', r'xxx.xxx.xxx.\1', text) # IPs
    return text