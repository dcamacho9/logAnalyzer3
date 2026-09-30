import re
from datetime import datetime

def run_log_report_generator(ingestion_data=None, pattern_data=None, correlation_data=None, anomaly_data=None):
    """
    Skill: log-report-generator
    Consolida evidencias de upstream skills, calcula deltas cronológicos y sanitiza datos sensibles (PII/Secrets).
    """
    evidence_notes = []
    
    # Validar presencia de evidencias (Prerequisites)
    if not ingestion_data: evidence_notes.append("Missing Evidence: log-ingestion data")
    if not pattern_data: evidence_notes.append("Missing Evidence: log-pattern-matcher data")
    if not correlation_data: evidence_notes.append("Missing Evidence: log-correlation-engine data")
    if not anomaly_data: evidence_notes.append("Missing Evidence: anomaly-detector data")

    # Inicializaciones por defecto si falta evidencia
    ingestion_data = ingestion_data or {"metadata": {}, "events": []}
    pattern_data = pattern_data or {"pattern_summary": [], "top_errors": []}
    correlation_data = correlation_data or {"chains": [], "topology": {}}
    anomaly_data = anomaly_data or {"anomalies": [], "baselines": {}}

    metadata = ingestion_data.get("metadata", {})
    anomalies = anomaly_data.get("anomalies", [])
    pattern_summary = pattern_data.get("pattern_summary", [])
    
    # --- Step 1: Determinar Estado de Salud del Sistema ---
    max_anomaly_score = max([a.get("score", 0.0) for a in anomalies]) if anomalies else 0.0
    has_resource_exhaustion = any(p.get("patternType") == "RESOURCE_EXHAUSTION" for p in pattern_summary)
    has_spikes = any(a.get("alertType") in ["ERROR_SPIKE", "LATENCY_SPIKE"] for a in anomalies)

    if max_anomaly_score >= 0.9 or has_resource_exhaustion:
        health_status = "CRITICAL"
    elif max_anomaly_score >= 0.7 or has_spikes:
        health_status = "DEGRADED"
    else:
        health_status = "HEALTHY"

    # --- Step 3: Reconstrucción de Línea de Tiempo Relativa ---
    timeline_events = []
    all_chains = correlation_data.get("chains", [])
    high_conf_anomalies = any(a.get("confidence") == "HIGH" for a in anomalies)
    has_cascading = any(c.get("status") == "FAILURE" for c in all_chains)

    if (high_conf_anomalies or has_cascading) and all_chains:
        # Extraer eventos de la cadena más crítica (o la primera con fallas)
        target_chain = next((c for c in all_chains if c.get("status") == "FAILURE"), all_chains[0])
        chain_events = target_chain.get("events", [])
        
        if chain_events:
            # Ordenar por timestamp
            chain_events = sorted(chain_events, key=lambda x: x.get("timestamp", ""))
            try:
                t0 = datetime.fromisoformat(chain_events[0]["timestamp"].replace("Z", "+00:00"))
                for e in chain_events:
                    t_current = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
                    delta_seconds = (t_current - t0).total_seconds()
                    timeline_events.append({
                        "delta": f"T+{delta_seconds:.1f}s",
                        "service": e.get("service", "unknown"),
                        "message": redact_sensitive_data(e.get("message", "")),
                        "correlationId": target_chain.get("correlationId", "N/A")
                    })
            except Exception as ex:
                evidence_notes.append(f"Timeline generation partial error: {str(ex)}")

    # --- Preparar Estructura de Salida Sanitizada ---
    sanitized_top_errors = []
    for err in pattern_data.get("top_errors", []):
        sanitized_err = err.copy()
        sanitized_err["sampleMessage"] = redact_sensitive_data(err.get("sampleMessage", ""))
        if "stackTrace" in err:
            sanitized_err["stackTrace"] = [redact_sensitive_data(line)[:120] for line in err["stackTrace"][:30]]
        sanitized_top_errors.append(sanitized_err)

    return {
        "healthStatus": health_status,
        "evidenceNotes": evidence_notes,
        "timelineEvents": timeline_events,
        "sanitizedTopErrors": sanitized_top_errors,
        "metadata": metadata,
        "patternSummary": pattern_summary[:20], # Limitar filas para evitar desborde
        "anomalies": anomalies[:5]
    }

def redact_sensitive_data(text):
    """
    Security Rules: Anonimiza Secrets, Tokens, PII (Emails, IPs v4/v6).
    """
    if not isinstance(text, str): return text
    
    # 1. Anonimizar Authorization Headers y tokens similares
    text = re.sub(r'(?i)(authorization|bearer|passwd|password|secret|apikey|token)[=:\s\'"]+([^\s\'";,]{1,4})([^\s\'";,]+)', 
                  r'\1: \2****', text)
    
    # 2. Anonimizar correos electrónicos (PII)
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', r'****@domain.com', text)
    
    # 3. Anonimizar Direcciones IP IPv4 (conservando la última sección si es necesario para depurar redes internas)
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})\b', r'xxx.xxx.xxx.\1', text)
    
    return text