import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def run_log_correlation_engine(annotated_events, trace_id_field=None):
    """
    Skill: log-correlation-engine
    Mapeo algorítmico y matemático de correlación de trazas cross-service.
    """
    metadata = {
        "correlationAvailable": False,
        "totalChains": 0,
        "failureChains": 0,
        "avgDuration_ms": 0.0,
        "lowCoverageFlag": False,
        "clockSkewDetected": False
    }
    
    if not annotated_events:
        return {"correlation_chains": [], "cascading_failures": [], "multi_service_outages": [], "service_topology": {}, "metadata": metadata}

    df = pd.DataFrame(annotated_events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Step 1 — Identify correlation key
    candidate_keys = ['trace_id', 'traceId', 'request_id', 'requestId', 'req_id', 'correlation_id', 'correlationId', 'session_id', 'sessionId', 'x-request-id']
    
    selected_key = None
    if trace_id_field and trace_id_field in df.columns:
        selected_key = trace_id_field
    else:
        for key in candidate_keys:
            if key in df.columns and df[key].notna().any():
                selected_key = key
                break
                
    if not selected_key:
        # Error handling: No correlation field found
        return {"correlation_chains": [], "cascading_failures": [], "multi_service_outages": [], "service_topology": {}, "metadata": metadata}
        
    metadata["correlationAvailable"] = True
    
    # Error handling: Evaluar cobertura (< 10%)
    valid_keys_count = df[selected_key].notna().sum()
    if (valid_keys_count / len(df)) < 0.10:
        metadata["lowCoverageFlag"] = True

    # Filtrar eventos con llave válida y agrupar
    df_valid = df[df[selected_key].notna()].copy()
    
    # Check simple de clock-skew (si los logs ya vienen con inconsistencias de secuencia lógica)
    # Para fines del script, ordenamos estrictamente cronológico
    df_valid = df_valid.sort_values('timestamp')

    grouped = df_valid.groupby(selected_key)
    
    correlation_chains = []
    cascading_failures = []
    
    edges_failed = {} # Para topología
    durations = []
    
    # Step 2 & 3 — Group events by correlation ID and Build chains
    for cid, group in grouped:
        group = group.sort_values('timestamp')
        services_in_chain = group['service'].dropna().unique().tolist()
        
        # Determinar Outcome
        has_explicit_error = group['level'].isin(['ERROR', 'CRITICAL']).any() or group['message'].str.contains('EXCEPTION', case=False, na=False).any()
        has_partial_indicators = group['message'].str.contains('TIMEOUT|HTTP 4|HTTP 5', case=False, na=False).any()
        
        if has_explicit_error:
            outcome = "FAILURE"
        elif has_partial_indicators:
            outcome = "PARTIAL"
        else:
            outcome = "SUCCESS"
            
        first_event = group.iloc[0]
        last_event = group.iloc[-1]
        duration_ms = int((last_event['timestamp'] - first_event['timestamp']).total_seconds() * 1000)
        durations.append(duration_ms)
        
        events_list = []
        for _, row in group.iterrows():
            events_list.append({
                "timestamp": row['timestamp'].isoformat() + "Z",
                "service": row['service'],
                "patternType": row.get('patternType', 'UNKNOWN'),
                "message": row['message'],
                "level": row['level']
            })
            
        chain_record = {
            "correlationId": str(cid),
            "outcome": outcome,
            "services": services_in_chain,
            "duration_ms": duration_ms,
            "events": events_list,
            "firstEvent": first_event['timestamp'].isoformat() + "Z",
            "lastEvent": last_event['timestamp'].isoformat() + "Z"
        }
        
        correlation_chains.append(chain_record)
        
        if outcome == "FAILURE":
            metadata["failureChains"] += 1
            
            # Step 4 — Detect inter-service failures (Cascading)
            error_events = group[(group['level'].isin(['ERROR', 'CRITICAL'])) | (group['message'].str.contains('EXCEPTION', case=False, na=False))]
            if not error_events.empty:
                origin_failure = error_events.iloc[0]
                origin_service = origin_failure['service']
                origin_time = origin_failure['timestamp']
                
                downstream_failures = []
                affected_services = {origin_service}
                
                for _, err_row in error_events.iloc[1:].iterrows():
                    if err_row['service'] != origin_service:
                        lag = int((err_row['timestamp'] - origin_time).total_seconds() * 1000)
                        downstream_failures.append({
                            "service": err_row['service'],
                            "lag_ms": lag,
                            "patternType": err_row.get('patternType', 'UNKNOWN')
                        })
                        affected_services.add(err_row['service'])
                        
                        # Guardar aristas para la topología (Origen -> Destino impactado)
                        edge = f"{origin_service} --> {err_row['service']}"
                        edges_failed[edge] = edges_failed.get(edge, 0) + 1
                
                if len(affected_services) >= 2 and any(d['lag_ms'] <= 10000 for d in downstream_failures):
                    cascading_failures.append({
                        "correlationId": str(cid),
                        "originService": origin_service,
                        "originTimestamp": origin_time.isoformat() + "Z",
                        "downstreamFailures": downstream_failures
                    })

    # Step 5 — Temporal analysis (Multi-service outage & Lag)
    # Gaps de procesamiento > 5 minutos en una misma cadena
    for chain in correlation_chains:
        evs = chain["events"]
        if len(evs) > 1:
            for i in range(len(evs) - 1):
                t1 = datetime.fromisoformat(evs[i]["timestamp"].replace("Z", ""))
                t2 = datetime.fromisoformat(evs[i+1]["timestamp"].replace("Z", ""))
                if (t2 - t1).total_seconds() > 300:
                    chain["processingLagFlag"] = True

    # Fallos simultáneos: 3 o más servicios en una ventana de 30 segundos
    errors_df = df_valid[df_valid['level'].isin(['ERROR', 'CRITICAL'])].copy()
    multi_service_outages = []
    
    if not errors_df.empty:
        errors_df = errors_df.sort_values('timestamp')
        for idx, row in errors_df.iterrows():
            window_start = row['timestamp']
            window_end = window_start + timedelta(seconds=30)
            window_events = errors_df[(errors_df['timestamp'] >= window_start) & (errors_df['timestamp'] <= window_end)]
            distinct_services = window_events['service'].dropna().unique()
            
            if len(distinct_services) >= 3:
                window_id = f"{window_start.isoformat()}Z/{window_end.isoformat()}Z"
                if not any(w["window"] == window_id for w in multi_service_outages):
                    multi_service_outages.append({
                        "window": window_id,
                        "servicesAffected": distinct_services.tolist(),
                        "errorCount": len(window_events)
                    })

    # Step 6 — Service topology summary
    sorted_edges = sorted(edges_failed.items(), key=lambda x: x[1], reverse=True)[:5]
    topology_summary = {edge: f"[{count} failures]" for edge, count in sorted_edges}

    metadata["totalChains"] = len(correlation_chains)
    if durations:
        metadata["avgDuration_ms"] = float(np.mean(durations))

    return {
        "correlation_chains": correlation_chains,
        "cascading_failures": cascading_failures,
        "multi_service_outages": multi_service_outages[:5], # Top 5 ventanas críticas
        "service_topology": topology_summary,
        "metadata": metadata
    }