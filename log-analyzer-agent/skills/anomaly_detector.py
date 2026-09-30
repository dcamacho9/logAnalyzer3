import numpy as np
import pandas as pd
from datetime import datetime, timedelta

def run_anomaly_detector(annotated_events, correlation_data=None, baseline_percent=20, anomaly_threshold=0.7):
    """
    Skill: anomaly-detector
    Implementación exacta de los pasos matemáticos y reglas de negocio del agente.
    """
    metadata = {
        "baselinePercent": baseline_percent,
        "threshold": anomaly_threshold,
        "baselineEvents": 0,
        "analysisEvents": 0,
        "anomalyCount": 0
    }
    
    if not annotated_events:
        return {"baseline_metrics": {}, "bucketed_metrics": [], "anomaly_list": [], "alert_list": [], "metadata": metadata}

    # Convertir a DataFrame y asegurar orden cronológico (ISO 8601)
    df = pd.DataFrame(annotated_events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    total_events = len(df)
    split_idx = int(total_events * (baseline_percent / 100))
    
    # Step 1 — Partition the event stream
    df_baseline = df.iloc[:split_idx].copy()
    df_analysis = df.iloc[split_idx:].copy()
    
    metadata["baselineEvents"] = len(df_baseline)
    metadata["analysisEvents"] = len(df_analysis)
    
    # Manejo de errores: Baseline insuficiente
    confidence_modifier = "NORMAL"
    if len(df_baseline) < 50:
        confidence_modifier = "REDUCED_CONFIDENCE_INSUFFICIENT_BASELINE"
        
    # Helper para extraer latencia de campos comunes
    latency_fields = ['duration', 'elapsed', 'latency', 'responseTime']
    def extract_latency(row):
        for field in latency_fields:
            if field in row and pd.notna(row[field]):
                return float(row[field])
        return np.nan

    for d in [df_baseline, df_analysis]:
        if not d.empty:
            d['latency_ms'] = d.apply(extract_latency, axis=1)

    # Step 2 — Compute baseline metrics
    def calculate_metrics(data_frame, is_baseline=False):
        if data_frame.empty:
            return {}
        total = len(data_frame)
        errors = len(data_frame[data_frame['level'] == 'ERROR'])
        warns = len(data_frame[data_frame['level'] == 'WARN'])
        timeouts = len(data_frame[data_frame['level'].str.contains('TIMEOUT', case=False, na=False)])
        
        # Agrupación por minutos para obtener el volumen
        minutes = (data_frame['timestamp'].max() - data_frame['timestamp'].min()).total_seconds() / 60
        minutes = max(minutes, 1.0)
        
        latencies = data_frame['latency_ms'].dropna()
        
        return {
            "errorRate": errors / total,
            "warnRate": warns / total,
            "timeoutRate": timeouts / total,
            "eventsPerMinute": total / minutes,
            "p50Latency_ms": float(latencies.median()) if not latencies.empty else 0.0,
            "p95Latency_ms": float(np.percentile(latencies, 95)) if not latencies.empty else 0.0,
            "_raw_latencies": latencies.tolist() if is_baseline else []
        }

    baseline_metrics = calculate_metrics(df_baseline, is_baseline=True)
    
    # Calcular desviación estándar (sigma) para Z-Score corporativo
    # Si la desviación es 0, se maneja en el Step 4/5
    df_baseline_min_buckets = df_baseline.set_index('timestamp').resample('1min').size()
    ebm_std = df_baseline_min_buckets.std() if len(df_baseline_min_buckets) > 1 else 0.0

    # Step 3 — Bucket the analysis window (1-minute buckets)
    if df_analysis.empty:
        return {"baseline_metrics": baseline_metrics, "bucketed_metrics": [], "anomaly_list": [], "alert_list": [], "metadata": metadata}
        
    df_analysis.set_index('timestamp', inplace=True)
    buckets = df_analysis.resample('1min')
    
    bucketed_metrics = []
    anomaly_list = []
    alert_list = []
    epsilon = 1e-9

    for time_bucket, frame in buckets:
        if frame.empty:
            continue
            
        b_metrics = calculate_metrics(frame.reset_index())
        b_metrics["time_start"] = time_bucket.isoformat() + "Z"
        b_metrics["time_end"] = (time_bucket + timedelta(minutes=1)).isoformat() + "Z"
        
        # Step 4 — Score each bucket (Z-Score)
        # Asumiendo distribuciones estimadas basadas en históricos o reglas fijas para tasas
        z_error = (b_metrics["errorRate"] - baseline_metrics["errorRate"]) / (baseline_metrics["errorRate"] * 0.5 + epsilon)
        z_volume = (b_metrics["eventsPerMinute"] - baseline_metrics["eventsPerMinute"]) / (ebm_std + epsilon)
        z_latency = (b_metrics["p95Latency_ms"] - baseline_metrics["p95Latency_ms"]) / (baseline_metrics["p95Latency_ms"] * 0.5 + epsilon)
        
        max_z = max(z_error, z_volume, z_latency)
        score = min(1.0, float(max(0.0, max_z) / 4))
        b_metrics["anomaly_score"] = score
        bucketed_metrics.append(b_metrics)
        
        # Step 5 — Threshold-based alert rules
        bucket_alerts = []
        if b_metrics["errorRate"] > (2 * baseline_metrics["errorRate"]) and b_metrics["errorRate"] > 0:
            bucket_alerts.append({"type": "ERROR_SPIKE", "time": b_metrics["time_start"]})
        if b_metrics["eventsPerMinute"] > (3 * baseline_metrics["eventsPerMinute"]):
            bucket_alerts.append({"type": "LOG_FLOOD", "time": b_metrics["time_start"]})
        if b_metrics["eventsPerMinute"] < (0.1 * baseline_metrics["eventsPerMinute"]):
            bucket_alerts.append({"type": "LOG_SILENCE", "time": b_metrics["time_start"]})
        if b_metrics["p95Latency_ms"] > (2 * baseline_metrics["p95Latency_ms"]) and baseline_metrics["p95Latency_ms"] > 0:
            bucket_alerts.append({"type": "LATENCY_SPIKE", "time": b_metrics["time_start"]})
            
        # Comprobación de patrones de agotamiento de recursos
        if frame.reset_index()['message'].str.contains('RESOURCE_EXHAUSTION|Out of Memory|OOM|Disk Full', case=False, na=False).any():
            bucket_alerts.append({"type": "RESOURCE_EXHAUSTION", "time": b_metrics["time_start"]})
            
        alert_list.extend(bucket_alerts)
        
        # Step 6 — Correlate anomalies with patterns and chains
        if score >= anomaly_threshold or len(bucket_alerts) > 0:
            # Extraer patrones top en esta ventana
            top_patterns = frame['patternType'].value_counts().head(3).index.tolist() if 'patternType' in frame.columns else []
            
            # Buscar correlaciones activas
            active_chains = []
            has_failure_chain = False
            if correlation_data and 'correlationId' in frame.columns:
                active_chains = frame['correlationId'].dropna().unique().tolist()
                # Intersección con cadenas caídas pasadas por el motor de correlación
                has_failure_chain = any(c.get('status') == 'FAILURE' for c in correlation_data if c.get('id') in active_chains)

            # Asignación de confianza
            confidence = "LOW"
            if score >= 0.9 and has_failure_chain:
                confidence = "HIGH"
            elif score >= 0.7 or len(bucket_alerts) > 0:
                confidence = "MEDIUM"
                
            if confidence_modifier == "REDUCED_CONFIDENCE_INSUFFICIENT_BASELINE":
                confidence = "LOW"

            anomaly_list.append({
                "time_start": b_metrics["time_start"],
                "time_end": b_metrics["time_end"],
                "score": score,
                "contributing_metrics": {
                    "errorRate": b_metrics["errorRate"],
                    "eventsPerMinute": b_metrics["eventsPerMinute"],
                    "p95Latency_ms": b_metrics["p95Latency_ms"]
                },
                "alerts_fired": [a["type"] for a in bucket_alerts],
                "top_patterns": top_patterns,
                "confidence": confidence,
                "evidence": f"Desviación estadística detectada en ventana temporal con score {score:.2f}."
            })

    # Step 7 — Rank and select top anomalies
    anomaly_list = sorted(anomaly_list, key=lambda x: x['score'], reverse=True)[:10]
    metadata["anomalyCount"] = len(anomaly_list)
    
    # Limpieza de llaves internas antes del retorno técnico
    if "_raw_latencies" in baseline_metrics: 
        del baseline_metrics["_raw_latencies"]

    return {
        "baseline_metrics": baseline_metrics,
        "bucketed_metrics": bucketed_metrics,
        "anomaly_list": anomaly_list,
        "alert_list": alert_list,
        "metadata": metadata
    }