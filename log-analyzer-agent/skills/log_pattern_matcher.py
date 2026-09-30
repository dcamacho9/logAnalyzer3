import re
import pandas as pd
from datetime import datetime

def run_log_pattern_matcher(event_stream, custom_patterns=None):
    """
    Skill: log_pattern_matcher
    Clasificación semántica basada en Regex y agrupación de firmas de error.
    """
    if not event_stream:
        return {"annotated_events": [], "pattern_summary": [], "top_errors": [], "status": "OK"}

    annotated_events = []
    
    # Pre-compilar expresiones regulares para rendimiento
    regex_http = re.compile(r'(?:HTTP\s+([45]\d\d)|status[= ]([2345]\d\d))', re.IGNORECASE)
    regex_timeout = re.compile(r'(?i)(timeout|timed.?out|connection reset|read timeout|socket timeout)')
    regex_exception = re.compile(r'(?i)(exception|error):\s+(\S+)')
    regex_db = re.compile(r'(?i)(sql.*error|ora-\d+|connection.*refused|deadlock|lock.*wait.*timeout|too many connections)')
    regex_auth = re.compile(r'(?i)(401|403|unauthori[sz]ed|forbidden|invalid.*token|token.*expired|authentication.*failed)')
    regex_resource = re.compile(r'(?i)(out of memory|heap space|gc overhead|too many open files|connection pool exhausted|max.*connections.*reached)')
    regex_start = re.compile(r'(?i)(started|starting|listening on|server.*up|application.*started)')
    regex_stop = re.compile(r'(?i)(stopped|stopping|shutdown|terminated|killed)')
    regex_stack = re.compile(r'^\s+at\s+')

    # Cargar patrones personalizados si existen
    compiled_custom = {}
    if custom_patterns:
        for p_type, pattern_str in custom_patterns.items():
            try:
                compiled_custom[p_type] = re.compile(pattern_str)
            except Exception as e:
                print(f"[RECOMMENDED] Invalid custom regex rule [{p_type}]: {str(e)}")

    # Step 1 & 2 — Classification and Pattern extraction
    parent_exception_event = None
    
    for idx, raw_evt in enumerate(event_stream):
        evt = raw_evt.copy()
        msg = evt.get("message", "")
        raw_line = evt.get("rawLine", "")
        
        # Mapeo de Niveles (Step 1)
        lvl = str(evt.get("level", "UNKNOWN")).upper()
        if lvl in ['ERROR', 'FATAL', 'CRITICAL', 'SEVERE']:
            evt["category"] = "ERROR"
        elif lvl in ['WARN', 'WARNING']:
            evt["category"] = "WARN"
        elif lvl in ['INFO']:
            evt["category"] = "INFO"
        elif lvl in ['DEBUG', 'TRACE']:
            evt["category"] = "DEBUG"
        else:
            evt["category"] = "UNKNOWN"

        # Detección de Stack Traces multilínea (Step 2.3)
        if regex_stack.match(msg) or regex_stack.match(raw_line):
            if parent_exception_event:
                if "stackTrace" not in parent_exception_event:
                    parent_exception_event["stackTrace"] = []
                parent_exception_event["stackTrace"].append(msg.strip())
                continue # Omitir inserción como evento independiente para consolidarlo en el padre
        
        # Evaluación de patrones
        pattern_type = "UNKNOWN"
        http_code = None
        exception_class = None

        # Evaluar patrones personalizados primero (Tienen prioridad)
        custom_matched = False
        for p_type, r_comp in compiled_custom.items():
            if r_comp.search(msg) or r_comp.search(raw_line):
                pattern_type = p_type
                custom_matched = True
                break

        if not custom_matched:
            # Evaluar HTTP
            match_http = regex_http.search(msg) or regex_http.search(raw_line)
            if match_http:
                code = match_http.group(1) or match_http.group(2)
                http_code = int(code)
                if code.startswith(('4', '5')): pattern_type = "HTTP_ERROR"
                elif code.startswith('2'): pattern_type = "HTTP_SUCCESS"
                elif code.startswith('3'): pattern_type = "HTTP_REDIRECT"
            
            # Evaluar el resto de patrones embebidos
            elif regex_timeout.search(msg) or regex_timeout.search(raw_line):
                pattern_type = "TIMEOUT"
            elif regex_exception.search(msg) or regex_exception.search(raw_line):
                pattern_type = "EXCEPTION"
                match_ex = regex_exception.search(msg) or regex_exception.search(raw_line)
                exception_class = match_ex.group(2)
            elif regex_db.search(msg) or regex_db.search(raw_line):
                pattern_type = "DB_ERROR"
            elif regex_auth.search(msg) or regex_auth.search(raw_line):
                pattern_type = "AUTH_FAILURE"
            elif regex_resource.search(msg) or regex_resource.search(raw_line):
                pattern_type = "RESOURCE_EXHAUSTION"
            elif regex_start.search(msg) or regex_start.search(raw_line):
                pattern_type = "SERVICE_START"
            elif regex_stop.search(msg) or regex_stop.search(raw_line):
                pattern_type = "SERVICE_STOP"

        # Enriquecer el evento
        evt["patternType"] = pattern_type
        if http_code: evt["httpStatusCode"] = http_code
        if exception_class: evt["exceptionClass"] = exception_class
        evt["lineOffset"] = idx + 1 # Guardar referencia de línea

        annotated_events.append(evt)
        
        # Rastrear el último evento de excepción para anexarle líneas de tipo 'at ...'
        if pattern_type == "EXCEPTION":
            parent_exception_event = evt
        else:
            parent_exception_event = None

    # Step 3 — Frequency aggregation
    df_ann = pd.DataFrame(annotated_events)
    
    # Rellenar campos opcionales para evitar problemas de agrupación por valores nulos
    for col in ["exceptionClass", "httpStatusCode"]:
        if col not in df_ann.columns: df_ann[col] = None
    df_ann["exceptionClass"] = df_ann["exceptionClass"].fillna("None")
    df_ann["httpStatusCode"] = df_ann["httpStatusCode"].fillna("None")
    
    group_cols = ["patternType", "exceptionClass", "httpStatusCode", "service"]
    grouped = df_ann.groupby(group_cols)
    
    pattern_summary = []
    for keys, group in grouped:
        p_type, ex_class, h_code, srv = keys
        group_sorted = group.sort_values("timestamp")
        
        record = {
            "patternType": p_type,
            "exceptionClass": None if ex_class == "None" else ex_class,
            "httpStatusCode": None if h_code == "None" else int(h_code),
            "service": srv,
            "count": len(group),
            "firstOccurrence": group_sorted.iloc[0]["timestamp"],
            "lastOccurrence": group_sorted.iloc[-1]["timestamp"],
            "sampleMessage": group_sorted.iloc[0]["message"]
        }
        pattern_summary.append(record)
        
    pattern_summary = sorted(pattern_summary, key=lambda x: x["count"], reverse=True)

    # Step 4 — Extract top errors
    errors_df = df_ann[df_ann["category"] == "ERROR"]
    top_errors = []
    
    if not errors_df.empty:
        # Volvemos a agrupar por campos firma para no repetir el mismo log idéntico
        error_groups = errors_df.groupby(group_cols)
        error_records = []
        for keys, group in error_groups:
            p_type, ex_class, h_code, srv = keys
            group_sorted = group.sort_values("timestamp")
            
            sample_evt = group_sorted.iloc[0]
            error_records.append({
                "count": len(group),
                "service": srv,
                "firstTimestamp": group_sorted.iloc[0]["timestamp"],
                "lastTimestamp": group_sorted.iloc[-1]["timestamp"],
                "sampleMessage": sample_evt["message"],
                "stackTrace": sample_evt.get("stackTrace", []),
                "lineReference": int(sample_evt["lineOffset"])
            })
        
        top_errors = sorted(error_records, key=lambda x: x["count"], reverse=True)[:10]

    status = "OK" if any(e["patternType"] != "UNKNOWN" for e in annotated_events) else "PARTIAL"

    return {
        "annotated_events": annotated_events,
        "pattern_summary": pattern_summary,
        "top_errors": top_errors,
        "status": status
    }