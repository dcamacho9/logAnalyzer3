#!/usr/bin/env python
"""
AGENTE OPTIMIZADO - Versión mejorada de agent.py con streaming y caché
Cambios clave:
1. Streaming activado
2. Soporte para caché de respuestas
3. Mejor manejo de timeouts
4. Logging detallado de latencia
"""

import os
import json
import re
import requests
import hashlib
import time
from datetime import datetime
from dotenv import load_dotenv

# Importar las habilidades del directorio local skills/
from skills.log_ingestion import fetch_logs
from skills.log_pattern_matcher import run_log_pattern_matcher
from skills.servicenow_token_generator import run_servicenow_token_generator
from skills.servicenow_incident_creator import run_servicenow_incident_creator

# Cargar variables de entorno
load_dotenv()

# =====================================================
# LIMPIEZA DE TEXTO (NUEVO)
# =====================================================
def clean_text_response(text: str) -> str:
    """
    Limpia caracteres especiales y no imprimibles del texto
    - Convierte secuencias escape literales (\\n, \\r, \\t) a caracteres reales
    - Remueve caracteres de control no imprimibles
    - Normaliza espacios en blanco múltiples
    - Limpia caracteres especiales problemáticos
    """
    if not text:
        return text
    
    # Convertir secuencias escape literales a caracteres reales
    # (ej: "\n" string literal -> \n real)
    text = text.replace('\\n', '\n')
    text = text.replace('\\r', '\r')
    text = text.replace('\\t', '\t')
    text = text.replace('\\"', '"')
    
    # Remover caracteres de control no imprimibles (excepto \n, \r, \t)
    # Rango de caracteres imprimibles: 32-126 en ASCII
    text = ''.join(
        char for char in text 
        if ord(char) >= 32 or char in '\n\r\t'
    )
    
    # Reemplazar múltiples espacios en blanco con un único espacio (solo en línea, no saltos)
    lines = text.split('\n')
    lines = [re.sub(r' +', ' ', line) for line in lines]
    text = '\n'.join(lines)
    
    # Remover espacios en blanco al inicio y final de líneas
    text = '\n'.join(line.strip() for line in text.split('\n'))
    
    # Remover líneas completamente vacías múltiples (pero preservar saltos de línea simples)
    text = re.sub(r'\n\n+', '\n\n', text)
    
    return text.strip()

# =====================================================
# CACHÉ GLOBAL (NUEVO)
# =====================================================
RESPONSE_CACHE = {}
CACHE_STATS = {"hits": 0, "misses": 0}

def get_cache_key(prompt: str) -> str:
    """Generar clave de caché SHA256"""
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]

def cached_ollama_call(prompt_content: str, use_cache: bool = True) -> tuple:
    """
    Llamar a Ollama con caché opcional
    Returns: (response_text, elapsed_time, cache_hit)
    """
    cache_key = get_cache_key(prompt_content)
    
    # Verificar caché
    if use_cache and cache_key in RESPONSE_CACHE:
        print(f"[CACHE HIT] Usando respuesta cacheada (clave: {cache_key[:8]}...)")
        CACHE_STATS["hits"] += 1
        return RESPONSE_CACHE[cache_key], 0.0, True
    
    CACHE_STATS["misses"] += 1
    
    # Llamar a Ollama
    response_text, elapsed = call_ollama(prompt_content)
    
    # Limpiar caracteres especiales de la respuesta
    if response_text:
        response_text = clean_text_response(response_text)
    
    # Guardar en caché
    if use_cache and response_text:
        RESPONSE_CACHE[cache_key] = response_text
    
    return response_text, elapsed, False

# =====================================================
# CONFIGURACIÓN DE OLLAMA
# =====================================================
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434")
OLLAMA_GENERATE_URL = f"{OLLAMA_API_URL}/api/generate"
MODEL_NAME = os.getenv("OLLAMA_MODEL", "phi:2.7b")  # ✅ Cambiado a phi:2.7b (más ligero)
ENABLE_STREAMING = os.getenv("ENABLE_STREAMING", "true").lower() == "true"

print(f"[CONFIG] Modelo: {MODEL_NAME}")
print(f"[CONFIG] Streaming: {ENABLE_STREAMING}")

def parse_log_lines(raw_lines: list) -> list:
    """Convierte líneas de log en strings a diccionarios estructurados."""
    parsed_events = []
    
    for line in raw_lines:
        if not line.strip():
            continue
            
        # Intenta extraer timestamp y nivel usando regex
        match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\[(\w+)\]\s+(.*)', line)
        
        if match:
            timestamp, level, message = match.groups()
            parsed_events.append({
                "timestamp": timestamp,
                "level": level.upper(),
                "message": message,
                "rawLine": line,
                "service": "unknown"
            })
        else:
            parsed_events.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": "UNKNOWN",
                "message": line,
                "rawLine": line,
                "service": "unknown"
            })
    
    return parsed_events

def get_available_models() -> list:
    """Obtiene la lista de modelos disponibles en Ollama"""
    try:
        response = requests.get(f"{OLLAMA_API_URL}/api/tags", timeout=5)
        response.raise_for_status()
        data = response.json()
        return [m['name'] for m in data.get('models', [])]
    except Exception:
        return []

def call_ollama(prompt_content: str) -> tuple:
    """
    Envía el prompt a Ollama con streaming activado
    Returns: (response_text, elapsed_time_in_seconds)
    """
    
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt_content,
        "stream": ENABLE_STREAMING  # ✅ Streaming activado
    }
    
    start_time = time.time()
    
    try:
        print(f"[*] Enviando solicitud a Ollama ({MODEL_NAME})...")
        print(f"[*] Streaming: {ENABLE_STREAMING}")
        
        response = requests.post(
            OLLAMA_GENERATE_URL, 
            json=payload, 
            stream=ENABLE_STREAMING,
            timeout=900  # 15 minutos
        )
        response.raise_for_status()
        
        # Procesar respuesta
        if ENABLE_STREAMING:
            # Con streaming, procesar línea por línea
            full_response = ""
            first_chunk_time = None
            chunk_count = 0
            
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        chunk = data.get("response", "")
                        full_response += chunk
                        chunk_count += 1
                        
                        # Registrar tiempo del primer chunk
                        if first_chunk_time is None:
                            first_chunk_time = time.time()
                            elapsed_to_first = first_chunk_time - start_time
                            print(f"[✓] Primer chunk recibido en {elapsed_to_first:.1f}s")
                        
                        # Mostrar progreso
                        if chunk_count % 50 == 0:
                            print(f"[...] {chunk_count} chunks recibidos...")
                            
                    except json.JSONDecodeError:
                        continue
            
            elapsed = time.time() - start_time
            print(f"[✓] Respuesta completada en {elapsed:.1f}s ({chunk_count} chunks)")
            return full_response, elapsed
            
        else:
            # Sin streaming, esperar respuesta completa
            elapsed = time.time() - start_time
            response_text = response.json().get("response", "")
            # Limpiar caracteres especiales
            response_text = clean_text_response(response_text)
            print(f"[✓] Respuesta recibida en {elapsed:.1f}s")
            return response_text, elapsed
            
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        print(f"\n> [!CAUTION]")
        print(f"> **Timeout**: Ollama tardó más de 15 minutos ({elapsed:.1f}s)")
        print("> Si esto sucede frecuentemente, considera:")
        print(">   - Cambiar a un modelo más ligero (mistral:7b, phi:2.7b)")
        print(">   - Activar aceleración GPU")
        print(">   - Aumentar los recursos disponibles")
        return "", elapsed
        
    except requests.exceptions.ConnectionError:
        elapsed = time.time() - start_time
        print(f"\n> [!CAUTION]")
        print(f"> **Error de Conexión**: No se puede conectar con Ollama ({elapsed:.1f}s)")
        print(f"> Verifica que OLLAMA está corriendo: ollama serve")
        return "", elapsed
        
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"\n> [!ERROR] {e} ({elapsed:.1f}s)")
        return "", elapsed

def print_cache_stats():
    """Mostrar estadísticas de caché"""
    total = CACHE_STATS["hits"] + CACHE_STATS["misses"]
    if total > 0:
        hit_rate = (CACHE_STATS["hits"] / total) * 100
        print(f"\n[CACHE STATS] Hits: {CACHE_STATS['hits']} | Misses: {CACHE_STATS['misses']} | Tasa: {hit_rate:.1f}%")

def main():
    """Función principal del agente"""
    print("=" * 60)
    print(" Creando Sesión de Diagnóstico Automático e Integración ITSM ")
    print("=" * 60)

    # -------------------------------------------------------------------------
    # STEP 1: Ingesta de Logs (Skill 1)
    # -------------------------------------------------------------------------
    print("\n[1/4] Ingestando trazas desde la fuente de datos...")
    raw_log_lines = fetch_logs(source_id="prod-k8s-cluster", limit=100)
    
    if not raw_log_lines:
        print("[-] No se recuperaron logs. Abortando pipeline.")
        return
    
    raw_logs = parse_log_lines(raw_log_lines)

    # -------------------------------------------------------------------------
    # STEP 2: Análisis Sintáctico y Extracción de Patrones (Skill 2)
    # -------------------------------------------------------------------------
    print("[2/4] Ejecutando log-pattern-matcher...")
    pattern_result = run_log_pattern_matcher(raw_logs)
    annotated_events = pattern_result.get("annotated_events", [])
    correlation_data = {
        "pattern_summary": pattern_result.get("pattern_summary", []),
        "top_errors": pattern_result.get("top_errors", [])
    }
    
    # Construir prompt
    prompt_for_llm = f"""
Analice los siguientes eventos anotados y genere el Reporte Diagnóstico Causa-Raíz.

Eventos Anotados (JSON):
{json.dumps(annotated_events, indent=2)}

Datos de Correlación:
{json.dumps(correlation_data, indent=2)}
"""

    # -------------------------------------------------------------------------
    # STEP 3: Inferencia en Ollama (con caché activado)
    # -------------------------------------------------------------------------
    print("[3/4] Invocando inteligencia local en Ollama...")
    diagnostic_report, elapsed, cache_hit = cached_ollama_call(prompt_for_llm, use_cache=True)
    
    if cache_hit:
        print("[CACHE] Resultado obtenido desde caché")
    else:
        print(f"[TIMING] Tiempo total OLLAMA: {elapsed:.1f} segundos")
    
    if not diagnostic_report:
        print("[-] Falló la generación del diagnóstico.")
        return
        
    # Imprimir el reporte
    print("\n" + "=" * 20 + " REPORTE DIAGNÓSTICO " + "=" * 20)
    print(diagnostic_report)
    print("=" * 61 + "\n")

    # -------------------------------------------------------------------------
    # STEP 4: Integración Operacional con ServiceNow
    # -------------------------------------------------------------------------
    print("[4/4] Inicializando pasarela operacional ServiceNow...")
    
    auth_result = run_servicenow_token_generator()
    
    if auth_result["status"] == "BLOCKED":
        print(f"\n> [!CAUTION] {auth_result['reason']}")
        return
    
    token_data = auth_result["report_data"]
    print(f"\n## ServiceNow Token")
    print(f"| Field | Value |")
    print(f"|-------|-------|")
    print(f"| Instance | {token_data['instance']} |")
    print(f"| Expires at (UTC) | {token_data['expires_at']} |")
    print("-" * 60)

    # Crear incidentes si está habilitado
    if os.environ.get("SERVICENOW_CREATE_INCIDENTS", "false").lower() == "true":
        print("\nProcesando apertura automatizada de incidentes...")
        incident_result = run_servicenow_incident_creator(
            annotated_events=annotated_events,
            correlation_data=correlation_data,
            dedup_mode="pattern",
            log_source="prod-k8s-cluster",
            time_range="Últimos 15 minutos"
        )
    
    # Mostrar estadísticas
    print_cache_stats()
    print("\n[✓] Pipeline completado exitosamente")

if __name__ == "__main__":
    main()
