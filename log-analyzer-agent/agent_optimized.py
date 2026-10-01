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
import truststore

truststore.inject_into_ssl()

import requests
import hashlib
import time
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path

# Cargar variables de entorno - intentar .env.production primero, luego .env
# Función auxiliar para cargar .env con manejo robusto de encoding
def load_env_safe(env_file):
    """Carga archivo .env con manejo robusto de encoding"""
    try:
        # Intentar primero con UTF-8
        load_dotenv(env_file, encoding='utf-8')
        return True
    except UnicodeDecodeError:
        try:
            # Si falla, intentar con latin-1 que puede leer cualquier byte
            load_dotenv(env_file, encoding='latin-1')
            return True
        except Exception as e:
            print(f"[CONFIG] ✗ Error cargando {env_file}: {e}")
            return False

env_files = [
    Path(".env.production"),  # Producción con autenticación
    Path(".env"),              # Desarrollo local
]

for env_file in env_files:
    if env_file.exists():
        if load_env_safe(env_file):
            print(f"[CONFIG] ✓ Variables de entorno cargadas desde: {env_file.name}")
            break
else:
    # Si no hay archivos .env, advertir pero continuar con defaults
    print(f"[CONFIG] ⚠ No se encontraron archivos .env, usando valores por defecto")
    try:
        load_dotenv(encoding='utf-8')  # Cargar variables del sistema si existen
    except:
        load_dotenv()  # Fallback sin encoding especificado

# Importar las habilidades del directorio local skills/
from skills.log_ingestion import fetch_logs
from skills.log_pattern_matcher import run_log_pattern_matcher
from skills.servicenow_token_generator import run_servicenow_token_generator
from skills.servicenow_incident_creator import run_servicenow_incident_creator

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
# CACHÉ GLOBAL MEJORADO (OPTIMIZADO)
# =====================================================
RESPONSE_CACHE = {}
CACHE_STATS = {"hits": 0, "misses": 0, "partial_hits": 0}
CACHE_MAX_SIZE = 500  # Máximo 500 entradas en caché

def normalize_prompt(prompt: str) -> str:
    """
    ⚡ NUEVO: Normalizar prompt para mejor matching
    - Remover espacios extra
    - Converter números/timestamps a placeholders
    - Simplificar estructura JSON
    """
    import re
    # Normalizar espacios
    prompt = re.sub(r'\s+', ' ', prompt)
    # Reemplazar números y timestamps con placeholder
    prompt = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', prompt)
    prompt = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', prompt)
    prompt = re.sub(r'\b\d+\b', 'NUM', prompt)
    return prompt.lower()[:500]  # Limitar a 500 chars normalizados

def get_cache_key(prompt: str) -> str:
    """
    ⚡ MEJORADO: Generar clave de caché
    Usa prompt normalizado para mejor matching
    """
    normalized = normalize_prompt(prompt)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]

def cached_ollama_call(prompt_content: str, use_cache: bool = True) -> tuple:
    """
    ⚡ MEJORADO: Llamar a Ollama con caché inteligente
    Returns: (response_text, elapsed_time, cache_hit)
    """
    cache_key = get_cache_key(prompt_content)
    
    # Verificar caché exacto
    if use_cache and cache_key in RESPONSE_CACHE:
        cached_response = RESPONSE_CACHE[cache_key]
        print(f"[CACHE HIT] Respuesta cacheada en {len(RESPONSE_CACHE)}")
        CACHE_STATS["hits"] += 1
        return cached_response, 0.0, True
    
    CACHE_STATS["misses"] += 1
    
    # Llamar a Ollama
    response_text, elapsed = call_ollama(prompt_content)
    
    # Limpiar caracteres especiales de la respuesta
    if response_text:
        response_text = clean_text_response(response_text)
    
    # Guardar en caché (con límite de tamaño)
    if use_cache and response_text:
        if len(RESPONSE_CACHE) >= CACHE_MAX_SIZE:
            # Remover entrada más antigua (FIFO simple)
            oldest_key = next(iter(RESPONSE_CACHE))
            del RESPONSE_CACHE[oldest_key]
        RESPONSE_CACHE[cache_key] = response_text
    
    return response_text, elapsed, False

# =====================================================
# CONFIGURACIÓN DE OLLAMA (CON SOPORTE CLOUD)
# =====================================================
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "https://api.ollama.com")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")  # Para OLLAMA Cloud
OLLAMA_GENERATE_URL = f"{OLLAMA_API_URL}/api/generate"
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.2:1b:cloud")  # ✅ Cambiado a phi:2.7b (más ligero)
ENABLE_STREAMING = os.getenv("ENABLE_STREAMING", "true").lower() == "true"
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "90"))
LAST_OLLAMA_ERROR = {"message": None}

# Validar configuración
def _validate_ollama_config():
    """Validar que la configuración de OLLAMA es correcta"""
    print(f"\n[CONFIG] OLLAMA Configuration:")
    print(f"  URL: {OLLAMA_API_URL}")
    print(f"  Model: {MODEL_NAME}")
    print(f"  Streaming: {ENABLE_STREAMING}")
    
    # Si URL es OLLAMA Cloud pero no hay API Key
    if "api.ollama.com" in OLLAMA_API_URL and not OLLAMA_API_KEY:
        print(f"\n[!ERROR] ⚠️  CRITICAL CONFIG ERROR:")
        print(f"  - URL: {OLLAMA_API_URL} (OLLAMA Cloud)")
        print(f"  - Modelo: {MODEL_NAME}")
        print(f"  - API Key: NOT CONFIGURED ❌")
        print(f"\n  Para usar OLLAMA Cloud, debes configurar OLLAMA_API_KEY:")
        print(f"  1. Obtener en https://ollama.com/account/keys")
        print(f"  2. Crear archivo .env.production:")
        print(f"     cat > .env.production << EOF")
        print(f"     OLLAMA_API_URL=https://api.ollama.com")
        print(f"     OLLAMA_API_KEY=sk_... # TU API KEY")
        print(f"     OLLAMA_MODEL=llama3.2:1b:cloud")
        print(f"     FLASK_ENV=production")
        print(f"     EOF")
        print(f"  3. Reiniciar API")
        return False
    
    # Si hay API Key, mostrar que autenticación está activa
    if OLLAMA_API_KEY:
        print(f"  Auth: ✓ API Key configured")
    else:
        print(f"  Auth: ℹ Local mode (no authentication)")
    
    return True

_validate_ollama_config()

# Construir headers HTTP con autenticación si está configurada
def get_ollama_headers() -> dict:
    """
    Construye los headers HTTP para solicitudes a OLLAMA
    - Si OLLAMA_API_KEY está configurada, agregar encabezado Authorization
    - Útil para OLLAMA Cloud o OLLAMA con autenticación
    """
    headers = {
        "Content-Type": "application/json"
    }
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"
    return headers

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
        headers = get_ollama_headers()
        response = requests.get(
            f"{OLLAMA_API_URL}/api/tags", 
            headers=headers,
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        return [m['name'] for m in data.get('models', [])]
    except Exception as e:
        print(f"[!] Error al obtener modelos: {e}")
        return []

def call_ollama(prompt_content: str) -> tuple:
    """
    Envía el prompt a Ollama con streaming activado
    ⚡ OPTIMIZACIONES:
    - num_predict: 200 (limita tokens generados)
    - Primer chunk en < 5 segundos o timeout
    - Stream procesa más rápido
    Returns: (response_text, elapsed_time_in_seconds)
    """
    
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt_content,
        "stream": ENABLE_STREAMING,  # ✅ Streaming activado
        "num_predict": 200  # ⚡ NUEVO: Limitar a 200 tokens para respuestas rápidas
    }
    
    start_time = time.time()
    LAST_OLLAMA_ERROR["message"] = None
    
    try:
        print(f"[*] Enviando solicitud a Ollama ({MODEL_NAME})...")
        print(f"[*] Streaming: {ENABLE_STREAMING}")
        
        headers = get_ollama_headers()
        response = requests.post(
            OLLAMA_GENERATE_URL, 
            json=payload,
            headers=headers,
            stream=ENABLE_STREAMING,
            timeout=OLLAMA_TIMEOUT
        )
        if not response.ok:
            LAST_OLLAMA_ERROR["message"] = f"HTTP {response.status_code} desde {OLLAMA_GENERATE_URL}: {response.text[:500]}"
            print(f"> [!ERROR] {LAST_OLLAMA_ERROR['message']}")
            return "", time.time() - start_time
        
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
                        if data.get("error"):
                            LAST_OLLAMA_ERROR["message"] = f"Ollama: {data['error']}"
                            print(f"> [!ERROR] {LAST_OLLAMA_ERROR['message']}")
                            break
                        chunk = data.get("response", "")
                        full_response += chunk
                        chunk_count += 1
                        
                        # Registrar tiempo del primer chunk
                        if first_chunk_time is None:
                            first_chunk_time = time.time()
                            elapsed_to_first = first_chunk_time - start_time
                            print(f"[✓] Primer chunk recibido en {elapsed_to_first:.1f}s")
                            
                            # ⚡ Si primer chunk tarda > 3s, algo anda mal
                            if elapsed_to_first > 3:
                                print(f"[!] Primer chunk lento ({elapsed_to_first:.1f}s)")
                        
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
        LAST_OLLAMA_ERROR["message"] = f"Timeout tras {elapsed:.1f}s llamando a {OLLAMA_GENERATE_URL}"
        print(f"\n> [!CAUTION]")
        print(f"> **Timeout**: Ollama tardó más de 30 segundos ({elapsed:.1f}s)")
        print("> Considera usar /api/analyze-fast para máxima velocidad")
        return "", elapsed
        
    except requests.exceptions.ConnectionError as e:
        elapsed = time.time() - start_time
        LAST_OLLAMA_ERROR["message"] = f"No se pudo conectar con {OLLAMA_GENERATE_URL}: {e}"
        print(f"\n> [!CAUTION]")
        print(f"> **Error de Conexión**: No se puede conectar con Ollama ({elapsed:.1f}s)")
        print(f"> Verifica que OLLAMA está corriendo: ollama serve")
        return "", elapsed
        
    except Exception as e:
        elapsed = time.time() - start_time
        LAST_OLLAMA_ERROR["message"] = str(e)
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
