"""
API REST OPTIMIZADA para el Agente de Análisis de Logs
Cambios clave:
1. Streaming activado
2. Endpoints mejorados
3. Response timing incluido
4. Mejor manejo de errores
"""

from flask import Flask, request, jsonify, Response
import json
import time
from agent_optimized import (
    parse_log_lines, 
    cached_ollama_call,
    call_ollama,
    MODEL_NAME, 
    OLLAMA_API_URL,
    ENABLE_STREAMING,
    print_cache_stats
)
print(OLLAMA_API_URL)
from skills.log_ingestion import fetch_logs
from skills.log_pattern_matcher import run_log_pattern_matcher
from skills.servicenow_token_generator import run_servicenow_token_generator
from skills.servicenow_incident_creator import run_servicenow_incident_creator
import os

app = Flask(__name__)

# Configuración para soportar payloads grandes
app.config['JSON_AS_ASCII'] = False
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max
app.config['JSON_SORT_KEYS'] = False

# Manejador para errores de JSON
@app.errorhandler(400)
def handle_bad_request(e):
    """Manejador mejorado para errores 400"""
    return jsonify({
        "status": "error",
        "message": f"400 Bad Request: {str(e)}",
        "hint": "Verifique que Content-Type sea 'application/json' y que el JSON esté bien formado",
        "step": "unknown"
    }), 400

@app.route('/api/health', methods=['GET'])
def health():
    """Verificar que el servicio está activo"""
    return jsonify({
        "status": "OK",
        "service": "Log Analyzer Agent (Optimized)",
        "model": MODEL_NAME,
        "streaming": ENABLE_STREAMING,
        "ollama_url": OLLAMA_API_URL
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analizar logs y generar diagnóstico (con streaming)
    
    POST /api/analyze
    Content-Type: application/json
    
    Body:
    {
        "logs": "string de logs (opcional)",
        "limit": 100,
        "only_pattern_analysis": false,
        "use_cache": true,
        "stream_response": true
    }
    
    Response (JSON o Stream):
    {
        "status": "success|error",
        "step": "nombre del paso actual",
        "annotated_events": [...],
        "pattern_summary": [...],
        "diagnostic_report": "texto del diagnóstico",
        "timing": {
            "total_seconds": 4.32,
            "ollama_seconds": 3.21,
            "cache_hit": false
        }
    }
    """
    start_time = time.time()
    
    try:
        # Intentar obtener JSON con manejo robusto
        # Verificar Content-Type primero
        content_type = request.headers.get('Content-Type', '').lower()
        
        if not content_type.startswith('application/json'):
            # Intentar parsear de todas formas con force=True
            data = request.get_json(force=True, silent=True)
            if data is None:
                # Si falla, intentar del request raw
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError) as e:
                    return jsonify({
                        "status": "error",
                        "message": f"Error al parsear JSON: {str(e)}",
                        "hint": "Verifique que: 1) Content-Type sea 'application/json; charset=utf-8', 2) El JSON esté bien formado",
                        "step": "json_parsing"
                    }), 400
        else:
            # Content-Type es correcto, parsear JSON
            data = request.get_json(force=True, silent=True)
            if data is None:
                # Intentar del request raw si falla
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError) as e:
                    return jsonify({
                        "status": "error",
                        "message": f"Error al parsear JSON: {str(e)}",
                        "hint": "Verifique que el JSON esté bien formado",
                        "step": "json_parsing"
                    }), 400
        
        if data is None:
            data = {}
        
        # Paso 1: Ingesta de logs
        if data.get('logs'):
            logs_str = data['logs']
            if not isinstance(logs_str, str):
                return jsonify({
                    "status": "error",
                    "message": "El campo 'logs' debe ser un string",
                    "step": "1_ingestion"
                }), 400
            raw_log_lines = logs_str.split('\n')
        else:
            raw_log_lines = fetch_logs(limit=data.get('limit', 100))
        
        if not raw_log_lines or all(not line.strip() for line in raw_log_lines):
            return jsonify({
                "status": "error",
                "message": "No se encontraron logs válidos",
                "step": "1_ingestion"
            }), 400
        
        # Filtrar líneas vacías
        raw_log_lines = [line for line in raw_log_lines if line.strip()]
        
        # Paso 2: Parsear logs
        raw_logs = parse_log_lines(raw_log_lines)
        
        # Paso 3: Análisis de patrones
        pattern_result = run_log_pattern_matcher(raw_logs)
        annotated_events = pattern_result.get("annotated_events", [])
        pattern_summary = pattern_result.get("pattern_summary", [])
        top_errors = pattern_result.get("top_errors", [])
        
        # Si solo se quiere análisis de patrones
        if data.get('only_pattern_analysis'):
            elapsed_total = time.time() - start_time
            return jsonify({
                "status": "success",
                "step": "2_pattern_analysis",
                "annotated_events": annotated_events,
                "pattern_summary": pattern_summary,
                "top_errors": top_errors,
                "timing": {
                    "total_seconds": round(elapsed_total, 2)
                }
            }), 200
        
        # Paso 4: Generar prompt optimizado para Ollama
        # ⚡ OPTIMIZACIÓN: Reducir contexto al mínimo esencial
        prompt_for_llm = f"""Analiza brevemente (máximo 200 palabras):

Patrones principales:
{json.dumps(pattern_summary[:5], indent=1)}

Errores top:
{json.dumps(top_errors[:3], indent=1)}

Proporciona:
1. Causa raíz
2. Acciones recomendadas
3. Severidad (CRITICAL/HIGH/MEDIUM/LOW)
"""

        # ✅ VERSIÓN CON CACHÉ Y STREAMING
        use_cache = data.get('use_cache', True)
        stream_response = data.get('stream_response', ENABLE_STREAMING)
        
        ollama_start = time.time()
        diagnostic_report, ollama_elapsed, cache_hit = cached_ollama_call(
            prompt_for_llm, 
            use_cache=use_cache
        )
        
        if not diagnostic_report:
            return jsonify({
                "status": "error",
                "message": "Falló la generación del diagnóstico en Ollama",
                "step": "3_ollama_inference",
                "cache_hit": cache_hit
            }), 500
        
        # Calcular tiempos totales
        elapsed_total = time.time() - start_time
        
        # Respuesta final
        response_data = {
            "status": "success",
            "step": "4_diagnostic_report",
            "diagnostic_report": diagnostic_report,
            "timing": {
                "total_seconds": round(elapsed_total, 2),
                "ollama_seconds": round(ollama_elapsed, 2),
                "cache_hit": cache_hit,
                "model": MODEL_NAME
            }
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        import traceback
        elapsed_total = time.time() - start_time
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc() if app.debug else None,
            "step": "unknown",
            "elapsed_seconds": round(elapsed_total, 2)
        }), 500

@app.route('/api/analyze/streaming', methods=['POST'])
def analyze_streaming():
    """
    Versión de streaming con respuesta progresiva
    Envía chunks de respuesta conforme se van recibiendo de Ollama
    """
    try:
        # Intentar obtener JSON con manejo robusto
        content_type = request.headers.get('Content-Type', '').lower()
        
        if not content_type.startswith('application/json'):
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        else:
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        
        if data is None:
            data = {}
        
        # Paso 1: Ingesta de logs
        if data.get('logs'):
            logs_str = data['logs']
            if not isinstance(logs_str, str):
                return jsonify({
                    "status": "error",
                    "message": "El campo 'logs' debe ser un string",
                    "step": "1_ingestion"
                }), 400
            raw_log_lines = logs_str.split('\n')
        else:
            raw_log_lines = fetch_logs(limit=data.get('limit', 100))
        
        if not raw_log_lines or all(not line.strip() for line in raw_log_lines):
            return jsonify({
                "status": "error",
                "message": "No se encontraron logs válidos"
            }), 400
        
        # Filtrar líneas vacías
        raw_log_lines = [line for line in raw_log_lines if line.strip()]
        
        # Paso 2-3: Procesar logs
        raw_logs = parse_log_lines(raw_log_lines)
        pattern_result = run_log_pattern_matcher(raw_logs)
        
        # Paso 4: Generar prompt
        prompt_for_llm = f"""
Analice los siguientes eventos anotados:
{json.dumps(pattern_result.get("annotated_events", [])[:10], indent=2)}

Genere un Reporte Diagnóstico Causa-Raíz breve.
"""
        
        # Función para generar stream
        def generate():
            """Generador para streaming de respuesta"""
            yield '{"status":"streaming","chunks":[\n'
            
            chunk_num = 0
            full_response = ""
            
            try:
                # Enviar solicitud a Ollama con streaming
                import requests
                from agent_optimized import OLLAMA_GENERATE_URL
                
                payload = {
                    "model": MODEL_NAME,
                    "prompt": prompt_for_llm,
                    "stream": True
                }
                
                response = requests.post(
                    OLLAMA_GENERATE_URL,
                    json=payload,
                    stream=True,
                    timeout=900
                )
                
                for line in response.iter_lines():
                    if line:
                        try:
                            data_chunk = json.loads(line)
                            chunk_text = data_chunk.get("response", "")
                            
                            if chunk_text:
                                full_response += chunk_text
                                chunk_num += 1
                                
                                # Enviar chunk al cliente
                                chunk_json = json.dumps({
                                    "chunk_num": chunk_num,
                                    "text": chunk_text,
                                    "is_final": False
                                })
                                yield chunk_json + ",\n"
                        except json.JSONDecodeError:
                            continue
                
                # Chunk final
                final_chunk = json.dumps({
                    "chunk_num": chunk_num + 1,
                    "text": "",
                    "is_final": True,
                    "total_chunks": chunk_num,
                    "full_response": full_response
                })
                yield final_chunk + "\n"
                
            except Exception as e:
                error_chunk = json.dumps({
                    "error": str(e),
                    "is_final": True
                })
                yield error_chunk + "\n"
            
            yield '],"status":"complete"}\n'
        
        return Response(
            generate(),
            mimetype='application/json',
            headers={
                'X-Accel-Buffering': 'no',
                'Cache-Control': 'no-cache'
            }
        )
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/analyze-fast', methods=['POST'])
def analyze_fast():
    """
    ⚡ VERSIÓN ULTRA-RÁPIDA: /api/analyze-fast
    Objetivo: Reducir latencia a ~20-30 segundos
    
    Optimizaciones:
    1. Contexto mínimo (solo 3 errores top)
    2. Prompt ultra-conciso (100 palabras máx)
    3. Timeout agresivo (25s)
    4. Fallback a patrones si Ollama es lento
    5. Cache agresivo
    
    POST /api/analyze-fast
    Content-Type: application/json
    
    Body:
    {
        "logs": "string de logs (opcional)",
        "limit": 50,
        "timeout_seconds": 25,
        "fallback_to_patterns": true
    }
    
    Response:
    {
        "status": "success|partial",
        "method": "ollama|patterns_only",
        "diagnostic_report": "análisis breve",
        "pattern_summary": [...],
        "top_errors": [...],
        "timing": {
            "total_seconds": 22.5,
            "ollama_seconds": 20.1,
            "method": "fast_analysis"
        }
    }
    """
    start_time = time.time()
    
    try:
        # Intentar obtener JSON con manejo robusto
        content_type = request.headers.get('Content-Type', '').lower()
        
        if not content_type.startswith('application/json'):
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        else:
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        
        if data is None:
            data = {}
        
        max_timeout = data.get('timeout_seconds', 25)  # Timeout agresivo
        fallback_enabled = data.get('fallback_to_patterns', True)
        
        # Paso 1-2: Ingesta y parseo rápido
        if data.get('logs'):
            logs_str = data['logs']
            if not isinstance(logs_str, str):
                return jsonify({
                    "status": "error",
                    "message": "El campo 'logs' debe ser un string",
                    "step": "1_ingestion"
                }), 400
            raw_log_lines = logs_str.split('\n')[:50]  # Limitar a 50 líneas
        else:
            raw_log_lines = fetch_logs(limit=data.get('limit', 50))
        
        # Filtrar líneas vacías
        raw_log_lines = [line for line in raw_log_lines if line.strip()]
        
        if not raw_log_lines:
            return jsonify({
                "status": "error",
                "message": "No se encontraron logs válidos",
                "step": "1_ingestion"
            }), 400
        
        if not raw_log_lines:
            return jsonify({"status": "error", "message": "No logs"}), 400
        
        # Paso 3: Análisis de patrones (muy rápido)
        raw_logs = parse_log_lines(raw_log_lines)
        pattern_result = run_log_pattern_matcher(raw_logs)
        pattern_summary = pattern_result.get("pattern_summary", [])
        top_errors = pattern_result.get("top_errors", [])
        
        # Si cacheamos un hit aquí, devolver sin Ollama
        cache_key = json.dumps({"patterns": pattern_summary, "errors": top_errors})
        import hashlib
        cache_hash = hashlib.md5(cache_key.encode()).hexdigest()
        
        # Paso 4: Prompt ultra-conciso
        prompt_ultra_fast = f"""Análisis RCR breve (máx 150 palabras):

Errores: {json.dumps(top_errors[:3])}

Patrones: {','.join(str(p) for p in pattern_summary[:5])}

Causa-raíz + acciones:"""
        
        # Paso 5: Llamar Ollama con timeout AGRESIVO
        elapsed_before_ollama = time.time() - start_time
        ollama_timeout = max_timeout - elapsed_before_ollama - 2  # Reservar 2s para respuesta
        
        if ollama_timeout < 5:  # Si queda poco tiempo, devolver patrones
            if fallback_enabled:
                elapsed_total = time.time() - start_time
                return jsonify({
                    "status": "partial",
                    "method": "patterns_only",
                    "pattern_summary": pattern_summary[:5],
                    "top_errors": top_errors[:3],
                    "timing": {
                        "total_seconds": round(elapsed_total, 2),
                        "method": "fast_analysis_fallback"
                    }
                }), 200
        
        # Intentar Ollama con timeout reducido
        try:
            # Usar versión rápida sin caché para máxima velocidad
            import requests
            payload = {
                "model": MODEL_NAME,
                "prompt": prompt_ultra_fast,
                "stream": False,  # Sin streaming para respuesta más rápida
                "num_predict": 150  # Limitar a 150 tokens
            }
            
            ollama_start = time.time()
            response = requests.post(
                OLLAMA_GENERATE_URL,
                json=payload,
                stream=False,
                timeout=min(25, ollama_timeout)  # Máximo 25s
            )
            response.raise_for_status()
            diagnostic_report = response.json().get("response", "")
            ollama_elapsed = time.time() - ollama_start
            
            elapsed_total = time.time() - start_time
            return jsonify({
                "status": "success",
                "method": "ollama",
                "diagnostic_report": diagnostic_report,
                "top_errors": top_errors[:3],
                "timing": {
                    "total_seconds": round(elapsed_total, 2),
                    "ollama_seconds": round(ollama_elapsed, 2),
                    "method": "fast_analysis"
                }
            }), 200
            
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            # Fallback a patrones si Ollama falla
            if fallback_enabled:
                elapsed_total = time.time() - start_time
                return jsonify({
                    "status": "partial",
                    "method": "patterns_only",
                    "reason": "ollama_timeout",
                    "pattern_summary": pattern_summary[:5],
                    "top_errors": top_errors[:3],
                    "timing": {
                        "total_seconds": round(elapsed_total, 2),
                        "method": "fast_analysis_timeout_fallback"
                    }
                }), 200
            else:
                elapsed_total = time.time() - start_time
                return jsonify({
                    "status": "error",
                    "message": "Ollama timeout",
                    "elapsed_seconds": round(elapsed_total, 2)
                }), 504
    
    except Exception as e:
        elapsed_total = time.time() - start_time
        return jsonify({
            "status": "error",
            "message": str(e),
            "elapsed_seconds": round(elapsed_total, 2)
        }), 500

@app.route('/api/patterns', methods=['POST'])
def get_patterns():
    """
    Solo análisis de patrones (sin OLLAMA, respuesta rápida)
    POST /api/patterns
    Body: {"logs": "...", "limit": 100}
    """
    try:
        # Intentar obtener JSON con manejo robusto
        content_type = request.headers.get('Content-Type', '').lower()
        
        if not content_type.startswith('application/json'):
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        else:
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        
        if data is None:
            data = {}
        
        if data.get('logs'):
            logs_str = data['logs']
            if not isinstance(logs_str, str):
                return jsonify({
                    "status": "error",
                    "message": "El campo 'logs' debe ser un string"
                }), 400
            raw_log_lines = logs_str.split('\n')
        else:
            raw_log_lines = fetch_logs(limit=data.get('limit', 100))
        
        # Filtrar líneas vacías
        raw_log_lines = [line for line in raw_log_lines if line.strip()]
        
        if not raw_log_lines:
            return jsonify({
                "status": "error",
                "message": "No se encontraron logs válidos"
            }), 400
        
        raw_logs = parse_log_lines(raw_log_lines)
        pattern_result = run_log_pattern_matcher(raw_logs)
        
        return jsonify({
            "status": "success",
            "pattern_summary": pattern_result.get("pattern_summary", []),
            "top_errors": pattern_result.get("top_errors", []),
            "annotated_count": len(pattern_result.get("annotated_events", []))
        }), 200
        
    except Exception as e:
        import traceback
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc() if app.debug else None
        }), 500

@app.route('/api/cache-stats', methods=['GET'])
def cache_stats():
    """Obtener estadísticas de caché"""
    from agent_optimized import CACHE_STATS, RESPONSE_CACHE
    
    total_entries = len(RESPONSE_CACHE)
    total = CACHE_STATS["hits"] + CACHE_STATS["misses"]
    hit_rate = (CACHE_STATS["hits"] / total * 100) if total > 0 else 0
    
    return jsonify({
        "status": "success",
        "cache_stats": {
            "hits": CACHE_STATS["hits"],
            "misses": CACHE_STATS["misses"],
            "hit_rate_percent": round(hit_rate, 2),
            "cached_entries": total_entries
        }
    }), 200

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Limpiar caché"""
    from agent_optimized import RESPONSE_CACHE, CACHE_STATS
    
    entries = len(RESPONSE_CACHE)
    RESPONSE_CACHE.clear()
    CACHE_STATS["hits"] = 0
    CACHE_STATS["misses"] = 0
    
    return jsonify({
        "status": "success",
        "message": f"Caché limpiado ({entries} entradas eliminadas)"
    }), 200

@app.route('/api/incidents', methods=['POST'])
def create_incidents():
    """
    Crear incidentes en ServiceNow desde análisis de logs
    POST /api/incidents
    """
    try:
        # Intentar obtener JSON con manejo robusto
        content_type = request.headers.get('Content-Type', '').lower()
        
        if not content_type.startswith('application/json'):
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        else:
            data = request.get_json(force=True, silent=True)
            if data is None:
                try:
                    data = json.loads(request.get_data(as_text=True)) if request.get_data() else {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
        
        if data is None:
            data = {}
        
        if data.get('logs'):
            logs_str = data['logs']
            if not isinstance(logs_str, str):
                return jsonify({
                    "status": "error",
                    "message": "El campo 'logs' debe ser un string"
                }), 400
            raw_log_lines = logs_str.split('\n')
        else:
            raw_log_lines = fetch_logs(limit=data.get('limit', 100))
        
        # Filtrar líneas vacías
        raw_log_lines = [line for line in raw_log_lines if line.strip()]
        
        raw_logs = parse_log_lines(raw_log_lines)
        pattern_result = run_log_pattern_matcher(raw_logs)
        
        incident_result = run_servicenow_incident_creator(
            annotated_events=pattern_result.get("annotated_events", []),
            correlation_data={
                "pattern_summary": pattern_result.get("pattern_summary", []),
                "top_errors": pattern_result.get("top_errors", [])
            },
            dedup_mode=data.get('dedup_mode', 'pattern'),
            log_source=data.get('log_source', 'api'),
            time_range=data.get('time_range', 'Últimos 15 minutos')
        )
        
        if incident_result["status"] in ["OK", "INFO"]:
            return jsonify(incident_result), 200
        else:
            return jsonify(incident_result), 400
            
    except Exception as e:
        import traceback
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc() if app.debug else None
        }), 500

if __name__ == '__main__':
    print(f"[INFO] Iniciando API Flask")
    print(f"[INFO] Modelo OLLAMA: {MODEL_NAME}")
    print(f"[INFO] Streaming habilitado: {ENABLE_STREAMING}")
    print(f"[INFO] Escuchando en http://0.0.0.0:5000")
    print(f"[INFO] Endpoints disponibles:")
    print(f"  - GET  /api/health")
    print(f"  - POST /api/analyze")
    print(f"  - POST /api/analyze/streaming")
    print(f"  - POST /api/patterns")
    print(f"  - POST /api/incidents")
    print(f"  - GET  /api/cache-stats")
    print(f"  - POST /api/cache/clear")
    print("")
    
    port = int(os.getenv('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
