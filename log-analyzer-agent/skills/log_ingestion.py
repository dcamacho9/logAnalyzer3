# skills/log_ingestion.py
"""
Skill 1: Ingesta de Logs e Integración de Fuentes de Datos.
Maneja la lectura de trazas locales y paginación HTTPS en producción.
"""
import os

def fetch_logs(source_id="prod-k8s-cluster", limit=100):
    """
    Simula la ingesta de logs leyendo un archivo de prueba local.
    En producción, aquí se realizarían las peticiones HTTPS correspondientes.
    """
    # Intentar buscar el archivo de prueba en la raíz del proyecto
    file_path = "test_logs.txt"
    
    if not os.path.exists(file_path):
        print(f"[-] Skill log_ingestion: Archivo '{file_path}' no encontrado en la raíz.")
        print("[*] Creando un archivo de logs temporal con datos de prueba...")
        
        # Generar una muestra por defecto para que el agente no falle
        sample_logs = (
            "2026-07-31T09:40:01Z [INFO] User test.user@domain.com logged in from 192.168.1.50.\n"
            "2026-07-31T09:42:15Z [ERROR] db-proxy connection timeout. mysql_error_code=1045. IP: 10.0.0.4\n"
            "2026-07-31T09:42:18Z [CRITICAL] user-api failed to fetch profile. correlationId=req-99x-abc1234.\n"
        )
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(sample_logs)

    # Leer las trazas disponibles
    with open(file_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
        
    print(f"[+] Skill log_ingestion: {len(lines)} trazas cargadas correctamente.")
    return lines[:limit]