# skills/__init__.py
"""
Paquete de Habilidades (Skills) para el Log Analyzer Agent.
Expone las funciones principales de ingesta, análisis sintáctico y conectividad ITSM.
"""

# Exponer de forma directa las funciones principales para limpiar las importaciones en agent.py
from .log_ingestion import fetch_logs
from .log_pattern_matcher import run_log_pattern_matcher
from .servicenow_token_generator import run_servicenow_token_generator
from .servicenow_incident_creator import run_servicenow_incident_creator

# Definir el contrato de exportación del paquete
__all__ = [
    "fetch_logs",
    "run_log_pattern_matcher",
    "run_servicenow_token_generator",
    "run_servicenow_incident_creator"
]