"""
Configuración del proyecto.

Tres fuentes públicas y gratuitas:

  NVD  (NIST)       Puntaje CVSS: qué tan grave sería la vulnerabilidad.
                    https://nvd.nist.gov/developers/vulnerabilities

  EPSS (FIRST.org)  Probabilidad de que sea explotada en los próximos 30 días.
                    https://www.first.org/epss/

  KEV  (CISA)       Lista oficial de vulnerabilidades que SÍ se están
                    explotando en ataques reales. Es la verdad de campo.
                    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from pathlib import Path

# --- Fuentes -----------------------------------------------------------------
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# La API del NVD limita las peticiones. Sin llave exige esperar entre cada una;
# con llave gratuita el límite es mucho más alto.
# Se pide en: https://nvd.nist.gov/developers/request-an-api-key
NVD_TOKEN_ENV = "NVD_API_KEY"
ESPERA_SIN_LLAVE = 6.5   # segundos entre peticiones
ESPERA_CON_LLAVE = 0.7

# --- Alcance del análisis ----------------------------------------------------
# Solo vulnerabilidades publicadas desde esta fecha. Se acota a años recientes
# porque la pregunta es operativa: cómo priorizar lo que llega hoy, no revisar
# el histórico completo de los años noventa.
FECHA_INICIO = "2023-01-01"

# La API del NVD no acepta rangos de más de 120 días por petición.
# Se usan 119 y no 120 porque la petición extiende la fecha final hasta las
# 23:59:59 de ese día: con 120 exactos el rango queda en 120 días y casi 24
# horas, se pasa del límite y la API responde 404 sin explicar por qué.
DIAS_POR_VENTANA = 119

# --- Umbrales del análisis ---------------------------------------------------
# CVSS clasifica la severidad en bandas fijas. Se usan las oficiales.
UMBRAL_CVSS_CRITICO = 9.0
UMBRAL_CVSS_ALTO = 7.0

# EPSS es una probabilidad de 0 a 1. FIRST sugiere 0.10 como punto de corte
# práctico: por encima de ahí la vulnerabilidad merece atención inmediata.
UMBRAL_EPSS_ALTO = 0.10

# Cuántas vulnerabilidades puede parchar un equipo en un ciclo. Es el supuesto
# central del análisis: con recursos limitados, ¿qué estrategia acierta más?
CAPACIDAD_PARCHEO = 100

# --- Rutas -------------------------------------------------------------------
RAIZ = Path(__file__).resolve().parent.parent
DIR_DATA = RAIZ / "data"
DIR_DOCS = RAIZ / "docs"

ARCHIVO_NVD = DIR_DATA / "nvd_cvss.csv"
ARCHIVO_EPSS = DIR_DATA / "epss.csv"
ARCHIVO_KEV = DIR_DATA / "kev.csv"
ARCHIVO_UNIDO = DIR_DATA / "vulnerabilidades.csv"

for carpeta in (DIR_DATA, DIR_DOCS):
    carpeta.mkdir(parents=True, exist_ok=True)
