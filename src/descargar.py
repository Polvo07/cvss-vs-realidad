"""
Paso 1 — Descarga.

Trae las tres fuentes y las guarda como CSV. Cada fuente tiene su propia
función porque cada una funciona distinto: el NVD es una API paginada, EPSS es
un archivo comprimido y KEV es un JSON de una sola pieza.

Uso:
    python src/descargar.py          # descarga las tres
    python src/descargar.py kev      # solo una (kev, epss o nvd)
"""

import gzip
import io
import json
import os
import sys
import time
from datetime import datetime, timedelta

import pandas as pd
import requests

import config


# =============================================================================
# KEV — CISA. Es la más pequeña y la más importante del análisis.
# =============================================================================
def descargar_kev():
    """
    Lista oficial de vulnerabilidades que se están explotando en ataques reales.

    Son unas 1.300 y sirven como "verdad de campo": permiten medir qué tan bien
    acierta cada método de priorización.
    """
    print("[KEV] descargando...")
    respuesta = requests.get(config.KEV_URL, timeout=60)
    respuesta.raise_for_status()
    datos = respuesta.json()

    filas = []
    for v in datos["vulnerabilities"]:
        filas.append({
            "cve": v["cveID"],
            "kev_fabricante": v.get("vendorProject", ""),
            "kev_producto": v.get("product", ""),
            "kev_fecha_agregada": v.get("dateAdded", ""),
            "kev_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
        })

    tabla = pd.DataFrame(filas)
    tabla.to_csv(config.ARCHIVO_KEV, index=False, encoding="utf-8")
    print(f"[KEV] {len(tabla):,} vulnerabilidades explotadas -> {config.ARCHIVO_KEV.name}")
    return tabla


# =============================================================================
# EPSS — FIRST.org. Un solo archivo comprimido con todas las probabilidades.
# =============================================================================
def descargar_epss():
    """
    Probabilidad de que cada vulnerabilidad sea explotada en los próximos 30 días.

    El archivo viene comprimido en gzip y su primera línea es un comentario con
    la versión del modelo, por eso se salta al leerlo.
    """
    print("[EPSS] descargando (unos 5 MB comprimidos)...")
    respuesta = requests.get(config.EPSS_URL, timeout=120)
    respuesta.raise_for_status()

    texto = gzip.decompress(respuesta.content).decode("utf-8")
    tabla = pd.read_csv(io.StringIO(texto), comment="#")

    tabla = tabla.rename(columns={
        "cve": "cve",
        "epss": "epss",
        "percentile": "epss_percentil",
    })
    tabla.to_csv(config.ARCHIVO_EPSS, index=False, encoding="utf-8")
    print(f"[EPSS] {len(tabla):,} vulnerabilidades con probabilidad -> {config.ARCHIVO_EPSS.name}")
    return tabla


# =============================================================================
# NVD — NIST. Es la más lenta: API paginada y con límite de peticiones.
# =============================================================================
def _espera_entre_peticiones():
    """El NVD exige esperar entre peticiones. Con llave el límite es más alto."""
    if os.environ.get(config.NVD_TOKEN_ENV):
        return config.ESPERA_CON_LLAVE
    return config.ESPERA_SIN_LLAVE


def _cabeceras_nvd():
    llave = os.environ.get(config.NVD_TOKEN_ENV)
    return {"apiKey": llave} if llave else {}


def _extraer_cvss(registro):
    """
    Saca el puntaje CVSS de un registro del NVD.

    Hay tres versiones del estándar conviviendo (4.0, 3.1 y 3.0) y no todas las
    vulnerabilidades traen todas. Se busca de la más nueva a la más vieja y se
    devuelve la primera que exista, junto con la versión usada.
    """
    metricas = registro.get("metrics", {})
    for clave, version in (("cvssMetricV40", "4.0"),
                           ("cvssMetricV31", "3.1"),
                           ("cvssMetricV30", "3.0")):
        lista = metricas.get(clave)
        if lista:
            datos = lista[0]["cvssData"]
            return datos.get("baseScore"), datos.get("baseSeverity"), version
    return None, None, None


def _ventanas_de_fechas(inicio, fin, dias):
    """
    Parte el periodo en tramos, porque el NVD no acepta rangos largos.

    Devuelve pares (desde, hasta) que cubren el periodo completo sin traslape.
    """
    tramos = []
    actual = inicio
    while actual < fin:
        siguiente = min(actual + timedelta(days=dias), fin)
        tramos.append((actual, siguiente))
        actual = siguiente
    return tramos


def _pedir_pagina(desde, hasta, indice):
    """Una petición al NVD. Reintenta hasta 3 veces si el servidor falla."""
    parametros = {
        "pubStartDate": desde.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": hasta.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": 2000,
        "startIndex": indice,
    }
    for intento in (1, 2, 3):
        try:
            r = requests.get(config.NVD_URL, params=parametros,
                             headers=_cabeceras_nvd(), timeout=120)
            r.raise_for_status()
            return r.json()
        except requests.RequestException as error:
            # El NVD responde 404 tanto para llaves inválidas como para rangos
            # de fecha que exceden los 120 días permitidos. El mensaje lo aclara
            # porque el código de error por sí solo despista.
            if "404" in str(error):
                print("  [aviso] el NVD respondió 404. Suele ser la llave de API o un")
                print("          rango de fechas mayor a 120 días. Corre: python src/diagnostico.py")
            if intento == 3:
                raise
            print(f"  [reintento {intento}] {error}")
            time.sleep(10 * intento)


def descargar_nvd():
    """
    Puntajes CVSS de las vulnerabilidades publicadas desde la fecha configurada.

    Es la descarga larga: el NVD obliga a esperar entre peticiones, así que
    tarda entre 10 y 20 minutos sin llave de API.
    """
    inicio = datetime.strptime(config.FECHA_INICIO, "%Y-%m-%d")
    fin = datetime.now()
    ventanas = _ventanas_de_fechas(inicio, fin, config.DIAS_POR_VENTANA)
    espera = _espera_entre_peticiones()

    print(f"[NVD] {len(ventanas)} ventanas de {config.DIAS_POR_VENTANA} días, "
          f"esperando {espera}s entre peticiones")
    if not os.environ.get(config.NVD_TOKEN_ENV):
        print("[NVD] sin llave de API: va a tardar bastante más. "
              "Se pide gratis en nvd.nist.gov/developers/request-an-api-key")

    filas = []
    for numero, (desde, hasta) in enumerate(ventanas, start=1):
        indice = 0
        while True:
            datos = _pedir_pagina(desde, hasta, indice)
            for elemento in datos.get("vulnerabilities", []):
                registro = elemento["cve"]
                puntaje, severidad, version = _extraer_cvss(registro)
                filas.append({
                    "cve": registro["id"],
                    "publicada": registro.get("published", "")[:10],
                    "cvss": puntaje,
                    "cvss_severidad": severidad,
                    "cvss_version": version,
                })
            total = datos.get("totalResults", 0)
            indice += datos.get("resultsPerPage", 0)
            time.sleep(espera)
            if indice >= total:
                break

        print(f"[NVD] ventana {numero}/{len(ventanas)} "
              f"({desde:%Y-%m-%d}) · {len(filas):,} acumuladas")

    tabla = pd.DataFrame(filas).drop_duplicates(subset=["cve"])
    tabla.to_csv(config.ARCHIVO_NVD, index=False, encoding="utf-8")
    print(f"[NVD] {len(tabla):,} vulnerabilidades -> {config.ARCHIVO_NVD.name}")
    return tabla


def main():
    cual = sys.argv[1].lower() if len(sys.argv) > 1 else "todo"

    if cual in ("todo", "kev"):
        descargar_kev()
    if cual in ("todo", "epss"):
        descargar_epss()
    if cual in ("todo", "nvd"):
        descargar_nvd()

    print("\nListo. Siguiente paso: python src/unir.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
