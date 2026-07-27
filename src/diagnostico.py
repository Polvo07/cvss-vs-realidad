"""
Diagnóstico de la conexión con el NVD.

Prueba la API por pasos, del más simple al más complejo, para aislar qué está
fallando: el endpoint, la llave de API o los parámetros de fecha.

Uso:
    python src/diagnostico.py
"""

import os
import sys
import time

import requests

import config


def probar(nombre, parametros, usar_llave):
    """Hace una petición y reporta el resultado sin detener el programa."""
    cabeceras = {}
    if usar_llave:
        llave = os.environ.get(config.NVD_TOKEN_ENV)
        if not llave:
            print(f"  {nombre:<46s} OMITIDA (no hay llave configurada)")
            return None
        cabeceras["apiKey"] = llave

    try:
        r = requests.get(config.NVD_URL, params=parametros, headers=cabeceras, timeout=60)
    except requests.RequestException as error:
        print(f"  {nombre:<46s} ERROR DE RED: {error}")
        return None

    if r.status_code == 200:
        datos = r.json()
        print(f"  {nombre:<46s} OK · {datos.get('totalResults', 0):,} resultados")
        return datos

    print(f"  {nombre:<46s} HTTP {r.status_code}")
    return None


def main():
    llave = os.environ.get(config.NVD_TOKEN_ENV)
    print("=" * 72)
    print("DIAGNÓSTICO DEL NVD")
    print("=" * 72)
    print(f"Endpoint : {config.NVD_URL}")
    if llave:
        print(f"Llave    : configurada, {len(llave)} caracteres, "
              f"empieza en {llave[:4]}… y termina en …{llave[-4:]}")
    else:
        print("Llave    : NO configurada")

    print("\n1. El endpoint responde sin llave y sin filtros")
    base = probar("resultsPerPage=1, sin llave", {"resultsPerPage": 1}, usar_llave=False)
    time.sleep(7)

    print("\n2. La llave es válida")
    # El NVD devuelve 404 cuando la llave es inválida, en lugar de 401.
    # Si el paso 1 funciona y este falla, el problema es la llave.
    probar("resultsPerPage=1, con llave", {"resultsPerPage": 1}, usar_llave=bool(llave))
    time.sleep(2)

    print("\n3. El tamaño de página grande es aceptado")
    probar("resultsPerPage=2000", {"resultsPerPage": 2000}, usar_llave=bool(llave))
    time.sleep(2)

    print("\n4. El filtro de fechas funciona con un rango corto")
    probar("rango de 30 días", {
        "pubStartDate": "2024-01-01T00:00:00.000",
        "pubEndDate": "2024-01-31T00:00:00.000",
        "resultsPerPage": 1,
    }, usar_llave=bool(llave))
    time.sleep(2)

    print("\n5. El rango de 120 días es aceptado")
    # El NVD permite máximo 120 días. Si cuenta los extremos, 120 exactos puede
    # pasarse del límite y ser rechazado.
    probar("rango de 120 días exactos", {
        "pubStartDate": "2023-01-01T00:00:00.000",
        "pubEndDate": "2023-05-01T00:00:00.000",
        "resultsPerPage": 1,
    }, usar_llave=bool(llave))
    time.sleep(2)

    print("\n6. Un rango de 110 días")
    probar("rango de 110 días", {
        "pubStartDate": "2023-01-01T00:00:00.000",
        "pubEndDate": "2023-04-21T00:00:00.000",
        "resultsPerPage": 1,
    }, usar_llave=bool(llave))

    print("\n" + "=" * 72)
    print("CÓMO LEER EL RESULTADO")
    print("=" * 72)
    print("Si falló el paso 1  -> el endpoint o tu red bloquean la conexión.")
    print("Si 1 pasó y 2 falló -> la llave está mal escrita o fue revocada.")
    print("Si 1 y 2 pasaron y falló 3 -> hay que bajar resultsPerPage.")
    print("Si falló 5 pero pasó 6 -> el rango de 120 días se pasa del límite;")
    print("                          hay que reducir DIAS_POR_VENTANA en config.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())