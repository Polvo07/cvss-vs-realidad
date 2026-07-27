"""
Pruebas de la lógica de priorización.

No necesitan internet: arman tablas pequeñas con los casos que importan y
verifican que la clasificación haga lo esperado.

Uso:
    python src/test_unir.py
"""

import sys

import pandas as pd

import config
from unir import banda_cvss, calcular_riesgo, clasificar_prioridad, resumen


def ok(condicion, descripcion, fallos):
    if condicion:
        print(f"  PASA  {descripcion}")
    else:
        print(f"  FALLA {descripcion}")
        fallos.append(descripcion)


def fila(cvss=None, epss=0.0, explotada=False):
    """Arma una fila mínima con lo que necesitan las funciones de prioridad."""
    return pd.Series({"cvss": cvss, "epss": epss, "explotada": explotada})


def main():
    fallos = []

    print("== Bandas de severidad CVSS ==")
    ok(banda_cvss(9.8) == "Crítica", "9.8 es Crítica", fallos)
    ok(banda_cvss(9.0) == "Crítica", "9.0 es el límite inferior de Crítica", fallos)
    ok(banda_cvss(8.9) == "Alta", "8.9 baja a Alta", fallos)
    ok(banda_cvss(7.0) == "Alta", "7.0 es el límite inferior de Alta", fallos)
    ok(banda_cvss(5.0) == "Media", "5.0 es Media", fallos)
    ok(banda_cvss(2.1) == "Baja", "2.1 es Baja", fallos)
    ok(banda_cvss(None) == "Sin puntaje", "sin puntaje no revienta", fallos)

    print("\n== Orden de prioridad ==")
    # El caso central del proyecto: una vulnerabilidad poco grave pero que se
    # está explotando debe ir antes que una gravísima que nadie explota.
    explotada_leve = clasificar_prioridad(fila(cvss=5.3, epss=0.02, explotada=True))
    critica_tranquila = clasificar_prioridad(fila(cvss=9.8, epss=0.001, explotada=False))
    ok(explotada_leve.startswith("1"),
       "una vulnerabilidad explotada es prioridad 1 aunque su CVSS sea medio", fallos)
    ok(critica_tranquila.startswith("3"),
       "una crítica sin explotación conocida queda en prioridad 3", fallos)
    ok(explotada_leve < critica_tranquila,
       "la explotada ordena antes que la crítica sin explotación", fallos)

    ok(clasificar_prioridad(fila(cvss=6.5, epss=0.35)).startswith("2"),
       "EPSS alto sube a prioridad 2 sin necesidad de estar en KEV", fallos)
    ok(clasificar_prioridad(fila(cvss=3.1, epss=0.001)).startswith("4"),
       "lo poco grave y poco probable queda en seguimiento normal", fallos)

    print("\n== Puntaje de riesgo ==")
    ok(calcular_riesgo(fila(cvss=5.3, epss=0.02, explotada=True)) == 10.0,
       "lo que ya se explota recibe el riesgo máximo", fallos)

    riesgo_critica = calcular_riesgo(fila(cvss=9.8, epss=0.001))
    riesgo_media = calcular_riesgo(fila(cvss=6.5, epss=0.35))
    ok(riesgo_media > riesgo_critica,
       f"una media probable ({riesgo_media}) supera a una crítica improbable ({riesgo_critica})",
       fallos)

    ok(calcular_riesgo(fila(cvss=None, epss=0.5)) == 0.0,
       "sin CVSS el riesgo queda en cero, no en error", fallos)
    ok(calcular_riesgo(fila(cvss=10.0, epss=1.0)) == 10.0,
       "el máximo teórico es 10", fallos)

    print("\n== Resumen sobre una tabla completa ==")
    tabla = pd.DataFrame([
        {"cve": "CVE-2024-0001", "cvss": 9.8, "epss": 0.90, "explotada": True,
         "cvss_banda": "Crítica"},
        {"cve": "CVE-2024-0002", "cvss": 9.5, "epss": 0.001, "explotada": False,
         "cvss_banda": "Crítica"},
        {"cve": "CVE-2024-0003", "cvss": 5.3, "epss": 0.40, "explotada": True,
         "cvss_banda": "Media"},
        {"cve": "CVE-2024-0004", "cvss": None, "epss": 0.0, "explotada": False,
         "cvss_banda": "Sin puntaje"},
    ])
    lineas = resumen(tabla)
    texto = "\n".join(lineas)
    ok("**4**" in texto, "cuenta las 4 vulnerabilidades", fallos)
    ok("**3**" in texto, "detecta que solo 3 tienen puntaje CVSS", fallos)
    ok("**2**" in texto, "detecta las 2 explotadas", fallos)

    print("\n== Coherencia de los umbrales ==")
    ok(config.UMBRAL_CVSS_CRITICO > config.UMBRAL_CVSS_ALTO,
       "el umbral de crítica es mayor que el de alta", fallos)
    ok(0 < config.UMBRAL_EPSS_ALTO < 1,
       "el umbral de EPSS es una probabilidad válida", fallos)
    ok(config.CAPACIDAD_PARCHEO > 0,
       "la capacidad de parcheo es positiva", fallos)

    print("\n" + "=" * 60)
    if fallos:
        print(f"RESULTADO: {len(fallos)} prueba(s) fallaron")
        for f in fallos:
            print(f"  - {f}")
        return 1
    print("RESULTADO: todas las pruebas pasaron")
    return 0


if __name__ == "__main__":
    sys.exit(main())
