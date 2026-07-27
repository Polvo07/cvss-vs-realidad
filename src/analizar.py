"""
Paso 3 — Análisis.

Responde las tres preguntas del proyecto comparando cada criterio de
priorización contra la única evidencia dura disponible: la lista de CISA con
las vulnerabilidades que sí se están explotando.

Uso:
    python src/analizar.py
"""

import sys

import pandas as pd

import config


def titulo(texto):
    print(f"\n{'=' * 72}\n{texto}\n{'=' * 72}")


def cargar():
    if not config.ARCHIVO_UNIDO.exists():
        raise FileNotFoundError(
            f"Falta {config.ARCHIVO_UNIDO.name}. Ejecuta antes: python src/unir.py")
    return pd.read_csv(config.ARCHIVO_UNIDO)


# =============================================================================
# Pregunta 1: de las "críticas", ¿cuántas se explotan de verdad?
# =============================================================================
def pregunta_1(datos):
    titulo("1. ¿QUÉ TAN BIEN ACIERTA EL CVSS?")

    print("De cada banda de severidad, cuántas terminaron explotándose:\n")
    print(f"{'Banda CVSS':<16s} {'Vulnerabilidades':>18s} {'Explotadas':>12s} {'% explotado':>13s}")
    print("-" * 62)

    orden = ["Crítica", "Alta", "Media", "Baja", "Sin puntaje"]
    tabla = datos.groupby("cvss_banda").agg(
        total=("cve", "size"), explotadas=("explotada", "sum"))

    for banda in orden:
        if banda not in tabla.index:
            continue
        fila = tabla.loc[banda]
        tasa = fila["explotadas"] / fila["total"]
        print(f"{banda:<16s} {fila['total']:>18,} {fila['explotadas']:>12,} {tasa:>12.2%}")

    criticas = datos[datos["cvss_banda"] == "Crítica"]
    if len(criticas):
        tasa = criticas["explotada"].mean()
        print(f"\n  Solo el {tasa:.2%} de las vulnerabilidades marcadas como críticas")
        print(f"  llegó a explotarse. Tratar {len(criticas):,} vulnerabilidades como")
        print("  urgentes cuando casi ninguna lo es no es priorizar: es ruido.")


# =============================================================================
# Pregunta 2: de las que sí se explotan, ¿qué decía el CVSS?
# =============================================================================
def pregunta_2(datos):
    titulo("2. LAS QUE SÍ SE EXPLOTAN, ¿LAS HABRÍA VISTO EL CVSS?")

    explotadas = datos[datos["explotada"]]
    if not len(explotadas):
        print("No hay vulnerabilidades explotadas en el universo analizado.")
        return

    print(f"Severidad CVSS de las {len(explotadas):,} vulnerabilidades explotadas:\n")
    conteo = explotadas["cvss_banda"].value_counts()
    for banda in ["Crítica", "Alta", "Media", "Baja", "Sin puntaje"]:
        if banda in conteo.index:
            n = conteo[banda]
            print(f"  {banda:<14s} {n:>6,}  ({n/len(explotadas):5.1%})")

    # Una organización que priorice solo lo crítico deja fuera todo lo demás.
    perdidas = explotadas[~explotadas["cvss_banda"].isin(["Crítica"])]
    print(f"\n  {len(perdidas):,} vulnerabilidades ({len(perdidas)/len(explotadas):.1%}) se están")
    print("  explotando pese a NO estar calificadas como críticas. Un equipo que")
    print("  atienda solo lo crítico las deja sin parchar.")

    print(f"\n  EPSS mediano de las explotadas : {explotadas['epss'].median():.4f}")
    print(f"  EPSS mediano del resto         : {datos[~datos['explotada']]['epss'].median():.4f}")


# =============================================================================
# Pregunta 3: con presupuesto limitado, ¿qué estrategia acierta más?
# =============================================================================
def _aciertos(datos, columna, cuantas):
    """Cuántas vulnerabilidades realmente explotadas caen en el top N según un criterio."""
    top = datos.nlargest(cuantas, columna)
    return int(top["explotada"].sum())


def pregunta_3(datos):
    titulo("3. CON CAPACIDAD LIMITADA, ¿QUÉ ESTRATEGIA ACIERTA MÁS?")

    total_explotadas = int(datos["explotada"].sum())
    n = config.CAPACIDAD_PARCHEO

    print(f"Supuesto: el equipo alcanza a parchar {n} vulnerabilidades.")
    print(f"En el universo hay {total_explotadas:,} que se están explotando.")
    print("Ninguna estrategia mira el catálogo KEV para ordenar: se evalúa qué tan")
    print("bien predice cada criterio sin conocer la respuesta.\n")

    # Se usa riesgo_base y no riesgo: el operativo incluye el catálogo KEV, así
    # que ordenar por él pondría las explotadas primero por construcción y la
    # comparación no mediría nada.
    estrategias = {
        "Por severidad (CVSS)": "cvss",
        "Por probabilidad (EPSS)": "epss",
        "Por riesgo combinado": "riesgo_base",
    }

    print(f"{'Estrategia':<28s} {'Aciertos':>10s} {'% del total explotado':>24s}")
    print("-" * 64)
    resultados = {}
    for nombre, columna in estrategias.items():
        aciertos = _aciertos(datos, columna, n)
        resultados[nombre] = aciertos
        cobertura = aciertos / total_explotadas if total_explotadas else 0
        print(f"{nombre:<28s} {aciertos:>10,} {cobertura:>23.1%}")

    por_cvss = resultados["Por severidad (CVSS)"]
    por_riesgo = resultados["Por riesgo combinado"]
    if por_cvss > 0:
        print(f"\n  Priorizar por riesgo combinado encuentra {por_riesgo/por_cvss:.1f} veces")
        print("  más amenazas reales que priorizar por severidad, con el mismo esfuerzo.")
    elif por_riesgo > 0:
        print(f"\n  Priorizar por severidad no encontró ninguna amenaza real; el riesgo")
        print(f"  combinado encontró {por_riesgo}.")


def curva_de_cobertura(datos):
    """Cuánto se gana al ampliar la capacidad de parcheo, según el criterio usado."""
    titulo("4. CUÁNTO SE GANA AL AMPLIAR LA CAPACIDAD")

    total = int(datos["explotada"].sum())
    if not total:
        print("Sin vulnerabilidades explotadas: no aplica.")
        return

    print(f"{'Capacidad':>10s} {'CVSS':>10s} {'EPSS':>10s} {'Riesgo':>10s} {'% del total':>13s}")
    print("-" * 58)
    for cuantas in (50, 100, 250, 500, 1000):
        fila = [_aciertos(datos, c, cuantas) for c in ("cvss", "epss", "riesgo_base")]
        mejor = max(fila) / total
        print(f"{cuantas:>10,} {fila[0]:>10,} {fila[1]:>10,} {fila[2]:>10,} {mejor:>12.1%}")

    print("\n  Cada columna muestra cuántas amenazas reales atrapa cada criterio")
    print("  al parchar esa cantidad de vulnerabilidades.")


def limitaciones(datos):
    titulo("5. LÍMITES DE ESTE ANÁLISIS")

    sin_cvss = datos["cvss"].isna().sum()
    sin_epss = (datos["epss"] == 0).sum()

    print(f"- {sin_cvss:,} vulnerabilidades ({sin_cvss/len(datos):.1%}) no tienen puntaje")
    print("  CVSS asignado y quedan fuera de la estrategia por severidad.")
    print(f"- {sin_epss:,} ({sin_epss/len(datos):.1%}) no tienen puntaje EPSS.")
    print()
    print("- El modelo de EPSS se entrena con señales de explotación observada, así")
    print("  que comparte información con el catálogo KEV. La comparación lo favorece")
    print("  por construcción. La conclusión defendible no es que EPSS sea infalible,")
    print("  sino que la severidad por sí sola no basta para priorizar.")
    print()
    print("- El KEV recoge explotación confirmada y publicada. Hay ataques que nunca")
    print("  llegan al catálogo, así que es un piso, no la cifra total.")


def main():
    datos = cargar()
    print(f"Universo: {len(datos):,} vulnerabilidades publicadas desde {config.FECHA_INICIO}")

    pregunta_1(datos)
    pregunta_2(datos)
    pregunta_3(datos)
    curva_de_cobertura(datos)
    limitaciones(datos)

    titulo("SIGUIENTE PASO")
    print("Con estos números se escribe la sección de hallazgos del README.")
    print("Para usar la priorización sobre una lista propia:")
    print("    python src/priorizar.py mis_vulnerabilidades.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
