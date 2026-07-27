"""
Paso 2 — Unión.

Junta las tres fuentes en una sola tabla y calcula la prioridad de cada
vulnerabilidad combinando los tres criterios.

Uso:
    python src/unir.py
"""

import sys

import pandas as pd

import config


def banda_cvss(puntaje):
    """
    Convierte el puntaje CVSS en su banda oficial de severidad.

    Se recalcula en vez de usar el campo del NVD porque ese campo viene vacío
    en parte de los registros, y así todas las filas quedan clasificadas igual.
    """
    if pd.isna(puntaje):
        return "Sin puntaje"
    if puntaje >= config.UMBRAL_CVSS_CRITICO:
        return "Crítica"
    if puntaje >= config.UMBRAL_CVSS_ALTO:
        return "Alta"
    if puntaje >= 4.0:
        return "Media"
    return "Baja"


def clasificar_prioridad(fila):
    """
    Decide qué tan urgente es parchar una vulnerabilidad.

    El orden refleja cómo prioriza un equipo de seguridad en la práctica:

    1. Si ya se está explotando (KEV), no hay nada que discutir: va primero,
       sin importar su puntaje de severidad.
    2. Si la probabilidad de explotación es alta (EPSS), va después, porque el
       riesgo es inminente aunque todavía no haya ataques registrados.
    3. Solo entonces entra la severidad. Una vulnerabilidad muy grave pero que
       nadie explota puede esperar frente a una menos grave que sí se explota.
    """
    if fila["explotada"]:
        return "1 - Explotada activamente"
    if fila["epss"] >= config.UMBRAL_EPSS_ALTO:
        return "2 - Explotación probable"
    if fila["cvss"] >= config.UMBRAL_CVSS_CRITICO:
        return "3 - Grave pero sin explotación conocida"
    return "4 - Seguimiento normal"


def calcular_riesgo(fila):
    """
    Puntaje único de 0 a 10 para poder ordenar la lista.

    Multiplica severidad por probabilidad: una vulnerabilidad importa cuando es
    grave Y probable. Un 10 de severidad con probabilidad casi nula da un riesgo
    bajo, que es justamente lo que el CVSS por sí solo no refleja.

    Las que ya se están explotando reciben el máximo: la probabilidad para ellas
    no es una estimación, es un hecho.
    """
    if fila["explotada"]:
        return 10.0
    if pd.isna(fila["cvss"]) or pd.isna(fila["epss"]):
        return 0.0
    return round(fila["cvss"] * fila["epss"], 4)


def unir():
    """Carga las tres fuentes, las cruza y agrega las columnas del análisis."""
    faltantes = [a.name for a in (config.ARCHIVO_NVD, config.ARCHIVO_EPSS, config.ARCHIVO_KEV)
                 if not a.exists()]
    if faltantes:
        raise FileNotFoundError(
            f"Faltan archivos: {faltantes}. Ejecuta antes: python src/descargar.py")

    nvd = pd.read_csv(config.ARCHIVO_NVD)
    epss = pd.read_csv(config.ARCHIVO_EPSS)
    kev = pd.read_csv(config.ARCHIVO_KEV)

    print(f"[unir] NVD: {len(nvd):,} · EPSS: {len(epss):,} · KEV: {len(kev):,}")

    # El NVD manda: define el universo de vulnerabilidades publicadas en el
    # periodo. Las otras dos se pegan a la izquierda y aportan sus columnas.
    tabla = nvd.merge(epss, on="cve", how="left")
    tabla = tabla.merge(kev, on="cve", how="left")

    # Una vulnerabilidad está en KEV si el cruce le encontró fabricante.
    tabla["explotada"] = tabla["kev_fabricante"].notna()

    # Sin dato de EPSS se asume probabilidad cero, no dato faltante: si el
    # modelo no le asignó puntaje, no hay evidencia de explotación esperada.
    tabla["epss"] = tabla["epss"].fillna(0.0)
    tabla["epss_percentil"] = tabla["epss_percentil"].fillna(0.0)

    tabla["cvss_banda"] = tabla["cvss"].apply(banda_cvss)
    tabla["epss_alto"] = tabla["epss"] >= config.UMBRAL_EPSS_ALTO
    tabla["prioridad"] = tabla.apply(clasificar_prioridad, axis=1)
    tabla["riesgo"] = tabla.apply(calcular_riesgo, axis=1)

    return tabla


def resumen(tabla):
    """Cifras de control para verificar que el cruce salió bien."""
    lineas = []
    lineas.append(f"- Vulnerabilidades analizadas: **{len(tabla):,}**")

    con_cvss = tabla["cvss"].notna().sum()
    lineas.append(f"- Con puntaje CVSS: **{con_cvss:,}** ({con_cvss/len(tabla):.1%})")

    con_epss = (tabla["epss"] > 0).sum()
    lineas.append(f"- Con puntaje EPSS: **{con_epss:,}** ({con_epss/len(tabla):.1%})")

    explotadas = tabla["explotada"].sum()
    lineas.append(f"- Confirmadas como explotadas (KEV): **{explotadas:,}** "
                  f"({explotadas/len(tabla):.2%})")

    criticas = (tabla["cvss_banda"] == "Crítica").sum()
    lineas.append(f"- Clasificadas como críticas por CVSS: **{criticas:,}** "
                  f"({criticas/len(tabla):.1%})")
    return lineas


def main():
    tabla = unir()
    tabla.to_csv(config.ARCHIVO_UNIDO, index=False, encoding="utf-8")

    lineas = resumen(tabla)
    print("\n".join(lineas))
    print(f"\n[guardado] {config.ARCHIVO_UNIDO}")
    print("Siguiente paso: python src/analizar.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
