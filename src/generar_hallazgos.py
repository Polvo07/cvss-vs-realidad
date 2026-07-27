"""
Paso 4 — Hallazgos.

Calcula las cifras del análisis y las escribe en el README, entre los
marcadores HALLAZGOS. Se hace por código porque un número copiado a mano se
desactualiza en cuanto cambian los datos, y las tres fuentes cambian a diario.

Uso:
    python src/generar_hallazgos.py
"""

import re
import sys
from datetime import date

import pandas as pd

import config

INICIO = "<!-- HALLAZGOS:INICIO -->"
FIN = "<!-- HALLAZGOS:FIN -->"
README = config.RAIZ / "README.md"


def aciertos(datos, columna, cuantas):
    """Cuántas vulnerabilidades realmente explotadas caen en el top N según un criterio."""
    return int(datos.nlargest(cuantas, columna)["explotada"].sum())


def construir_seccion():
    datos = pd.read_csv(config.ARCHIVO_UNIDO)

    total = len(datos)
    explotadas = datos[datos["explotada"]]
    n_explotadas = len(explotadas)

    criticas = datos[datos["cvss_banda"] == "Crítica"]
    tasa_criticas = criticas["explotada"].mean() if len(criticas) else 0

    no_criticas = explotadas[explotadas["cvss_banda"] != "Crítica"]
    pct_no_criticas = len(no_criticas) / n_explotadas if n_explotadas else 0

    n = config.CAPACIDAD_PARCHEO
    por_cvss = aciertos(datos, "cvss", n)
    por_epss = aciertos(datos, "epss", n)
    por_riesgo = aciertos(datos, "riesgo_base", n)
    ventaja = por_epss / por_cvss if por_cvss else float("inf")

    epss_expl = explotadas["epss"].median()
    epss_resto = datos[~datos["explotada"]]["epss"].median()

    L = [INICIO, ""]
    L.append(f"*Cifras generadas automáticamente por `src/generar_hallazgos.py` el "
             f"{date.today():%d/%m/%Y}, sobre {total:,} vulnerabilidades publicadas "
             f"desde {config.FECHA_INICIO}.*")
    L.append("")

    L.append("| Indicador | Valor |")
    L.append("|---|---|")
    L.append(f"| Vulnerabilidades analizadas | {total:,} |")
    L.append(f"| Calificadas como críticas por CVSS | {len(criticas):,} |")
    L.append(f"| Confirmadas como explotadas (CISA KEV) | {n_explotadas:,} |")
    L.append(f"| **Críticas que llegaron a explotarse** | **{tasa_criticas:.2%}** |")
    L.append(f"| **Explotadas que NO eran críticas** | **{pct_no_criticas:.1%}** |")
    L.append(f"| Aciertos parchando {n} por CVSS | {por_cvss} |")
    L.append(f"| Aciertos parchando {n} por EPSS | {por_epss} |")
    L.append("")

    # --- Hallazgo 1 ---------------------------------------------------------
    L.append("### 1. Casi ninguna vulnerabilidad crítica llega a explotarse")
    L.append("")
    L.append(f"De las **{len(criticas):,}** vulnerabilidades calificadas como críticas "
             f"(CVSS ≥ 9,0), solo el **{tasa_criticas:.2%}** terminó apareciendo en el "
             "catálogo de explotación confirmada de CISA.")
    L.append("")
    L.append("Tasa de explotación por banda de severidad:")
    L.append("")
    L.append("| Banda CVSS | Vulnerabilidades | Explotadas | % explotado |")
    L.append("|---|---:|---:|---:|")
    for banda in ["Crítica", "Alta", "Media", "Baja", "Sin puntaje"]:
        grupo = datos[datos["cvss_banda"] == banda]
        if not len(grupo):
            continue
        expl = int(grupo["explotada"].sum())
        L.append(f"| {banda} | {len(grupo):,} | {expl:,} | {expl/len(grupo):.2%} |")
    L.append("")
    L.append("La severidad sí ordena el riesgo: lo crítico se explota más que lo bajo, "
             "y la tabla lo confirma. El problema es la escala. Marcar como urgentes a "
             f"{len(criticas):,} vulnerabilidades cuando el {1 - tasa_criticas:.1%} de "
             "ellas nunca se usará en un ataque no es priorizar: es repartir el esfuerzo "
             "al azar dentro de un grupo enorme.")
    L.append("")

    # --- Hallazgo 2 ---------------------------------------------------------
    L.append("### 2. La mayoría de las vulnerabilidades explotadas no son críticas")
    L.append("")
    L.append(f"De las **{n_explotadas:,}** que sí se están explotando, "
             f"**{len(no_criticas):,} ({pct_no_criticas:.1%})** no estaban calificadas "
             "como críticas. Un equipo que atienda solo lo crítico las deja sin parchar.")
    L.append("")
    L.append("| Severidad de las explotadas | Cantidad | % |")
    L.append("|---|---:|---:|")
    conteo = explotadas["cvss_banda"].value_counts()
    for banda in ["Crítica", "Alta", "Media", "Baja", "Sin puntaje"]:
        if banda in conteo.index:
            L.append(f"| {banda} | {conteo[banda]:,} | {conteo[banda]/n_explotadas:.1%} |")
    L.append("")
    L.append(f"El contraste con EPSS es nítido: la probabilidad mediana de las "
             f"vulnerabilidades explotadas es **{epss_expl:.4f}**, frente a "
             f"**{epss_resto:.4f}** en el resto. Una diferencia de "
             f"{epss_expl/epss_resto:.0f} veces.")
    L.append("")

    # --- Hallazgo 3 ---------------------------------------------------------
    L.append("### 3. Con el mismo esfuerzo, la probabilidad acierta mucho más")
    L.append("")
    L.append(f"Suponiendo capacidad para parchar **{n} vulnerabilidades**, se compara "
             "cuántas amenazas reales atrapa cada criterio. Ningún criterio consulta el "
             "catálogo KEV para ordenar: se mide qué tan bien predice sin conocer la "
             "respuesta.")
    L.append("")
    L.append("| Estrategia | Aciertos | % de las explotadas |")
    L.append("|---|---:|---:|")
    for nombre, valor in (("Por severidad (CVSS)", por_cvss),
                          ("Por probabilidad (EPSS)", por_epss),
                          ("Por riesgo combinado", por_riesgo)):
        L.append(f"| {nombre} | {valor} | {valor/n_explotadas:.1%} |")
    L.append("")
    if por_cvss:
        L.append(f"Priorizar por probabilidad encuentra **{ventaja:.0f} veces más "
                 "amenazas reales** que priorizar por severidad, con exactamente el "
                 "mismo esfuerzo.")
    L.append("")

    if por_epss > por_riesgo:
        L.append("Un resultado inesperado: **EPSS por sí solo supera al riesgo "
                 "combinado**. Multiplicar la probabilidad por la severidad no mejora "
                 "la predicción, la empeora ligeramente. Para anticipar explotación, el "
                 "CVSS no solo es insuficiente: como señal adicional, no aporta.")
        L.append("")

    L.append("La ventaja se mantiene al ampliar la capacidad:")
    L.append("")
    L.append("| Capacidad de parcheo | CVSS | EPSS | Riesgo combinado |")
    L.append("|---:|---:|---:|---:|")
    for cuantas in (50, 100, 250, 500, 1000):
        fila = [aciertos(datos, c, cuantas) for c in ("cvss", "epss", "riesgo_base")]
        L.append(f"| {cuantas:,} | {fila[0]} | {fila[1]} | {fila[2]} |")
    L.append("")

    # --- Honestidad metodológica --------------------------------------------
    L.append("### Qué NO demuestra este análisis")
    L.append("")
    L.append("El modelo de EPSS se entrena con señales de explotación observada, así que "
             "comparte información con el catálogo KEV. La comparación lo favorece por "
             "construcción y sería deshonesto presentarla como una predicción limpia.")
    L.append("")
    L.append("La conclusión defendible no es que EPSS sea infalible, sino la contraria: "
             "**la severidad por sí sola no basta para priorizar**, y existe información "
             "pública y gratuita que mejora esa decisión de forma sustancial.")
    L.append("")
    L.append(f"Además, el catálogo KEV recoge explotación confirmada y publicada. Hay "
             f"ataques que nunca llegan a él, así que las {n_explotadas:,} "
             "vulnerabilidades explotadas son un piso, no la cifra total.")
    L.append("")
    L.append(FIN)
    return "\n".join(L)


def main():
    if not config.ARCHIVO_UNIDO.exists():
        print(f"[error] Falta {config.ARCHIVO_UNIDO.name}. Ejecuta antes: python src/unir.py")
        return 1
    if not README.exists():
        print(f"[error] No se encontró {README}")
        return 1

    seccion = construir_seccion()
    texto = README.read_text(encoding="utf-8")

    if INICIO in texto and FIN in texto:
        patron = re.compile(re.escape(INICIO) + r".*?" + re.escape(FIN), re.DOTALL)
        README.write_text(patron.sub(seccion, texto), encoding="utf-8")
        print(f"[README] sección de hallazgos actualizada -> {README}")
    else:
        salida = config.DIR_DOCS / "hallazgos.md"
        salida.write_text(seccion, encoding="utf-8")
        print(f"[aviso] no se hallaron los marcadores en el README.")
        print(f"[guardado] sección escrita en {salida} para pegarla a mano")
    return 0


if __name__ == "__main__":
    sys.exit(main())
