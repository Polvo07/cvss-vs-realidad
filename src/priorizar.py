"""
Herramienta de priorización.

Recibe una lista de vulnerabilidades y devuelve el orden en que conviene
parcharlas, con el motivo de cada decisión.

Uso:
    python src/priorizar.py mis_cves.txt
    python src/priorizar.py mis_cves.txt --csv salida.csv

El archivo de entrada es texto plano con un identificador por línea. Se ignoran
las líneas vacías y las que empiezan con #.

    # inventario de ejemplo
    CVE-2024-3400
    CVE-2023-4966
"""

import argparse
import sys

import pandas as pd

import config


def leer_lista(ruta):
    """Lee los identificadores del archivo, uno por línea."""
    identificadores = []
    with open(ruta, encoding="utf-8") as archivo:
        for linea in archivo:
            limpia = linea.strip().upper()
            if limpia and not limpia.startswith("#"):
                identificadores.append(limpia)
    # Se quitan repetidos conservando el orden de aparición
    return list(dict.fromkeys(identificadores))


def priorizar(identificadores):
    """
    Busca cada vulnerabilidad en la base y las ordena por riesgo operativo.

    Aquí sí se usa el catálogo de explotación confirmada: para decidir qué
    parchar primero, saber que algo ya se está usando en ataques es la
    información más valiosa que existe.
    """
    if not config.ARCHIVO_UNIDO.exists():
        raise FileNotFoundError(
            f"Falta {config.ARCHIVO_UNIDO.name}. Ejecuta antes: python src/unir.py")

    base = pd.read_csv(config.ARCHIVO_UNIDO)
    encontradas = base[base["cve"].isin(identificadores)].copy()
    faltantes = sorted(set(identificadores) - set(encontradas["cve"]))

    encontradas = encontradas.sort_values(
        ["prioridad", "riesgo"], ascending=[True, False])
    return encontradas, faltantes


def imprimir(encontradas, faltantes, total_pedidas):
    print(f"\nSe consultaron {total_pedidas} vulnerabilidades · "
          f"{len(encontradas)} encontradas en la base\n")

    if not len(encontradas):
        print("Ninguna apareció en la base. Revisa el formato: CVE-AAAA-NNNNN")
        return

    ancho = 78
    for nivel in sorted(encontradas["prioridad"].unique()):
        grupo = encontradas[encontradas["prioridad"] == nivel]
        print("=" * ancho)
        print(f"{nivel}  ({len(grupo)})")
        print("=" * ancho)
        for _, f in grupo.iterrows():
            cvss = "n/d" if pd.isna(f["cvss"]) else f"{f['cvss']:.1f}"
            print(f"  {f['cve']:<18s} CVSS {cvss:>4s} · "
                  f"EPSS {f['epss']:.4f} · riesgo {f['riesgo']:.2f}")
            if f["explotada"]:
                producto = f"{f['kev_fabricante']} {f['kev_producto']}".strip()
                extra = " · usada en ransomware" if f.get("kev_ransomware") == "Known" else ""
                print(f"                     explotada activamente en {producto}{extra}")
        print()

    if faltantes:
        print("-" * ancho)
        print(f"No encontradas ({len(faltantes)}):")
        print("  " + ", ".join(faltantes[:15]) + ("..." if len(faltantes) > 15 else ""))
        print("  Puede ser que se publicaran antes de "
              f"{config.FECHA_INICIO} o que el identificador esté mal escrito.")


def main():
    parser = argparse.ArgumentParser(
        description="Ordena una lista de vulnerabilidades por prioridad de parcheo.")
    parser.add_argument("archivo", help="Archivo de texto con un CVE por línea.")
    parser.add_argument("--csv", default=None,
                        help="Guarda el resultado ordenado en un CSV.")
    args = parser.parse_args()

    identificadores = leer_lista(args.archivo)
    if not identificadores:
        print("El archivo no tiene identificadores válidos.")
        return 1

    encontradas, faltantes = priorizar(identificadores)
    imprimir(encontradas, faltantes, len(identificadores))

    if args.csv:
        columnas = ["cve", "prioridad", "riesgo", "cvss", "cvss_banda",
                    "epss", "explotada", "kev_fabricante", "kev_producto"]
        columnas = [c for c in columnas if c in encontradas.columns]
        encontradas[columnas].to_csv(args.csv, index=False, encoding="utf-8")
        print(f"[guardado] {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
