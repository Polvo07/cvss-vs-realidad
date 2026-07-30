"""Genera una muestra reproducible de la tabla de análisis.

`data/vulnerabilidades.csv` (~19 MB) es un derivado que reconstruye
`src/unir.py` cruzando EPSS, KEV y NVD, así que no se versiona. En su lugar se
versiona esta muestra de 5.000 filas con semilla fija: alcanza para inspeccionar
el esquema y las columnas derivadas sin descargar ni cruzar las tres fuentes
completas, y es reproducible byte a byte.

Uso:
    python src/generar_muestra.py
"""
from pathlib import Path

import pandas as pd

SEMILLA = 42
N_FILAS = 5000
RAIZ = Path(__file__).resolve().parent.parent
ORIGEN = RAIZ / "data" / "vulnerabilidades.csv"
DESTINO = RAIZ / "data" / "muestra_vulnerabilidades.csv"


def main() -> None:
    df = pd.read_csv(ORIGEN)
    n = min(N_FILAS, len(df))
    muestra = df.sample(n=n, random_state=SEMILLA).sort_index()
    muestra.to_csv(DESTINO, index=False, encoding="utf-8")
    print(f"[muestra] {n} de {len(df)} filas -> {DESTINO.relative_to(RAIZ)}")


if __name__ == "__main__":
    main()
