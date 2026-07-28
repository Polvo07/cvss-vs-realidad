"""
Guarda la salida del análisis y de la herramienta como evidencia en docs/.

Se corre una vez, después del pipeline completo, para dejar en el repositorio
la prueba de que el análisis produjo los números que reporta el README.

Uso:
    python src/guardar_evidencia.py
"""

import contextlib
import io
import sys

import config
import analizar
import priorizar


def main():
    if not config.ARCHIVO_UNIDO.exists():
        print(f"[error] Falta {config.ARCHIVO_UNIDO.name}. Ejecuta antes: python src/unir.py")
        return 1

    # 1) Salida completa del análisis
    salida_analisis = io.StringIO()
    with contextlib.redirect_stdout(salida_analisis):
        analizar.main()
    ruta1 = config.DIR_DOCS / "analisis_salida.txt"
    ruta1.write_text(salida_analisis.getvalue(), encoding="utf-8")
    print(f"[guardado] {ruta1}")

    # 2) Ejemplo de la herramienta de priorización
    ejemplo = config.RAIZ / "data" / "ejemplo_inventario.txt"
    if ejemplo.exists():
        identificadores = priorizar.leer_lista(ejemplo)
        encontradas, faltantes = priorizar.priorizar(identificadores)
        salida_prior = io.StringIO()
        with contextlib.redirect_stdout(salida_prior):
            priorizar.imprimir(encontradas, faltantes, len(identificadores))
        ruta2 = config.DIR_DOCS / "priorizar_ejemplo.txt"
        ruta2.write_text(salida_prior.getvalue(), encoding="utf-8")
        print(f"[guardado] {ruta2}")

    return 0


if __name__ == "__main__":
    sys.exit(main())