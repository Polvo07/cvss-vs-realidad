# ¿Sirve el CVSS para priorizar parches?

Análisis de datos aplicado a la gestión de vulnerabilidades. Cruza tres fuentes
públicas oficiales para responder una pregunta operativa: cuando un equipo de
seguridad solo puede parchar unas pocas vulnerabilidades al mes, ¿qué criterio
acierta más?

---

## El problema

Casi todas las organizaciones priorizan qué parchar según el **CVSS**, el
puntaje de severidad de 0 a 10 que publica el NIST. Es lo que enseñan los cursos
y lo que exigen muchas auditorías.

El problema es qué mide ese puntaje: el CVSS estima **qué tan grave sería** una
vulnerabilidad si alguien la explotara. No estima **qué tan probable es** que
alguien la explote.

Y esas dos cosas se parecen mucho menos de lo que uno esperaría. Cada año se
publican decenas de miles de vulnerabilidades calificadas como críticas, pero
solo una fracción diminuta llega a usarse en ataques reales. Mientras tanto,
algunas vulnerabilidades de severidad media se explotan masivamente.

Este proyecto mide ese desajuste con datos.

---

## Las fuentes

Las tres son públicas, gratuitas y de referencia en la industria.

| Fuente | Qué aporta | Volumen |
|---|---|---|
| **[NVD](https://nvd.nist.gov/)** (NIST) | Puntaje CVSS: qué tan grave sería | ~120.000 |
| **[EPSS](https://www.first.org/epss/)** (FIRST.org) | Probabilidad de explotación en 30 días | ~240.000 |
| **[KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** (CISA) | Vulnerabilidades que **sí** se están explotando | ~1.300 |

El KEV es la pieza clave del análisis: es la verdad de campo. Al saber cuáles se
explotan de verdad, se puede medir qué tan bien acierta cada criterio de
priorización en lugar de discutirlo en abstracto.

---

## Las preguntas

1. De las vulnerabilidades calificadas como **críticas** por CVSS, ¿qué
   porcentaje se explota realmente?
2. De las que **sí se explotan**, ¿cuántas el CVSS habría dejado en segundo
   plano por considerarlas medias o bajas?
3. Con capacidad para parchar 100 vulnerabilidades al mes, ¿qué estrategia
   atrapa más amenazas reales: las 100 de mayor CVSS o las 100 de mayor EPSS?

---

## Hallazgos

<!-- HALLAZGOS:INICIO -->

*Pendiente: se completa al ejecutar el análisis.*

<!-- HALLAZGOS:FIN -->

---

## Cómo funciona la priorización

El pipeline clasifica cada vulnerabilidad en cuatro niveles, en un orden que
refleja cómo decide un equipo de seguridad en la práctica:

| Nivel | Criterio | Razonamiento |
|---|---|---|
| **1 · Explotada activamente** | Aparece en KEV | No hay nada que discutir: ya se está usando en ataques |
| **2 · Explotación probable** | EPSS ≥ 0,10 | El riesgo es inminente aunque aún no haya ataques registrados |
| **3 · Grave sin explotación** | CVSS ≥ 9,0 | Peligrosa en teoría, pero nadie la está usando |
| **4 · Seguimiento normal** | El resto | |

Además se calcula un **puntaje de riesgo** de 0 a 10 que multiplica severidad por
probabilidad. La lógica: una vulnerabilidad importa cuando es grave **y**
probable. Un 9,8 de severidad con probabilidad casi nula produce un riesgo bajo,
que es exactamente lo que el CVSS por sí solo no refleja.

---

## Arquitectura

```
NVD  ─┐
EPSS ─┼─► descargar.py ──► data/*.csv ──► unir.py ──► vulnerabilidades.csv
KEV  ─┘                                                      │
                                          ┌──────────────────┴──────────────┐
                                          ▼                                 ▼
                                    analizar.py                      priorizar.py
                                  responde las preguntas        herramienta de uso diario
```

---

## Cómo reproducirlo

Requisitos: Python 3.10+

```bash
git clone https://github.com/Polvo07/cvss-vs-realidad.git
cd cvss-vs-realidad
pip install -r requirements.txt

python src/test_unir.py          # verifica la lógica antes de descargar nada

# Opcional pero recomendado: llave gratuita del NVD, acelera mucho la descarga
# https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="tu_llave"

python src/descargar.py kev      # rápido, unos segundos
python src/descargar.py epss     # rápido, unos 10 MB
python src/descargar.py nvd      # lento: 10-20 min por los límites de la API

python src/unir.py               # cruza las tres fuentes
```

---

## Sobre el alcance

El análisis cubre vulnerabilidades **publicadas desde 2023**. La pregunta es
operativa —cómo priorizar lo que llega hoy—, no un repaso del histórico
completo. Acotar el periodo también hace la descarga manejable dentro de los
límites de la API del NVD.

---

## Stack

Python (pandas, requests) · APIs REST · Git

---

## Autor

**Andrés Felipe Domínguez Pallares** — Estudiante de Ingeniería Multimedia,
Universidad Simón Bolívar.
[LinkedIn](https://www.linkedin.com/in/andres-dominguez-4877a51b8/) ·
[GitHub](https://github.com/Polvo07)
