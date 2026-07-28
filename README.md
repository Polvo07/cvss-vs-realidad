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

*Cifras generadas automáticamente por `src/generar_hallazgos.py` el 28/07/2026, sobre 166,776 vulnerabilidades publicadas desde 2023-01-01.*

| Indicador | Valor |
|---|---|
| Vulnerabilidades analizadas | 166,776 |
| Calificadas como críticas por CVSS | 15,943 |
| Confirmadas como explotadas (CISA KEV) | 624 |
| **Críticas que llegaron a explotarse** | **1.57%** |
| **Explotadas que NO eran críticas** | **59.9%** |
| Aciertos parchando 100 por CVSS | 4 |
| Aciertos parchando 100 por EPSS | 84 |

### 1. Casi ninguna vulnerabilidad crítica llega a explotarse

De las **15,943** vulnerabilidades calificadas como críticas (CVSS ≥ 9,0), solo el **1.57%** terminó apareciendo en el catálogo de explotación confirmada de CISA.

Tasa de explotación por banda de severidad:

| Banda CVSS | Vulnerabilidades | Explotadas | % explotado |
|---|---:|---:|---:|
| Crítica | 15,943 | 250 | 1.57% |
| Alta | 55,947 | 286 | 0.51% |
| Media | 77,270 | 84 | 0.11% |
| Baja | 9,766 | 4 | 0.04% |
| Sin puntaje | 7,850 | 0 | 0.00% |

La severidad sí ordena el riesgo: lo crítico se explota más que lo bajo, y la tabla lo confirma. El problema es la escala. Marcar como urgentes a 15,943 vulnerabilidades cuando el 98.4% de ellas nunca se usará en un ataque no es priorizar: es repartir el esfuerzo al azar dentro de un grupo enorme.

### 2. La mayoría de las vulnerabilidades explotadas no son críticas

De las **624** que sí se están explotando, **374 (59.9%)** no estaban calificadas como críticas. Un equipo que atienda solo lo crítico las deja sin parchar.

| Severidad de las explotadas | Cantidad | % |
|---|---:|---:|
| Crítica | 250 | 40.1% |
| Alta | 286 | 45.8% |
| Media | 84 | 13.5% |
| Baja | 4 | 0.6% |

El contraste con EPSS es nítido: la probabilidad mediana de las vulnerabilidades explotadas es **0.4059**, frente a **0.0033** en el resto. Una diferencia de 123 veces.

### 3. Con el mismo esfuerzo, la probabilidad acierta mucho más

Suponiendo capacidad para parchar **100 vulnerabilidades**, se compara cuántas amenazas reales atrapa cada criterio. Ningún criterio consulta el catálogo KEV para ordenar: se mide qué tan bien predice sin conocer la respuesta.

| Estrategia | Aciertos | % de las explotadas |
|---|---:|---:|
| Por severidad (CVSS) | 4 | 0.6% |
| Por probabilidad (EPSS) | 84 | 13.5% |
| Por riesgo combinado | 80 | 12.8% |

Priorizar por probabilidad encuentra **21 veces más amenazas reales** que priorizar por severidad, con exactamente el mismo esfuerzo.

Un resultado inesperado: **EPSS por sí solo supera al riesgo combinado**. Multiplicar la probabilidad por la severidad no mejora la predicción, la empeora ligeramente. Para anticipar explotación, el CVSS no solo es insuficiente: como señal adicional, no aporta.

La ventaja se mantiene al ampliar la capacidad:

| Capacidad de parcheo | CVSS | EPSS | Riesgo combinado |
|---:|---:|---:|---:|
| 50 | 0 | 47 | 48 |
| 100 | 4 | 84 | 80 |
| 250 | 8 | 171 | 170 |
| 500 | 21 | 241 | 227 |
| 1,000 | 46 | 302 | 292 |

### Qué NO demuestra este análisis

El modelo de EPSS se entrena con señales de explotación observada, así que comparte información con el catálogo KEV. La comparación lo favorece por construcción y sería deshonesto presentarla como una predicción limpia.

La conclusión defendible no es que EPSS sea infalible, sino la contraria: **la severidad por sí sola no basta para priorizar**, y existe información pública y gratuita que mejora esa decisión de forma sustancial.

Además, el catálogo KEV recoge explotación confirmada y publicada. Hay ataques que nunca llegan a él, así que las 624 vulnerabilidades explotadas son un piso, no la cifra total.

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
```

**La llave del NVD** es opcional pero muy recomendable: sin ella la descarga
tarda alrededor del triple. Se pide gratis en
[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
y se configura como variable de entorno, con sintaxis distinta según el sistema:

```bash
# Linux y macOS
export NVD_API_KEY="tu_llave"
```

```bat
:: Windows (símbolo del sistema), solo para la ventana actual
set NVD_API_KEY=tu_llave

:: Windows, de forma permanente. Aplica solo a ventanas nuevas.
setx NVD_API_KEY tu_llave
```

La llave nunca se escribe en el código: `config.py` guarda el nombre de la
variable de entorno, no su contenido.

```bash
python src/descargar.py kev      # segundos
python src/descargar.py epss     # un minuto, unos 10 MB comprimidos
python src/descargar.py nvd      # 5-20 min según haya llave o no

python src/unir.py               # cruza las tres fuentes
python src/analizar.py           # responde las tres preguntas
python src/generar_hallazgos.py  # escribe las cifras en este README
```

Si el NVD responde con error, `python src/diagnostico.py` prueba la conexión por
pasos y aísla si el problema es el endpoint, la llave o el rango de fechas.

---

## La herramienta

Además del análisis, el repositorio incluye una herramienta de uso diario:
recibe una lista de vulnerabilidades y devuelve el orden en que conviene
parcharlas, con el motivo de cada decisión.

```bash
python src/priorizar.py data/ejemplo_inventario.txt
python src/priorizar.py mis_cves.txt --csv resultado.csv
```

El archivo de entrada es texto plano con un identificador por línea. Salida
resumida:

```
========================================================
1 - Explotada activamente  (2)
========================================================
  CVE-2024-3400      CVSS 10.0 · EPSS 0.9400 · riesgo 10.00
                     explotada activamente en Palo Alto Networks PAN-OS · usada en ransomware
  CVE-2023-4966      CVSS  7.5 · EPSS 0.8800 · riesgo 10.00
                     explotada activamente en Citrix NetScaler · usada en ransomware

========================================================
3 - Grave pero sin explotación conocida  (1)
========================================================
  CVE-2024-21762     CVSS  9.8 · EPSS 0.0020 · riesgo 0.02
```

El ejemplo resume el proyecto entero: priorizando por severidad se atendería
primero la de 9,8, mientras que la de 7,5 —que ya se está usando en ataques de
ransomware— quedaría esperando.

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
