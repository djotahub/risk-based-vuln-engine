# Risk-Based Vulnerability Prioritization Engine

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Focus-Zero%20Trust-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-green?style=for-the-badge)

## Visión General del Proyecto

En la gestión de ciberseguridad corporativa, los equipos de TI a menudo sufren de "fatiga de alertas" debido a reportes de escáneres que priorizan vulnerabilidades basándose únicamente en métricas técnicas (CVSS). Esto resulta en una asignación ineficiente de recursos, donde se prioriza el parcheo de activos irrelevantes sobre infraestructura crítica.

Este proyecto implementa un **Motor de Priorización de Riesgos** que ingesta datos técnicos brutos y los enriquece con el contexto del negocio. El resultado no es un simple reporte técnico, sino un **Plan de Remediación Estratégico** en formato CSV, listo para ser consumido por la gerencia y equipos de operaciones.



## 🧠 Lógica de Negocio y Metodología de Riesgo

Este motor implementa una estrategia de **Risk-Based Vulnerability Management (RBVM)**. A diferencia de los escaneos tradicionales que solo reportan la severidad técnica (CVSS Base Score), este sistema calcula un **"Risk Score Contextual"**.

La metodología sigue los principios de las **Métricas Ambientales (Environmental Metrics)** del estándar CVSS v3.1, donde la severidad final se ajusta basándose en la importancia del activo para la organización.

### Fórmula de Scoring Personalizada
El sistema utiliza un algoritmo de ponderación lineal para recalcular la prioridad:

$$Contextual Risk Score = CVSS_{Base} \times Asset_{Criticality Factor}$$

| Criticidad (CMDB) | Factor ($W$) | Alineación con NIST SP 800-30 |
| :--- | :--- | :--- |
| **ALTA** | **1.5** | Impacto Crítico en Confidencialidad/Integridad/Disponibilidad. |
| **MEDIA** | **1.2** | Impacto Moderado. Activos operativos estándar. |
| **BAJA** | **1.0** | Impacto Bajo. Riesgo técnico aislado sin impacto directo al negocio. |

> **Ejemplo de Impacto:**
> * Una vulnerabilidad crítica (CVSS 9.8) en una Impresora resulta en un Score de **9.8**.
> * Una vulnerabilidad alta (CVSS 9.0) en una Base de Datos resulta en un Score de **13.5**.
> * **Resultado:** El sistema fuerza la atención sobre la Base de Datos primero, alineando la seguridad con la continuidad del negocio.

### 2. Protocolo Zero Trust (Detección de Anomalías)
El sistema implementa una política de "confianza cero" para la validación de inventario:
* **Regla:** Todo activo detectado en el escaneo XML que no posea una entrada correspondiente en el archivo JSON de activos se clasifica automáticamente como **Rogue Device (Intruso)**.
* **Acción:** Estos dispositivos son segregados del cálculo de riesgo y se reportan en una sección de alerta máxima para su bloqueo inmediato.


## Especificaciones del Reporte de Salida (CSV)

El sistema genera un artefacto de auditoría llamado `reporte_seguridad_final.csv`. Este archivo está estructurado en dos segmentos lógicos para facilitar la toma de decisiones:

### Segmento A: Alertas de Seguridad (Actionable Intelligence)
Listado de dispositivos no autorizados detectados en la red.
* **IP Address:** Dirección de origen.
* **Vulnerability:** Hallazgo técnico asociado.
* **Required Action:** Acción recomendada (e.g., "BLOCK & INVESTIGATE").

### Segmento B: Matriz de Priorización (Remediation Plan)
Tabla principal ordenada descendentemente por el *Score de Prioridad de Negocio*.
* **Business Priority:** Puntaje recalculado (Resultado del algoritmo).
* **Asset Criticality:** Contexto del activo (ALTA/MEDIA/BAJA).
* **IP / Hostname:** Identificación del activo.
* **CVSS Base:** Puntaje técnico original (Referencia NIST).
* **Vulnerability Name:** Descripción del fallo.


##  Arquitectura Técnica

El proyecto sigue un diseño de pipeline de datos secuencial sin dependencias externas, garantizando portabilidad y seguridad en la cadena de suministro.

1.  **Ingesta (Data Ingestion):**
    * Parser XML personalizado para interpretar estándares de escaneo (simulación Nessus/Nmap).
    * Carga de diccionario JSON para el contexto de activos.
2.  **Procesamiento (Core Logic):**
    * Validación de existencia de claves (IPs).
    * Aplicación de aritmética de punto flotante para el cálculo de riesgo.
3.  **Exportación (Reporting):**
    * Uso de la librería `csv` para la generación de reportes estructurados compatibles con Microsoft Excel.



##  Guía de Ejecución

### Requisitos Previos
* Python 3.8 o superior.
* Archivos de entrada en el directorio raíz:
    * `activos_criticos.json` (Inventario).
    * `input_scan.xml` (Reporte Técnico).

### Comandos
1.  Clonar el repositorio:
    ```bash
    git clone [https://github.com/djotahub/risk-based-vuln-engine.git](https://github.com/djotahub/risk-based-vuln-engine.git)
    ```
2.  Ejecutar el motor:
    ```bash
    python vuln_prioritizer.py
    ```
3.  El resultado se guardará automáticamente como `reporte_seguridad_final.csv`.


---
## 👤 Author Identity

```json
{
  "user": "Qb1t",
  "role": "Security Automation Engineer",
  "status": "Building / Breaking / Fixing",
  "stack": ["Python", "Nmap", "Risk Analysis"],
  "contact": {
    "linkedin": "linkedin.com/in/david-jeferson",
    "github": "github.com/djotahub"
  }
}
