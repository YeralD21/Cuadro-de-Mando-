# Dashboard de Ciberseguridad

Dashboard interactivo para análisis de tráfico de red y detección de amenazas cibernéticas.

## Características

- **Análisis de flujos de red**: Visualización de métricas de tráfico (duración, paquetes, bytes/s, etc.)
- **Detección de amenazas**: Identificación de patrones sospechosos mediante heurísticas
- **Balanceo de datos**: Implementación de SMOTE para manejar desbalance de clases
- **Visualizaciones interactivas**: Gráficos dinámicos con Plotly
- **Análisis estadístico**: Estadísticas descriptivas y correlaciones entre variables

## Requisitos

```bash
pip install streamlit pandas numpy plotly imbalanced-learn scikit-learn
```

## Uso

```bash
streamlit run streamlit_app.py
```

La aplicación se abrirá en `http://localhost:8501`

## Estructura

- `streamlit_app.py`: Aplicación principal de Streamlit
- `datamart_ciberseguridad_listo.csv`: Dataset con métricas de flujos de red
- `.gitignore`: Archivos excluidos del control de versiones

## Dataset

El dataset contiene las siguientes variables:
- `Flow Duration`: Duración del flujo en microsegundos
- `Total Fwd Packets`: Total de paquetes forward
- `Total Length of Fwd Packets`: Longitud total de paquetes forward
- `Flow Bytes/s`: Bytes por segundo del flujo
- `Flow IAT Mean`: Media del tiempo entre llegadas
- `Fwd Packet Length Mean`: Media de longitud de paquetes forward
- `Bwd Packet Length Mean`: Media de longitud de paquetes backward
- `is_threat`: Etiqueta binaria (0: normal, 1: amenaza)

