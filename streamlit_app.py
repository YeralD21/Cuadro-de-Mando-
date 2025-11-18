from pathlib import Path
from typing import Optional, Union

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit.runtime.uploaded_file_manager import UploadedFile

from imblearn.over_sampling import SMOTE
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score


DATA_PATH = Path("/Users/usuario/Documents/CUADRO/datamart_ciberseguridad_listo.csv")
LABEL_COL = "is_threat"
RISK_LEVELS = ["Bajo", "Medio", "Alto"]


@st.cache_data(show_spinner=False, hash_funcs={UploadedFile: lambda f: f.file_id})
def load_data(uploaded_file: Optional[Union[Path, UploadedFile]] = None) -> pd.DataFrame:
    if uploaded_file is not None:
        return pd.read_csv(uploaded_file)
    if DATA_PATH.exists():
        return pd.read_csv(DATA_PATH)
    raise FileNotFoundError(
        "No se encontró el dataset. Sube un archivo CSV desde la barra lateral."
    )


def balance_data(df: pd.DataFrame) -> pd.DataFrame:
    smote = SMOTE(random_state=42)
    features = df.drop(columns=[LABEL_COL])
    target = df[LABEL_COL]
    features_res, target_res = smote.fit_resample(features, target)
    balanced_df = pd.DataFrame(features_res, columns=features.columns)
    balanced_df[LABEL_COL] = target_res
    return balanced_df


def enrich_with_cyber_features(df: pd.DataFrame) -> pd.DataFrame:
    enriched = df.copy()
    duration_seconds = enriched["Flow Duration"].replace(0, np.nan) / 1_000_000
    enriched["Flow Duration (s)"] = duration_seconds.fillna(0)
    enriched["Forward Packets/s (calc)"] = (
        enriched["Total Fwd Packets"] / duration_seconds
    ).replace([np.inf, -np.inf], np.nan).fillna(0)
    enriched["Payload Ratio"] = (
        enriched["Total Length of Fwd Packets"].replace(0, np.nan)
        / enriched["Total Fwd Packets"].replace(0, np.nan)
    ).fillna(0)

    risk_inputs = [
        "Flow Bytes/s",
        "Forward Packets/s (calc)",
        "Flow Duration (s)",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
    ]
    z_scores = {}
    for col in risk_inputs:
        mean = enriched[col].mean()
        std = enriched[col].std() or 1.0
        z_scores[col] = (enriched[col] - mean) / std

    risk_score = (
        z_scores["Flow Bytes/s"].clip(lower=0)
        + z_scores["Forward Packets/s (calc)"].clip(lower=0)
        + (-z_scores["Flow Duration (s)"]).clip(lower=0)
        + (-z_scores["Fwd Packet Length Mean"]).clip(lower=0)
        + (-z_scores["Bwd Packet Length Mean"]).clip(lower=0)
    )
    enriched["Risk Score (raw)"] = risk_score
    if risk_score.max() > risk_score.min():
        enriched["Risk Score"] = (risk_score - risk_score.min()) / (
            risk_score.max() - risk_score.min()
        )
    else:
        enriched["Risk Score"] = 0.0
    enriched["Risk Level"] = (
        pd.cut(
            enriched["Risk Score"],
            bins=[-np.inf, 0.33, 0.66, np.inf],
            labels=RISK_LEVELS,
        )
        .astype(str)
        .replace("nan", "Bajo")
    )

    enriched["Heurística: ráfaga rápida"] = (
        (enriched["Flow Duration (s)"] <= 0.002)
        & (
            enriched["Total Fwd Packets"]
            >= enriched["Total Fwd Packets"].quantile(0.75)
        )
    )
    enriched["Heurística: paquetes diminutos"] = (
        (enriched["Fwd Packet Length Mean"] <= enriched["Fwd Packet Length Mean"].quantile(0.25))
        & (
            enriched["Forward Packets/s (calc)"]
            >= enriched["Forward Packets/s (calc)"].quantile(0.75)
        )
    )
    enriched["Heurística: bytes explosivos"] = (
        enriched["Flow Bytes/s"] >= enriched["Flow Bytes/s"].quantile(0.99)
    )
    return enriched


def render_overview(df: pd.DataFrame, dataset_label: str) -> None:
    st.subheader("Visión general")
    st.caption(
        f"Resumen ejecutivo del dataset ({dataset_label}). "
        "Estas métricas ayudan a dimensionar el volumen de tráfico y el nivel de riesgo."
    )
    total_rows, total_cols = df.shape
    threat_ratio = df[LABEL_COL].mean() * 100
    avg_duration = df["Flow Duration"].mean()
    median_packets = df["Total Fwd Packets"].median()
    mean_bytes = df["Flow Bytes/s"].mean()

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Total de flujos", f"{total_rows:,}")
    kpi2.metric("Variables monitorizadas", total_cols)
    kpi3.metric("Amenazas detectadas", f"{int(df[LABEL_COL].eq(1).sum()):,}")
    kpi4.metric("Amenazas (%)", f"{threat_ratio:.2f}")

    gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=max(threat_ratio, 0.01),
            title={"text": "Índice de Riesgo (Amenazas %)"},
            gauge={
                "axis": {"range": [0, max(5, threat_ratio * 1.5)]},
                "steps": [
                    {"range": [0, 1], "color": "#3CB371"},
                    {"range": [1, 3], "color": "#FFD700"},
                    {"range": [3, max(5, threat_ratio * 1.5)], "color": "#FF6347"},
                ],
            },
        )
    )
    st.plotly_chart(gauge, use_container_width=True)

    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Duración media de flujo (μs)", f"{avg_duration:,.0f}")
    col_b.metric("Mediana paquetes Fwd", f"{median_packets:,.0f}")
    col_c.metric("Bytes promedio por segundo", f"{mean_bytes:,.0f}")

    st.write("Vista previa de los primeros registros:")
    st.dataframe(df.head(10), use_container_width=True)


def render_class_distribution(df: pd.DataFrame) -> None:
    st.subheader("Distribución de clases")
    st.caption(
        "Compara la cantidad de observaciones etiquetadas como tráfico normal frente "
        "a amenazas. Útil para detectar desbalance de clases antes de entrenar modelos."
    )
    counts = (
        df[LABEL_COL]
            .value_counts()
            .rename_axis(LABEL_COL)
            .reset_index(name="count")
            .replace({LABEL_COL: {0: "Normal", 1: "Amenaza"}})
    )
    fig = px.bar(
        counts,
        x=LABEL_COL,
        y="count",
        labels={LABEL_COL: "Clase", "count": "Número de registros"},
        text_auto=True,
    )
    fig.update_layout(yaxis_title="Número de registros", xaxis_title="Clase")
    st.plotly_chart(fig, use_container_width=True)


def render_statistics(df: pd.DataFrame) -> None:
    st.subheader("Estadísticas descriptivas")
    st.caption(
        "Tabla de medidas básicas (mínimo, máximo, cuartiles, media y desviación) "
        "para cada variable numérica. Permite detectar rangos, escalas y posibles "
        "outliers extremos."
    )
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    st.write("Resumen estadístico para variables numéricas:")
    st.dataframe(df[numeric_cols].describe().T, use_container_width=True)

    median_duration = df["Flow Duration"].median()
    p75_duration = df["Flow Duration"].quantile(0.75)
    max_duration = df["Flow Duration"].max()
    median_packets = df["Total Fwd Packets"].median()
    p75_packets = df["Total Fwd Packets"].quantile(0.75)
    max_packets = df["Total Fwd Packets"].max()
    median_fwd_size = df["Fwd Packet Length Mean"].median()
    median_bwd_size = df["Bwd Packet Length Mean"].median()
    threat_share = df[LABEL_COL].mean() * 100

    st.markdown(
        f"""
        **Interpretación rápida**
        - `Flow Duration` presenta una mediana de {median_duration:,.0f} μs (≈{median_duration/1e6:.2f} s); el 75 % de los flujos dura menos de {p75_duration:,.0f} μs, pero hay outliers que alcanzan {max_duration:,.0f} μs (≈{max_duration/1e6:.2f} s). Esto evidencia colas muy largas que pueden requerir transformaciones logarítmicas.
        - El tráfico suele implicar pocos paquetes (`Total Fwd Packets`: mediana {median_packets:,.0f}, 75 % bajo {p75_packets:,.0f}), aunque existen sesiones masivas de hasta {max_packets:,.0f} paquetes.
        - Los tamaños medios de paquete son reducidos (medianas {median_fwd_size:,.0f} y {median_bwd_size:,.0f} bytes), lo que concuerda con ráfagas cortas detectadas en amenazas.
        - Solo {threat_share:.2f} % de los registros está marcado como amenaza, por lo que el dataset es altamente desbalanceado y requerirá técnicas de balanceo o métricas específicas.
        """
    )

    st.write("Selecciona una variable para explorar su distribución:")
    st.caption(
        "El histograma muestra la distribución de valores segmentada por clase; "
        "el boxplot realza rangos típicos y outliers para cada etiqueta."
    )
    selected_col = st.selectbox("Variable numérica", numeric_cols, index=0)
    col1, col2 = st.columns(2)

    hist_fig = px.histogram(
        df,
        x=selected_col,
        color=df[LABEL_COL].map({0: "Normal", 1: "Amenaza"}),
        nbins=40,
        barmode="overlay",
        opacity=0.6,
        labels={selected_col: selected_col, "color": "Clase"},
    )
    hist_fig.update_layout(legend_title="Clase")
    col1.plotly_chart(hist_fig, use_container_width=True)

    box_fig = px.box(
        df,
        x=df[LABEL_COL].map({0: "Normal", 1: "Amenaza"}),
        y=selected_col,
        points="suspectedoutliers",
        labels={"x": "Clase", selected_col: selected_col},
    )
    col2.plotly_chart(box_fig, use_container_width=True)

    st.markdown("#### Diferencias de medias normalizadas")
    class_means = df.groupby(LABEL_COL)[numeric_cols].mean()
    std = df[numeric_cols].std().replace(0, np.nan)
    standardized_diff = (
        (class_means.loc[1] - class_means.loc[0]) / std
    ).dropna().sort_values(key=np.abs, ascending=False)
    diff_fig = px.bar(
        standardized_diff,
        labels={"value": "Diferencia (desviaciones estándar)", "index": "Variable"},
        color=standardized_diff,
        color_continuous_scale="RdBu",
    )
    diff_fig.update_layout(coloraxis_showscale=False)
    st.plotly_chart(diff_fig, use_container_width=True)


def render_correlations(df: pd.DataFrame) -> None:
    st.subheader("Correlaciones")
    st.caption(
        "Mapa de calor con la correlación de Pearson entre variables numéricas. "
        "El degradado rojo→blanco→azul representa magnitudes de 0 (sin relación) a 1 "
        "(correlación positiva perfecta); cuanto más azul es el recuadro, más tienden "
        "a aumentar ambas variables a la vez. Ayuda a detectar colinealidad o relaciones fuertes."
    )
    numeric_df = df.select_dtypes(include=[np.number]).drop(columns=[LABEL_COL])
    corr = numeric_df.corr()
    fig = px.imshow(
        corr,
        color_continuous_scale="RdBu",
        origin="lower",
        aspect="auto",
        labels=dict(color="Correlación"),
    )
    st.plotly_chart(fig, use_container_width=True)

    strongest = (
        corr.abs()
        .where(np.triu(np.ones(corr.shape), k=1).astype(bool))
        .stack()
        .sort_values(ascending=False)
        .head(3)
    )
    explanations = []
    for (feat_a, feat_b), value in strongest.items():
        sign = corr.loc[feat_a, feat_b]
        trend = "positiva" if sign > 0 else "negativa"
        strength = "moderada" if abs(sign) < 0.7 else "fuerte"
        direction = (
            "cuando una variable aumenta, la otra también lo hace"
            if sign > 0
            else "cuando una variable aumenta, la otra tiende a disminuir"
        )
        insight = ""
        if {"Total Length of Fwd Packets", "Fwd Packet Length Mean"} == {feat_a, feat_b}:
            insight = (
                " Esto refleja que si un flujo envía muchos bytes hacia adelante, "
                "los paquetes individuales también tienden a ser más grandes; en "
                "escenarios de ciberseguridad puede indicar transferencias voluminosas "
                "como exfiltración de datos."
            )
        elif {"Flow Duration", "Flow IAT Mean"} == {feat_a, feat_b}:
            insight = (
                " Flujos muy largos suelen traer intervalos medios entre paquetes más "
                "amplios; patrones así pueden corresponder a conexiones persistentes "
                "como escaneos lentos o beaconing controlado."
        )
        elif {"Total Fwd Packets", "Bwd Packet Length Mean"} == {feat_a, feat_b}:
            insight = (
                " Cuando se envían muchos paquetes hacia adelante, las respuestas "
                "tienden a contener paquetes más grandes; podría ser síntoma de "
                "servicios que devuelven grandes bloques tras múltiples solicitudes, "
                "útil para distinguir tráfico legítimo masivo de ataques de sondeo."
        )
        explanations.append(
            f"- **{feat_a} ↔ {feat_b}**: correlación {trend} {strength} de {sign:.2f}, "
            f"{direction}. Puede bastar con usar solo uno de los campos para evitar "
            f"multicolinealidad en modelos lineales.{insight}"
        )
    st.markdown(
        "**Lectura sugerida**\n"
        + "\n".join(explanations)
        + "\n- Valores cercanos a cero indican variables prácticamente independientes, "
        "lo que puede aportar información complementaria a los modelos.\n"
        "- Como regla práctica: |r| < 0.3 implica relación débil, 0.3 ≤ |r| < 0.7 "
        "relación moderada y |r| ≥ 0.7 relación fuerte."
    )


def render_flow_analysis(df: pd.DataFrame) -> None:
    st.subheader("Análisis interactivo de flujos")
    st.caption(
        "Utiliza los filtros para aislar subconjuntos interesantes y comparar cómo se comportan los indicadores."
    )

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    col_filter1, col_filter2 = st.columns(2)
    duration_range = col_filter1.slider(
        "Filtrar por duración de flujo (μs)",
        min_value=float(df["Flow Duration"].min()),
        max_value=float(df["Flow Duration"].max()),
        value=(
            float(df["Flow Duration"].quantile(0.05)),
            float(df["Flow Duration"].quantile(0.95)),
        ),
        step=1.0,
    )
    packets_range = col_filter2.slider(
        "Filtrar por total de paquetes forward",
        min_value=float(df["Total Fwd Packets"].min()),
        max_value=float(df["Total Fwd Packets"].max()),
        value=(
            float(df["Total Fwd Packets"].quantile(0.05)),
            float(df["Total Fwd Packets"].quantile(0.95)),
        ),
        step=1.0,
    )

    filtered = df[
        df["Flow Duration"].between(*duration_range)
        & df["Total Fwd Packets"].between(*packets_range)
    ]

    if filtered.empty:
        st.warning("No hay registros que cumplan con los filtros seleccionados.")
        return

    scatter_x = st.selectbox(
        "Eje X (scatter)",
        numeric_cols,
        index=numeric_cols.index("Flow Duration") if "Flow Duration" in numeric_cols else 0,
    )
    scatter_y = st.selectbox(
        "Eje Y (scatter)",
        numeric_cols,
        index=numeric_cols.index("Flow Bytes/s") if "Flow Bytes/s" in numeric_cols else 1,
    )

    scatter_fig = px.scatter(
        filtered,
        x=scatter_x,
        y=scatter_y,
        color=filtered[LABEL_COL].map({0: "Normal", 1: "Amenaza"}),
        opacity=0.7,
        labels={scatter_x: scatter_x, scatter_y: scatter_y, "color": "Clase"},
        hover_data=numeric_cols,
    )
    st.plotly_chart(scatter_fig, use_container_width=True)

    st.markdown("#### Histogramas comparativos")
    hist_col = st.selectbox(
        "Variable para histograma",
        numeric_cols,
        index=numeric_cols.index("Flow Duration") if "Flow Duration" in numeric_cols else 0,
    )
    hist_comp = px.histogram(
        filtered,
        x=hist_col,
        color=filtered[LABEL_COL].map({0: "Normal", 1: "Amenaza"}),
        barmode="overlay",
        nbins=40,
        opacity=0.6,
        labels={hist_col: hist_col, "color": "Clase"},
    )
    st.plotly_chart(hist_comp, use_container_width=True)

    st.markdown("#### Tabla filtrada")
    st.dataframe(filtered.head(100), use_container_width=True)


def render_balance_section(original_df: pd.DataFrame, balanced_df: pd.DataFrame) -> None:
    st.subheader("Comparativa dataset original vs balanceado")
    st.caption(
        "Evalúa cómo cambia la distribución de métricas al aplicar SMOTE. "
        "Los datos sintéticos permiten entrenar modelos menos sesgados."
    )

    col1, col2 = st.columns(2)
    for col, data, label in (
        (col1, original_df, "Original"),
        (col2, balanced_df, "Balanceado"),
    ):
        col.metric(f"Filas ({label})", f"{len(data):,}")
        col.metric(
            f"Amenazas ({label})",
            f"{data[LABEL_COL].sum():,}",
            f"{data[LABEL_COL].mean()*100:.2f} %",
        )

    dist_fig = px.histogram(
        original_df,
        x="Flow Duration",
        color=original_df[LABEL_COL].map({0: "Normal", 1: "Amenaza"}),
        nbins=40,
        opacity=0.5,
        marginal="box",
        labels={"color": "Clase"},
    )
    dist_fig.update_layout(title="Distribución de duración de flujo (dataset original)")
    st.plotly_chart(dist_fig, use_container_width=True)

    dist_balanced = px.histogram(
        balanced_df,
        x="Flow Duration",
        color=balanced_df[LABEL_COL].map({0: "Normal", 1: "Amenaza"}),
        nbins=40,
        opacity=0.5,
        marginal="box",
        labels={"color": "Clase"},
    )
    dist_balanced.update_layout(
        title="Distribución de duración de flujo (dataset balanceado)"
    )
    st.plotly_chart(dist_balanced, use_container_width=True)


def render_model_results(df: pd.DataFrame, auc_score: float) -> None:
    """
    Muestra los resultados del modelo de Regresión Logística calibrado.
    """
    st.subheader("Resultados del Modelo Predictivo (Regresión Logística)")
    st.caption(
        "Esta pestaña muestra los resultados del modelo de ML (entrenado en Colab) "
        "aplicando el **umbral óptimo de 1.5% (0.015)**. "
        "Estos son los resultados finales que se usarían en producción."
    )

    # Verificar que las columnas necesarias existan
    if 'ML Model Score' not in df.columns or 'ML Model Alert' not in df.columns:
        st.error("Las columnas 'ML Model Score' y 'ML Model Alert' no están disponibles. "
                 "Asegúrate de usar el 'Dataset original' para ver los resultados del modelo.")
        return

    # --- Métrica de Calidad del Modelo (AUC) ---
    st.metric(
        label="Calidad del Modelo (AUC Score)",
        value=f"{auc_score:.4f}",
        help="Área Bajo la Curva ROC (calculada en el set de prueba). "
             "Un valor de 1.0 es perfecto, 0.5 es aleatorio. "
             "Este alto valor demuestra que el modelo es sólido."
    )
    st.divider()

    # --- KPIs Clave del Modelo Calibrado ---
    st.markdown("#### KPIs de Rendimiento del Modelo (Umbral 1.5%)")
    
    # Calcular métricas usando confusion_matrix de sklearn
    cm = confusion_matrix(df[LABEL_COL], df["ML Model Alert"])
    tn, fp, fn, tp = cm.ravel()
    
    total_alerts = fp + tp
    
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Ataques Reales Detectados (TP)", f"{tp:,}")
    kpi2.metric("Falsas Alarmas (FP)", f"{fp:,}")
    kpi3.metric("Ataques Omitidos (FN)", f"{fn:,}")
    kpi4.metric("Total Alertas Generadas", f"{total_alerts:,}")

    if fn == 0:
        st.success(
            "¡ÉXITO! Con el umbral de 1.5%, el modelo detectó el 100% de las "
            "amenazas reales (0 Ataques Omitidos), cumpliendo el objetivo principal."
        )
    else:
        st.error(
            f"FALLO: El modelo omitió {fn} ataques. Revisar calibración."
        )

    # --- Matriz de Confusión Visual ---
    st.markdown("#### Matriz de Confusión (Umbral 1.5%)")
    st.caption(
        "Muestra el balance visual entre la Verdad Real (`is_threat`) y la "
        "Predicción del Modelo (`ML Model Alert`)."
    )
    # Crear un DataFrame para el heatmap de Plotly
    cm_df = pd.DataFrame(
        cm,
        index=["Real: Normal (0)", "Real: Amenaza (1)"],
        columns=["Predicho: Normal (0)", "Predicho: Alerta (1)"]
    )
    fig_cm = px.imshow(
        cm_df, 
        text_auto=True, 
        aspect="auto", 
        color_continuous_scale='Blues',
        labels=dict(x="Predicción del Modelo", y="Verdad Real", color="Cantidad")
    )
    st.plotly_chart(fig_cm, use_container_width=True)

    # --- Tabla de Priorización de Alertas ---
    st.markdown("#### Tabla de Priorización de Alertas (Accionable)")
    st.caption(
        "Esta es la 'Lista de Tareas' para un analista. Muestra solo las "
        f"{total_alerts} alertas generadas, ordenadas por el 'ML Model Score' "
        "(el más riesgoso primero) para una investigación eficiente."
    )
    
    priority_table = df[df["ML Model Alert"] == 1].sort_values(
        "ML Model Score", ascending=False
    )
    
    display_cols = [
        "ML Model Score",
        "is_threat",  # Para verificar si fue un acierto
        "Flow Duration",
        "Flow Bytes/s",
        "Total Fwd Packets",
        "Fwd Packet Length Mean",
    ]
    
    # Añadir Risk Score si existe
    if 'Risk Score' in priority_table.columns:
        display_cols.insert(2, "Risk Score")
    
    available_cols = [col for col in display_cols if col in priority_table.columns]
    st.dataframe(
        priority_table[available_cols].head(20),  # Mostrar solo las 20 más críticas
        use_container_width=True
    )
    
    # Interpretación automática
    if not priority_table.empty:
        st.markdown("#### 📊 Interpretación de los Resultados")
        
        top_20 = priority_table.head(20)
        real_threats_top20 = top_20[LABEL_COL].sum()
        false_positives_top20 = len(top_20) - real_threats_top20
        avg_ml_score = top_20['ML Model Score'].mean()
        
        interpretation = f"""
        **Resumen Ejecutivo:**
        
        De los **20 flujos más riesgosos** identificados por el modelo ML:
        - ✅ **{real_threats_top20} son amenazas reales** (Verdaderos Positivos)
        - ⚠️ **{false_positives_top20} son falsas alarmas** (Falsos Positivos)
        - 📈 **Score promedio del modelo:** {avg_ml_score:.4f} (umbral: 0.0150)
        - 🎯 **Tasa de precisión en Top 20:** {(real_threats_top20/len(top_20)*100):.1f}%
        
        **Implicaciones para la Seguridad:**
        - El modelo ML está siendo **conservador** al generar alertas incluso para flujos con características atípicas pero no necesariamente maliciosas.
        - La presencia de falsos positivos en los Top 20 sugiere que el umbral podría ajustarse, pero esto debe balancearse con la necesidad de detectar todas las amenazas reales.
        """
        
        st.markdown(interpretation)


@st.cache_resource(show_spinner="Entrenando Modelo de ML...")
def train_and_get_model_predictions(df: pd.DataFrame) -> tuple:
    """
    Entrena un modelo de Regresión Logística y devuelve las predicciones 
    para todo el dataframe junto con el AUC score del set de prueba.
    """
    # 1. Definir las 7 características originales del Data Mart
    features = [
        "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
        "Flow Bytes/s", "Flow IAT Mean", "Fwd Packet Length Mean", 
        "Bwd Packet Length Mean"
    ]
    target = "is_threat"

    X = df[features]
    y = df[target]

    # 2. Dividir los datos para un entrenamiento robusto
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 3. Escalar los datos
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 4. Entrenar el modelo
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train_scaled, y_train)

    # 5. Calcular AUC score en el set de prueba
    y_test_proba = model.predict_proba(X_test_scaled)[:, 1]
    auc_score = roc_auc_score(y_test, y_test_proba)

    # 6. Generar predicciones para TODO el dataset
    X_full_scaled = scaler.transform(X[features])
    ml_scores = model.predict_proba(X_full_scaled)[:, 1]

    # 7. Definir el umbral óptimo que encontramos (1.5%)
    UMBRAL_OPTIMO = 0.015
    
    results_df = pd.DataFrame(index=df.index)
    results_df["ML Model Score"] = ml_scores
    results_df["ML Model Alert"] = (ml_scores >= UMBRAL_OPTIMO).astype(int)
    
    return results_df, auc_score


def render_calibration_tuning(df: pd.DataFrame) -> None:
    """
    Muestra un slider interactivo para que el usuario explore cómo
    cambia el rendimiento del modelo al ajustar el umbral de decisión.
    """
    st.subheader("Visualizador Interactivo de Umbral (Calibración)")
    st.caption(
        "Esta es la demostración de la **Fase 5: Evaluación y Calibración**. "
        "Usa el slider para ver cómo un pequeño cambio en el umbral de decisión "
        "impacta drásticamente el costo (Falsas Alarmas) y el riesgo (Ataques Omitidos)."
    )

    # Verificar que las columnas necesarias existan
    if 'ML Model Score' not in df.columns:
        st.error("La columna 'ML Model Score' no está disponible. "
                 "Asegúrate de usar el 'Dataset original' para ver la calibración.")
        return

    # Crear una copia local para evitar modificar el dataframe original
    df_local = df.copy()

    # 1. Crear el Slider
    umbral_dinamico_pct = st.slider(
        "Selecciona un Umbral de Decisión (%)",
        min_value=0.5,
        max_value=5.0,
        value=1.5,  # Nuestro óptimo
        step=0.1,
        format="%.1f%%"
    )
    umbral_dinamico = umbral_dinamico_pct / 100.0  # Convertir a decimal (ej. 0.015)

    # 2. Recalcular predicciones y métricas dinámicamente
    df_local['alerta_dinamica'] = (df_local['ML Model Score'] >= umbral_dinamico).astype(int)
    
    cm_dinamico = confusion_matrix(df_local[LABEL_COL], df_local['alerta_dinamica'])
    
    # Manejar el caso raro de que no haya 4 valores (ej. en umbrales muy altos)
    if len(cm_dinamico.ravel()) == 4:
        tn, fp, fn, tp = cm_dinamico.ravel()
    else:
        # Asumir que solo hay TN (todo predicho como 0)
        tn = cm_dinamico.ravel()[0]
        fp, fn, tp = 0, df_local[LABEL_COL].sum(), 0

    # 3. Calcular métricas adicionales para mejor interpretación
    total_threats = df_local[LABEL_COL].sum()
    fn_percentage = (fn / total_threats * 100) if total_threats > 0 else 0
    detection_rate = (tp / total_threats * 100) if total_threats > 0 else 0
    
    # Calcular métricas del umbral óptimo (1.5%) para comparación
    umbral_optimo = 0.015
    df_local['alerta_optima'] = (df_local['ML Model Score'] >= umbral_optimo).astype(int)
    cm_optimo = confusion_matrix(df_local[LABEL_COL], df_local['alerta_optima'])
    if len(cm_optimo.ravel()) == 4:
        _, fp_optimo, fn_optimo, tp_optimo = cm_optimo.ravel()
    else:
        fp_optimo, fn_optimo, tp_optimo = 0, total_threats, 0

    # 4. Mostrar KPIs dinámicos
    st.markdown("#### Métricas de Impacto (en tiempo real)")
    st.caption(
        "Observa cómo el umbral afecta la detección de amenazas. El umbral óptimo de 1.5% "
        "fue calibrado para minimizar el riesgo de ataques omitidos mientras se controla el volumen de falsas alarmas."
    )
    
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Ataques Detectados (TP)", f"{tp:,}", f"{detection_rate:.2f}% del total")
    kpi2.metric("Ataques Omitidos (FN)", f"{fn:,}", f"{fn_percentage:.2f}% del total")
    kpi3.metric("Falsas Alarmas (FP)", f"{fp:,}")
    
    # Mostrar comparación con umbral óptimo
    if abs(umbral_dinamico_pct - 1.5) < 0.1:  # Dentro de ±0.1% del óptimo
        kpi4.metric("Estado", "Umbral Óptimo", "1.5%")
    else:
        diff_fp = fp - fp_optimo
        kpi4.metric("vs. Óptimo (1.5%)", f"FP: {diff_fp:+,}", 
                   f"FN: {fn - fn_optimo:+d}")

    # 5. Mensajes contextuales mejorados
    # Tolerancia: considerar óptimo si está cerca de 1.5% y el riesgo es bajo
    umbral_cerca_optimo = abs(umbral_dinamico_pct - 1.5) < 0.2
    riesgo_bajo = fn_percentage < 2.0  # Menos del 2% de amenazas omitidas
    
    if fn == 0:
        if umbral_cerca_optimo:
            st.success(
                f"**✅ Umbral Óptimo ({umbral_dinamico_pct:.1f}%):** "
                f"Detección perfecta (100% de amenazas detectadas) con {fp:,} falsas alarmas. "
                f"Este es el punto de equilibrio ideal entre seguridad y eficiencia operativa."
            )
        else:
            st.info(
                f"**Detección Completa:** Con este umbral se detectan todas las amenazas ({tp:,} de {total_threats:,}), "
                f"pero genera {fp:,} falsas alarmas. El umbral óptimo de 1.5% ofrece mejor balance."
            )
    elif riesgo_bajo and umbral_cerca_optimo:
        st.success(
            f"**✅ Umbral Cercano al Óptimo ({umbral_dinamico_pct:.1f}%):** "
            f"Riesgo muy bajo ({fn_percentage:.2f}% de amenazas omitidas, {fn} de {total_threats}). "
            f"Se detectan {detection_rate:.2f}% de las amenazas con {fp:,} falsas alarmas. "
            f"Este umbral ofrece un excelente balance entre seguridad y eficiencia."
        )
    elif riesgo_bajo:
        st.info(
            f"**Riesgo Bajo:** Con este umbral se omiten {fn} amenazas ({fn_percentage:.2f}% del total), "
            f"lo cual representa un riesgo aceptable. Se detectan {detection_rate:.2f}% de las amenazas "
            f"con {fp:,} falsas alarmas. Considera ajustar hacia 1.5% para optimizar el balance."
        )
    elif fn_percentage < 5.0:  # Menos del 5% de riesgo
        st.warning(
            f"**⚠️ Riesgo Moderado:** El modelo está omitiendo {fn} amenazas ({fn_percentage:.2f}% del total). "
            f"Se detectan {detection_rate:.2f}% de las amenazas. "
            f"Se recomienda reducir el umbral hacia 1.5% para mejorar la detección."
        )
    else:
        st.error(
            f"**🚨 Riesgo Alto:** Con este umbral se están omitiendo {fn} amenazas ({fn_percentage:.2f}% del total), "
            f"lo cual es significativo. Solo se detectan {detection_rate:.2f}% de las amenazas. "
            f"Se recomienda reducir el umbral a 1.5% o menos para mejorar la seguridad."
        )


def render_cybersecurity_focus(df: pd.DataFrame) -> None:
    st.subheader("Perspectiva de ciberseguridad")
    st.caption(
        "Visualiza heurísticas defensivas (ráfagas, paquetes diminutos, bytes explosivos) y el puntaje de riesgo generado a partir de los indicadores de red."
    )

    total_flows = len(df)
    high_risk = df[df["Risk Level"] == "Alto"]
    medium_risk = df[df["Risk Level"] == "Medio"]

    col1, col2, col3 = st.columns(3)
    col1.metric("Flujos de alto riesgo", f"{len(high_risk):,}", f"{len(high_risk)/total_flows*100:.2f}%")
    col2.metric("Flujos medio riesgo", f"{len(medium_risk):,}", f"{len(medium_risk)/total_flows*100:.2f}%")
    col3.metric(
        "Coincidencia con etiqueta 'Amenaza'",
        f"{df[(df['Risk Level'] == 'Alto') & (df[LABEL_COL] == 1)].shape[0]:,}",
        help="Cantidad de flujos que el dataset etiqueta como amenaza y además nuestra heurística marca como alto riesgo.",
    )

    risk_dist = px.histogram(
        df,
        x="Risk Score",
        color="Risk Level",
        nbins=40,
        color_discrete_map={"Bajo": "#4CAF50", "Medio": "#FFC107", "Alto": "#F44336"},
        labels={"Risk Score": "Puntaje de riesgo normalizado", "Risk Level": "Nivel"},
    )
    st.plotly_chart(risk_dist, use_container_width=True)

    heuristics = {
        "Heurística: ráfaga rápida": "Detecta ráfagas extremadamente cortas con muchos paquetes, patrones típicos de escaneo agresivo.",
        "Heurística: paquetes diminutos": "Señala flujos con paquetes muy pequeños enviados rápidamente, común en escaneo o reconocimiento sigiloso.",
        "Heurística: bytes explosivos": "Identifica flujos con tasa de bytes por segundo inusualmente alta, potencial exfiltración o transferencia maliciosa.",
    }
    heuristic_data = []
    for col, desc in heuristics.items():
        matches = df[df[col]]
        heuristic_data.append(
            {
                "Heurística": col.replace("Heurística: ", ""),
                "Coincidencias": len(matches),
                "% del total": f"{len(matches)/total_flows*100:.2f}%",
                "Amenazas etiquetadas": matches[LABEL_COL].sum(),
                "Descripción": desc,
            }
        )
    st.markdown("#### Reglas heurísticas activadas")
    st.dataframe(pd.DataFrame(heuristic_data), use_container_width=True)

    st.markdown("#### Flujos más críticos según puntaje de riesgo")
    top_risk = df.sort_values("Risk Score", ascending=False).head(20)
    st.dataframe(
        top_risk[
            [
                "Risk Score",
                "Risk Level",
                "Flow Duration",
                "Total Fwd Packets",
                "Flow Bytes/s",
                "Fwd Packet Length Mean",
                "Bwd Packet Length Mean",
                LABEL_COL,
            ]
        ],
        use_container_width=True,
    )


def render_comparison(df: pd.DataFrame) -> None:
    """
    Compara el enfoque heurístico con el modelo de ML.
    """
    st.subheader("Comparativa: Enfoque Heurístico vs. Modelo ML")
    st.caption(
        "Esta sección permite comparar directamente ambos enfoques de detección de amenazas "
        "para evaluar sus fortalezas y debilidades complementarias."
    )
    
    # Verificar que las columnas necesarias existan
    if 'ML Model Score' not in df.columns or 'ML Model Alert' not in df.columns:
        st.error("Las columnas 'ML Model Score' y 'ML Model Alert' no están disponibles. "
                 "Asegúrate de usar el 'Dataset original' para ver la comparativa.")
        return
    
    if 'Risk Score' not in df.columns or 'Risk Level' not in df.columns:
        st.error("Las columnas 'Risk Score' y 'Risk Level' no están disponibles.")
        return
    
    # --- Comparativa de Rendimiento Final ---
    st.markdown("#### Comparativa de Rendimiento Final")
    st.caption(
        "Comparación directa del rendimiento entre el modelo Heurístico "
        "(basado en reglas 'Risk Level') y el modelo de ML (calibrado a 1.5%)."
    )

    col1, col2 = st.columns(2)

    # --- Columna 1: Modelo de ML (El Ganador) ---
    with col1:
        st.markdown("##### Modelo ML (Calibrado a 1.5%)")
        cm_ml = confusion_matrix(df[LABEL_COL], df["ML Model Alert"])
        if len(cm_ml.ravel()) == 4:
            tn_ml, fp_ml, fn_ml, tp_ml = cm_ml.ravel()
        else:
            tn_ml, fp_ml, fn_ml, tp_ml = df[df[LABEL_COL]==0].shape[0], 0, df[df[LABEL_COL]==1].shape[0], 0
            
        st.metric("Ataques Detectados (TP)", f"{tp_ml:,}")
        st.metric("Ataques Omitidos (FN)", f"{fn_ml:,}")
        st.metric("Falsas Alarmas (FP)", f"{fp_ml:,}")

    # --- Columna 2: Modelo Heurístico ---
    with col2:
        st.markdown("##### Modelo Heurístico ('Risk Level')")
        # Asumir que 'Alto' es la alerta heurística
        heuristica_alerta = (df['Risk Level'] == 'Alto').astype(int)
        cm_heu = confusion_matrix(df[LABEL_COL], heuristica_alerta)
        
        if len(cm_heu.ravel()) == 4:
            tn_heu, fp_heu, fn_heu, tp_heu = cm_heu.ravel()
        else:
            tn_heu, fp_heu, fn_heu, tp_heu = df[df[LABEL_COL]==0].shape[0], 0, df[df[LABEL_COL]==1].shape[0], 0

        st.metric("Ataques Detectados (TP)", f"{tp_heu:,}")
        st.metric("Ataques Omitidos (FN)", f"{fn_heu:,}")
        st.metric("Falsas Alarmas (FP)", f"{fp_heu:,}")

    # --- Veredicto ---
    if fn_ml == 0 and fn_heu > fn_ml:
        st.success(
            f"**Veredicto:** El modelo de ML es superior. "
            f"El modelo Heurístico omitió {fn_heu} ataques, mientras que "
            "el modelo de ML (calibrado a 1.5%) no omitió ninguno."
        )
    
    st.divider()
    
    # Métricas comparativas
    st.markdown("#### Métricas Comparativas")
    
    # Alertas heurísticas (usando Risk Level Alto)
    heuristic_alerts = df[df['Risk Level'] == 'Alto']
    ml_alerts = df[df['ML Model Alert'] == 1]
    
    # Intersección y diferencias
    heuristic_only = heuristic_alerts[~heuristic_alerts.index.isin(ml_alerts.index)]
    ml_only = ml_alerts[~ml_alerts.index.isin(heuristic_alerts.index)]
    both_methods = heuristic_alerts[heuristic_alerts.index.isin(ml_alerts.index)]
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Alertas Heurísticas (Alto Riesgo)", f"{len(heuristic_alerts):,}")
    col2.metric("Alertas ML (Umbral 1.5%)", f"{len(ml_alerts):,}")
    col3.metric("Detectadas por Ambos", f"{len(both_methods):,}")
    col4.metric("Solo Heurística", f"{len(heuristic_only):,}")
    
    col5, col6 = st.columns(2)
    col5.metric("Solo ML", f"{len(ml_only):,}")
    
    # Precisión comparativa
    heuristic_tp = heuristic_alerts[LABEL_COL].sum()
    ml_tp = ml_alerts[LABEL_COL].sum()
    
    heuristic_precision = (heuristic_tp / len(heuristic_alerts) * 100) if len(heuristic_alerts) > 0 else 0
    ml_precision = (ml_tp / len(ml_alerts) * 100) if len(ml_alerts) > 0 else 0
    
    st.markdown("#### Precisión de Detección")
    precision_df = pd.DataFrame({
        'Método': ['Heurístico (Alto Riesgo)', 'ML (Umbral 1.5%)'],
        'Alertas Generadas': [len(heuristic_alerts), len(ml_alerts)],
        'Verdaderos Positivos': [heuristic_tp, ml_tp],
        'Precisión (%)': [f"{heuristic_precision:.2f}", f"{ml_precision:.2f}"]
    })
    st.dataframe(precision_df, use_container_width=True)
    
    # Visualización comparativa de scores
    st.markdown("#### Distribución de Scores")
    st.caption("Comparación visual entre Risk Score (heurístico) y ML Model Score")
    
    comparison_df = df[['Risk Score', 'ML Model Score', LABEL_COL]].copy()
    comparison_df['Método'] = comparison_df[LABEL_COL].map({0: 'Normal', 1: 'Amenaza'})
    
    fig_comparison = go.Figure()
    
    # Scatter plot comparando ambos scores
    fig_comparison.add_trace(go.Scatter(
        x=comparison_df['Risk Score'],
        y=comparison_df['ML Model Score'],
        mode='markers',
        marker=dict(
            color=comparison_df[LABEL_COL],
            colorscale='RdYlGn',
            showscale=True,
            colorbar=dict(title="Amenaza Real")
        ),
        text=comparison_df['Método'],
        hovertemplate='Risk Score: %{x:.3f}<br>ML Score: %{y:.4f}<br>%{text}<extra></extra>'
    ))
    
    fig_comparison.update_layout(
        title="Comparación de Scores: Heurístico vs ML",
        xaxis_title="Risk Score (Heurístico)",
        yaxis_title="ML Model Score",
        height=500
    )
    st.plotly_chart(fig_comparison, use_container_width=True)
    
    # Tabla de casos interesantes
    st.markdown("#### Casos de Interés")
    st.caption("Flujos donde los métodos difieren significativamente")
    
    # Casos donde ML detecta pero heurística no (y son amenazas reales)
    ml_correct_heuristic_missed = ml_only[ml_only[LABEL_COL] == 1]
    
    if not ml_correct_heuristic_missed.empty:
        st.markdown("**✅ ML detectó correctamente amenazas que la heurística pasó por alto:**")
        st.dataframe(
            ml_correct_heuristic_missed[['ML Model Score', 'Risk Score', 'Risk Level', 
                                         'Flow Duration', 'Total Fwd Packets', LABEL_COL]].head(10),
            use_container_width=True
        )
    
    # Casos donde heurística detecta pero ML no (y son amenazas reales)
    heuristic_correct_ml_missed = heuristic_only[heuristic_only[LABEL_COL] == 1]
    
    if not heuristic_correct_ml_missed.empty:
        st.markdown("**✅ Heurística detectó correctamente amenazas que ML pasó por alto:**")
        st.dataframe(
            heuristic_correct_ml_missed[['Risk Score', 'Risk Level', 'ML Model Score',
                                        'Flow Duration', 'Total Fwd Packets', LABEL_COL]].head(10),
            use_container_width=True
        )
    
    # Resumen de conclusiones
    st.markdown("#### Conclusiones de la Comparativa")
    
    conclusions = f"""
    **Hallazgos Clave:**
    
    1. **Cobertura Complementaria:** {'Ambos métodos detectan amenazas que el otro pasa por alto, lo que sugiere que son complementarios.' if (not ml_correct_heuristic_missed.empty and not heuristic_correct_ml_missed.empty) else 'Los métodos muestran diferentes patrones de detección.'}
    
    2. **Precisión:** 
       - Heurístico: {heuristic_precision:.2f}% de precisión ({heuristic_tp}/{len(heuristic_alerts)} alertas son reales)
       - ML: {ml_precision:.2f}% de precisión ({ml_tp}/{len(ml_alerts)} alertas son reales)
    
    3. **Volumen de Alertas:**
       - El método heurístico genera {'más' if len(heuristic_alerts) > len(ml_alerts) else 'menos'} alertas que el modelo ML
       - Esto impacta directamente en la carga de trabajo del analista
    
    4. **Recomendación:** 
       - Considera usar ambos métodos en conjunto para maximizar la detección
       - El modelo ML puede servir como filtro inicial más preciso
       - La heurística puede capturar patrones específicos que el ML no detecta
    """
    
    st.markdown(conclusions)


def main() -> None:
    st.set_page_config(
        page_title="Análisis de Ciberseguridad",
        page_icon="🛡️",
        layout="wide",
    )
    st.title("Datamart de Ciberseguridad")
    st.markdown(
        """
        Esta aplicación permite explorar las métricas del datamart de ciberseguridad y
        comparar el comportamiento entre tráfico normal y amenazas (escaneos de puertos).
        """
    )

    uploaded_file = st.sidebar.file_uploader(
        "Sube un CSV alternativo",
        type=["csv"],
        help="Si no subes nada, se usará el dataset por defecto del repositorio.",
    )
    try:
        raw_df = load_data(uploaded_file)
    except FileNotFoundError as exc:
        st.error(str(exc))
        st.stop()

    if LABEL_COL not in raw_df.columns:
        st.error(f"El dataset debe contener la columna '{LABEL_COL}'.")
        st.stop()

    dataset_option = st.sidebar.selectbox(
        "Modo de análisis",
        (
            "Dataset original",
            "Dataset balanceado (SMOTE)",
        ),
        help="El balanceo SMOTE genera ejemplos sintéticos de la clase minoritaria "
        "para equilibrar el conjunto. Úsalo para evaluar modelos sin sesgo por "
        "frecuencia, pero recuerda que los registros adicionales son sintéticos.",
    )

    base_enriched = enrich_with_cyber_features(raw_df)

    # Entrenar modelo de ML y obtener sus predicciones
    model_results_df = None
    auc_score = None
    try:
        model_results_df, auc_score = train_and_get_model_predictions(raw_df)
        # Fusionar los resultados del ML con los datos enriquecidos (heurísticos)
        # Asegurarse de que los índices coincidan
        base_enriched = base_enriched.join(model_results_df, how='left')
    except Exception as e:
        st.warning(f"No se pudo entrenar el modelo de ML: {str(e)}")
        model_results_df = None
        auc_score = None

    if dataset_option.startswith("Dataset balanceado"):
        if "balanced_df_raw" not in st.session_state:
            with st.spinner("Generando dataset balanceado con SMOTE..."):
                st.session_state["balanced_df_raw"] = balance_data(raw_df)
        df_view = enrich_with_cyber_features(st.session_state["balanced_df_raw"])
        # Nota: El modelo de ML solo se entrena y aplica al dataset original.
        # Para el dataset balanceado, no fusionamos las columnas ML ya que los índices no coinciden
        dataset_label = "balanceado con SMOTE"
    else:
        df_view = base_enriched
        dataset_label = "original"

    tabs = st.tabs(
        [
            "Visión general",
            "Distribución y estadísticas",
            "Análisis interactivo",
            "Ciberseguridad (Heurístico)",
            "Modelo ML (Predictivo)",
            "Calibración de Umbral (Fase 5)",
            "Comparativa (Heurístico vs. ML)",
            "Balanceo",
        ]
    )

    with tabs[0]:
        render_overview(df_view, dataset_label)
        st.divider()
        render_class_distribution(df_view)

    with tabs[1]:
        render_statistics(df_view)
        st.divider()
        render_correlations(df_view)

    with tabs[2]:
        render_flow_analysis(df_view)

    with tabs[3]:
        render_cybersecurity_focus(df_view)
    
    with tabs[4]:
        if model_results_df is not None and 'ML Model Score' in df_view.columns and auc_score is not None:
            render_model_results(df_view, auc_score)
        else:
            st.info(
                "Los resultados del modelo de ML están disponibles solo cuando se selecciona "
                "'Dataset original' en la barra lateral."
            )
    
    with tabs[5]:
        # Pestaña de Calibración de Umbral
        try:
            if model_results_df is not None and 'ML Model Score' in df_view.columns:
                render_calibration_tuning(df_view)
            else:
                st.info(
                    "⚠️ **El visualizador de calibración está disponible solo cuando se selecciona "
                    "'Dataset original' en la barra lateral.**\n\n"
                    "Por favor, cambia a 'Dataset original' en el selector de la barra lateral para ver "
                    "cómo el umbral de decisión afecta el rendimiento del modelo."
                )
                st.markdown("---")
                st.markdown("#### ¿Qué es la Calibración de Umbral?")
                st.caption(
                    "La calibración de umbral es un proceso crítico en la Fase 5 de CRISP-DM que permite "
                    "ajustar el punto de corte de decisión del modelo para optimizar el balance entre "
                    "detección de amenazas (TP) y falsas alarmas (FP)."
                )
        except Exception as e:
            st.error(f"Error al mostrar el visualizador de calibración: {str(e)}")
            st.info("Asegúrate de estar usando el 'Dataset original' en la barra lateral.")
    
    with tabs[6]:
        if model_results_df is not None and 'ML Model Score' in df_view.columns:
            render_comparison(df_view)
        else:
            st.info(
                "La comparativa está disponible solo cuando se selecciona "
                "'Dataset original' en la barra lateral."
            )

    with tabs[7]:
        if dataset_option.startswith("Dataset balanceado"):
            render_balance_section(base_enriched, df_view)
        else:
            st.info(
                "Selecciona 'Dataset balanceado (SMOTE)' en la barra lateral para comparar ambos conjuntos."
            )

    st.sidebar.markdown("### Información del dataset")
    st.sidebar.write(f"Filas (vista actual): {len(df_view):,}")
    st.sidebar.write(f"Columnas: {len(df_view.columns)}")
    st.sidebar.write(
        "Columnas disponibles:",
        df_view.columns.tolist(),
    )


if __name__ == "__main__":
    main()

