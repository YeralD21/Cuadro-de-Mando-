# 📊 Guía de Gráficos Estadísticos en Power BI
## Análisis de Variables de Ciberseguridad

---

## 📋 Variables Disponibles

- **Bwd Packet Length Mean** (Tamaño promedio de paquetes backward)
- **Flow Bytes/s** (Velocidad de transferencia)
- **Flow Duration** (Duración del flujo)
- **Flow IAT Mean** (Tiempo promedio entre llegadas)
- **Fwd Packet Length Mean** (Tamaño promedio de paquetes forward)
- **is_threat** (Etiqueta: 0=Normal, 1=Amenaza)
- **Total Fwd Packets** (Total de paquetes forward)
- **Total Length of Fwd Packets** (Longitud total de paquetes forward)

---

## 🎯 Gráficos Recomendados por Tipo de Análisis

### 1. **ANÁLISIS DE DISTRIBUCIÓN Y COMPARACIÓN**

#### 📊 **Gráfico de Barras Agrupadas** (Grouped Bar Chart)
**Uso**: Comparar promedios de variables entre Normal vs Amenaza

**Configuración**:
- **Eje X**: `is_threat` (o crear una columna calculada: `Tipo = IF(is_threat=1, "Amenaza", "Normal")`)
- **Eje Y**: Promedio de cualquier variable numérica (ej: `Flow Bytes/s`, `Flow Duration`)
- **Leyenda**: `is_threat` o `Tipo`

**Ejemplos**:
- Promedio de `Flow Bytes/s` por tipo de tráfico
- Promedio de `Total Fwd Packets` por tipo de tráfico
- Promedio de `Flow Duration` por tipo de tráfico

**Cómo crearlo**:
1. Arrastra `is_threat` al eje X
2. Arrastra `Flow Bytes/s` al eje Y
3. En el panel de campos, cambia la agregación a "Promedio"
4. Agrega `is_threat` a la leyenda

---

#### 📊 **Histograma** (Histogram Chart)
**Uso**: Ver distribución de una variable

**Configuración**:
- **Eje X**: Variable numérica (ej: `Flow Duration`)
- **Eje Y**: Conteo (Count)
- **Leyenda**: `is_threat` para comparar distribuciones

**Ejemplos**:
- Distribución de `Flow Duration` (Normal vs Amenaza)
- Distribución de `Flow Bytes/s` (Normal vs Amenaza)
- Distribución de `Total Fwd Packets` (Normal vs Amenaza)

**Cómo crearlo**:
1. Arrastra `Flow Duration` al eje X
2. Arrastra `is_threat` al eje Y (conteo automático)
3. Agrega `is_threat` a la leyenda para colorear por tipo

---

### 2. **ANÁLISIS DE RELACIONES Y CORRELACIONES**

#### 📊 **Gráfico de Dispersión (Scatter Plot)**
**Uso**: Analizar relación entre dos variables numéricas

**Configuración**:
- **Eje X**: Variable 1 (ej: `Flow Duration`)
- **Eje Y**: Variable 2 (ej: `Flow Bytes/s`)
- **Leyenda**: `is_threat` para colorear puntos
- **Tamaño**: Opcional - otra variable numérica (ej: `Total Fwd Packets`)

**Ejemplos Recomendados**:

1. **Flow Duration vs Flow Bytes/s**
   - Identifica ráfagas rápidas (duración baja, bytes/s altos)
   - Las amenazas suelen estar en la esquina superior izquierda

2. **Total Fwd Packets vs Flow Bytes/s**
   - Identifica escaneos masivos (muchos paquetes, alta velocidad)
   - Las amenazas suelen estar en la esquina superior derecha

3. **Flow Duration vs Total Fwd Packets**
   - Identifica conexiones persistentes (duración alta, pocos paquetes)
   - Las amenazas suelen estar en la esquina inferior derecha

4. **Fwd Packet Length Mean vs Bwd Packet Length Mean**
   - Analiza asimetría en tamaños de paquetes
   - Puede indicar patrones de exfiltración

**Cómo crearlo**:
1. Selecciona "Scatter Chart" en el panel de visualizaciones
2. Arrastra `Flow Duration` al eje X
3. Arrastra `Flow Bytes/s` al eje Y
4. Arrastra `is_threat` a la leyenda
5. (Opcional) Arrastra `Total Fwd Packets` al tamaño de burbujas

---

#### 📊 **Matriz de Correlación** (Correlation Matrix)
**Uso**: Ver correlaciones entre múltiples variables

**Configuración**:
- Usa una tabla con todas las variables numéricas
- Calcula correlaciones usando DAX o R/Python visual

**Variables a correlacionar**:
- Flow Duration
- Total Fwd Packets
- Flow Bytes/s
- Flow IAT Mean
- Fwd Packet Length Mean
- Bwd Packet Length Mean

**Cómo crearlo**:
1. Crea una tabla con todas las variables numéricas
2. Usa un visual de "R Script" o "Python Script" para calcular correlaciones
3. O usa un visual de "Matrix" con valores calculados en DAX

**Código DAX para correlación** (ejemplo):
```DAX
Correlación = 
VAR X = [Flow Duration]
VAR Y = [Flow Bytes/s]
RETURN
CORREL(X, Y)
```

---

### 3. **ANÁLISIS DE TENDENCIAS Y PATRONES**

#### 📊 **Gráfico de Líneas** (Line Chart)
**Uso**: Ver tendencias cuando hay una variable temporal (si la tienes)

**Configuración**:
- **Eje X**: Variable temporal (si existe) o variable numérica ordenada
- **Eje Y**: Variable numérica
- **Leyenda**: `is_threat`

**Alternativa sin tiempo**:
- Ordena por `Flow Duration` y muestra `Flow Bytes/s` como línea
- Útil para ver patrones según duración

---

#### 📊 **Gráfico de Área Apilada** (Stacked Area Chart)
**Uso**: Comparar proporciones acumuladas

**Configuración**:
- **Eje X**: Variable numérica ordenada (ej: `Flow Duration` en rangos)
- **Eje Y**: Conteo o suma
- **Leyenda**: `is_threat`

**Ejemplo**:
- Rangos de `Flow Duration` (0-1M, 1M-10M, 10M-100M μs)
- Proporción de Normal vs Amenaza en cada rango

---

### 4. **ANÁLISIS DE CATEGORIZACIÓN**

#### 📊 **Gráfico de Pastel/Donut** (Pie/Donut Chart)
**Uso**: Ver proporción de Normal vs Amenaza

**Configuración**:
- **Leyenda**: `is_threat` o `Tipo`
- **Valores**: Conteo de registros

**Cómo crearlo**:
1. Selecciona "Pie Chart" o "Donut Chart"
2. Arrastra `is_threat` a la leyenda
3. Arrastra cualquier campo al valor (Power BI contará automáticamente)

---

#### 📊 **Gráfico de Embudo** (Funnel Chart)
**Uso**: Ver distribución en etapas o rangos

**Configuración**:
- **Categoría**: Rangos de una variable (ej: Rangos de `Flow Duration`)
- **Valores**: Conteo o suma

**Ejemplo**:
- Crear rangos de `Flow Duration`: "Muy Corto", "Corto", "Medio", "Largo", "Muy Largo"
- Ver cuántos flujos hay en cada rango

---

### 5. **ANÁLISIS MULTIVARIADO**

#### 📊 **Gráfico de Barras Apiladas** (Stacked Bar Chart)
**Uso**: Comparar múltiples variables simultáneamente

**Configuración**:
- **Eje X**: `is_threat` o `Tipo`
- **Eje Y**: Múltiples variables normalizadas
- **Leyenda**: Variables a comparar

**Ejemplo**:
- Comparar promedios normalizados de:
  - Flow Duration
  - Flow Bytes/s
  - Total Fwd Packets
  - Por tipo de tráfico

---

#### 📊 **Gráfico de Combinación** (Combo Chart)
**Uso**: Mostrar diferentes tipos de métricas en un solo gráfico

**Configuración**:
- **Eje X**: `is_threat` o variable categórica
- **Eje Y (Barras)**: Variable 1 (ej: Promedio de `Flow Duration`)
- **Eje Y (Línea)**: Variable 2 (ej: Promedio de `Flow Bytes/s`)

**Ejemplo**:
- Barras: Promedio de `Total Fwd Packets` por tipo
- Línea: Promedio de `Flow Bytes/s` por tipo

---

## 🔧 PASOS PARA CREAR GRÁFICOS EN POWER BI

### Paso 1: Preparar los Datos

1. **Crea una columna calculada para Tipo de Tráfico**:
   ```DAX
   Tipo Tráfico = IF(datamart_ciberseguridad_listo[is_threat] = 1, "Amenaza", "Normal")
   ```

2. **Crea medidas para promedios** (opcional pero recomendado):
   ```DAX
   Promedio Flow Bytes/s = AVERAGE(datamart_ciberseguridad_listo[Flow Bytes/s])
   
   Promedio Flow Duration = AVERAGE(datamart_ciberseguridad_listo[Flow Duration])
   
   Promedio Total Fwd Packets = AVERAGE(datamart_ciberseguridad_listo[Total Fwd Packets])
   ```

### Paso 2: Crear el Gráfico

1. **Selecciona el tipo de gráfico** en el panel de visualizaciones
2. **Arrastra campos** desde el panel de campos:
   - Al eje X
   - Al eje Y
   - A la leyenda (si aplica)
   - Al tamaño (si es scatter plot)
3. **Ajusta la agregación**:
   - Click derecho en el campo del eje Y
   - Selecciona "Promedio", "Suma", "Conteo", etc.

### Paso 3: Personalizar

1. **Colores**: 
   - Click en el gráfico → Formato → Colores de datos
   - Asigna colores específicos (azul para Normal, rojo para Amenaza)

2. **Títulos y Etiquetas**:
   - Formato → Título → Personaliza el título
   - Formato → Etiquetas de datos → Activa/desactiva valores

3. **Ejes**:
   - Formato → Eje X/Y → Ajusta título, formato numérico, escala

---

## 📈 GRÁFICOS PRIORITARIOS RECOMENDADOS

### Top 5 Gráficos Esenciales:

1. **Scatter Plot: Flow Duration vs Flow Bytes/s**
   - Coloreado por `is_threat`
   - Identifica ráfagas rápidas (amenazas)

2. **Scatter Plot: Total Fwd Packets vs Flow Bytes/s**
   - Coloreado por `is_threat`
   - Identifica escaneos masivos

3. **Histograma: Flow Duration**
   - Coloreado por `is_threat`
   - Compara distribuciones

4. **Barras Agrupadas: Promedios por Tipo**
   - Compara todas las variables numéricas entre Normal y Amenaza

5. **Gráfico de Pastel: Proporción Normal vs Amenaza**
   - Muestra el desbalance de clases

---

## 💡 TIPS ADICIONALES

### Crear Rangos para Análisis:

**Rangos de Flow Duration**:
```DAX
Rango Duración = 
SWITCH(
    TRUE(),
    datamart_ciberseguridad_listo[Flow Duration] < 1000000, "Muy Corto (<1M μs)",
    datamart_ciberseguridad_listo[Flow Duration] < 10000000, "Corto (1M-10M μs)",
    datamart_ciberseguridad_listo[Flow Duration] < 100000000, "Medio (10M-100M μs)",
    "Largo (>100M μs)"
)
```

**Rangos de Flow Bytes/s**:
```DAX
Rango Velocidad = 
SWITCH(
    TRUE(),
    datamart_ciberseguridad_listo[Flow Bytes/s] < 1000, "Muy Baja",
    datamart_ciberseguridad_listo[Flow Bytes/s] < 10000, "Baja",
    datamart_ciberseguridad_listo[Flow Bytes/s] < 100000, "Media",
    "Alta"
)
```

### Filtros Interactivos:

- Crea un **Slicer** con `is_threat` para filtrar entre Normal y Amenaza
- Crea **Slicers** con rangos de variables para análisis dinámico
- Todos los gráficos se actualizarán automáticamente al filtrar

---

## 🎯 EJEMPLO COMPLETO: Dashboard de Análisis

**Página 1: Análisis de Distribución**
- Gráfico de Pastel: Proporción Normal vs Amenaza
- Histograma: Flow Duration por tipo
- Histograma: Flow Bytes/s por tipo
- Histograma: Total Fwd Packets por tipo

**Página 2: Análisis de Relaciones**
- Scatter Plot: Flow Duration vs Flow Bytes/s
- Scatter Plot: Total Fwd Packets vs Flow Bytes/s
- Scatter Plot: Flow Duration vs Total Fwd Packets
- Scatter Plot: Fwd Packet Length Mean vs Bwd Packet Length Mean

**Página 3: Comparación de Métricas**
- Barras Agrupadas: Promedios de todas las variables por tipo
- Gráfico de Combinación: Múltiples métricas simultáneas
- Tabla: Estadísticas descriptivas (promedio, mediana, desviación estándar)

---

## 📚 Recursos Adicionales

- **Documentación Power BI**: https://docs.microsoft.com/power-bi/
- **DAX Guide**: https://dax.guide/
- **Power BI Community**: https://community.powerbi.com/

---

**¡Con estos gráficos podrás realizar un análisis estadístico completo de tus datos de ciberseguridad!** 🛡️📊

