# 📡 Explicación de Variables de Análisis de Tráfico de Red

## Conceptos Fundamentales

### ¿Qué es un "Flujo de Red"?
Un **flujo de red** es una comunicación bidireccional entre dos puntos (por ejemplo, tu computadora y un servidor web). Cada flujo tiene características que pueden analizarse para detectar comportamientos sospechosos.

---

## 🔍 Variables Explicadas

### 1. **Total Fwd Packets** (Total de Paquetes Forward)

**¿Qué es?**
- Es el **número total de paquetes de datos** que se envían desde el origen hacia el destino en un flujo de red.
- "Forward" significa "hacia adelante" (dirección del flujo).

**Analogía simple:**
Imagina que envías cartas por correo. `Total Fwd Packets` sería el **número total de cartas** que envías en una conversación.

**Ejemplos prácticos:**
- **Navegación web normal**: 10-50 paquetes (páginas web pequeñas)
- **Descarga de archivo**: 100-1000+ paquetes (archivo grande)
- **Escaneo de puertos (amenaza)**: 500-5000+ paquetes (muchos intentos de conexión)
- **Ataque DDoS**: Miles de paquetes (saturación)

**¿Por qué es importante para detectar amenazas?**
- Los **escaneos masivos** generan muchos paquetes porque prueban muchos puertos/servicios
- Los **ataques de fuerza bruta** envían muchos paquetes intentando diferentes credenciales
- El tráfico normal suele tener menos paquetes por flujo

---

### 2. **Flow Duration** (Duración del Flujo)

**¿Qué es?**
- Es el **tiempo total que dura una conexión** desde que se establece hasta que se cierra.
- Se mide en **microsegundos (μs)** o milisegundos.

**Conversión:**
- 1 segundo = 1,000,000 microsegundos (μs)
- 1 segundo = 1,000 milisegundos (ms)

**Analogía simple:**
Es como medir **cuánto tiempo dura una llamada telefónica**. Desde que contestas hasta que cuelgas.

**Ejemplos prácticos:**
- **Conexión web rápida**: 10,000 - 100,000 μs (0.01 - 0.1 segundos)
- **Descarga de archivo**: 1,000,000 - 10,000,000 μs (1 - 10 segundos)
- **Conexión persistente (beaconing)**: 50,000,000+ μs (50+ segundos)
- **Ráfaga rápida (amenaza)**: 1,000 - 50,000 μs (muy corta, <0.05 segundos)

**¿Por qué es importante para detectar amenazas?**
- **Ráfagas rápidas**: Las amenazas a menudo hacen conexiones muy cortas para exfiltrar datos rápidamente y evitar detección
- **Conexiones persistentes**: Algunos malware mantienen conexiones abiertas mucho tiempo para comunicación con servidores de comando y control (C2)
- **Patrones anómalos**: Las duraciones muy cortas o muy largas pueden indicar actividad sospechosa

---

### 3. **Flow Bytes/s** (Bytes por Segundo del Flujo)

**¿Qué es?**
- Es la **velocidad de transferencia de datos** en un flujo de red.
- Mide cuántos **bytes** (unidad de datos) se transfieren por segundo.
- Es como la "velocidad de descarga" que ves cuando descargas un archivo.

**Conversión:**
- 1 KB/s = 1,024 bytes/s
- 1 MB/s = 1,048,576 bytes/s
- 1 GB/s = 1,073,741,824 bytes/s

**Analogía simple:**
Es como medir **qué tan rápido fluye el agua por una tubería**. `Flow Bytes/s` mide qué tan rápido fluyen los datos por la conexión de red.

**Ejemplos prácticos:**
- **Navegación web normal**: 1,000 - 50,000 bytes/s (1-50 KB/s)
- **Streaming de video**: 100,000 - 1,000,000 bytes/s (100 KB/s - 1 MB/s)
- **Descarga rápida**: 1,000,000 - 10,000,000 bytes/s (1-10 MB/s)
- **Exfiltración de datos (amenaza)**: 500,000 - 5,000,000+ bytes/s (muy alta velocidad)
- **Ataque DDoS**: 10,000,000+ bytes/s (saturación de ancho de banda)

**¿Por qué es importante para detectar amenazas?**
- **Transferencias explosivas**: Las amenazas a menudo intentan transferir datos muy rápido para minimizar el tiempo de exposición
- **Exfiltración de datos**: Robo de información genera transferencias a alta velocidad
- **Ataques de saturación**: DDoS intenta saturar el ancho de banda con tráfico masivo

---

## 🔗 Relaciones entre Variables

### Patrón 1: **Ráfagas Rápidas** (Amenaza común)
- **Flow Duration**: Baja (< 50,000 μs)
- **Flow Bytes/s**: Alta (> 500,000 bytes/s)
- **Total Fwd Packets**: Variable

**¿Qué significa?**
Alguien está transfiriendo datos muy rápido en una conexión muy corta. Esto es sospechoso porque:
- Normalmente, las transferencias grandes toman más tiempo
- Las transferencias rápidas y cortas pueden ser exfiltración de datos

---

### Patrón 2: **Escaneos Masivos** (Amenaza común)
- **Total Fwd Packets**: Muy alto (> 500 paquetes)
- **Flow Bytes/s**: Alta o media
- **Flow Duration**: Variable

**¿Qué significa?**
Alguien está enviando muchos paquetes, posiblemente probando muchos puertos o servicios. Esto es sospechoso porque:
- El tráfico normal no necesita tantos paquetes
- Los escaneos de puertos generan muchos paquetes de prueba

---

### Patrón 3: **Conexiones Persistentes** (Amenaza común)
- **Flow Duration**: Muy alta (> 50,000,000 μs)
- **Total Fwd Packets**: Baja (< 50 paquetes)
- **Flow Bytes/s**: Baja

**¿Qué significa?**
Una conexión que dura mucho tiempo pero con muy poca actividad. Esto es sospechoso porque:
- Puede ser "beaconing" (comunicación periódica con servidores maliciosos)
- Los malware a menudo mantienen conexiones abiertas para recibir comandos
- El tráfico normal suele tener más actividad o cerrarse más rápido

---

## 📊 Interpretación en Gráficos

### Scatter Plot: Flow Duration vs Flow Bytes/s

```
Alta Velocidad (Bytes/s)
    ↑
    |     ⚠️ Ráfagas Rápidas
    |     (Amenazas)
    |
    |     ● Normal
    |  ●  ●
    |● ●  ●
    |_____________→ Duración Alta
Corta Duración    (μs)
```

**Zonas del gráfico:**
- **Esquina superior izquierda**: Ráfagas rápidas (sospechoso)
- **Centro**: Tráfico normal
- **Esquina inferior derecha**: Conexiones lentas y largas (puede ser normal o beaconing)

---

### Scatter Plot: Total Fwd Packets vs Flow Bytes/s

```
Alta Velocidad (Bytes/s)
    ↑
    |     ⚠️ Escaneos Masivos
    |     (Amenazas)
    |
    |     ● Normal
    |  ●  ●
    |● ●  ●
    |_____________→ Muchos Paquetes
Pocos Paquetes
```

**Zonas del gráfico:**
- **Esquina superior derecha**: Muchos paquetes + alta velocidad (sospechoso - escaneos)
- **Centro**: Tráfico normal
- **Esquina inferior izquierda**: Pocos paquetes + baja velocidad (normal)

---

## 🎯 Resumen Visual

| Variable | ¿Qué mide? | Analogía | Valores Normales | Valores Sospechosos |
|----------|------------|----------|------------------|---------------------|
| **Total Fwd Packets** | Cantidad de paquetes enviados | Número de cartas enviadas | 10-100 paquetes | >500 paquetes |
| **Flow Duration** | Tiempo de la conexión | Duración de llamada | 0.1-10 segundos | <0.05 o >50 segundos |
| **Flow Bytes/s** | Velocidad de transferencia | Velocidad de descarga | 1-100 KB/s | >500 KB/s en conexiones cortas |

---

## 💡 Ejemplos del Mundo Real

### Escenario 1: Usuario Normal Navegando Web
- **Total Fwd Packets**: 25 paquetes
- **Flow Duration**: 500,000 μs (0.5 segundos)
- **Flow Bytes/s**: 15,000 bytes/s (15 KB/s)
- **Interpretación**: ✅ Normal - carga rápida de página web

### Escenario 2: Descarga de Archivo Grande
- **Total Fwd Packets**: 800 paquetes
- **Flow Duration**: 5,000,000 μs (5 segundos)
- **Flow Bytes/s**: 2,000,000 bytes/s (2 MB/s)
- **Interpretación**: ✅ Normal - descarga legítima

### Escenario 3: Escaneo de Puertos (Amenaza)
- **Total Fwd Packets**: 1,500 paquetes
- **Flow Duration**: 2,000,000 μs (2 segundos)
- **Flow Bytes/s**: 800,000 bytes/s (800 KB/s)
- **Interpretación**: ⚠️ Sospechoso - muchos paquetes en poco tiempo

### Escenario 4: Exfiltración de Datos (Amenaza)
- **Total Fwd Packets**: 200 paquetes
- **Flow Duration**: 20,000 μs (0.02 segundos)
- **Flow Bytes/s**: 3,000,000 bytes/s (3 MB/s)
- **Interpretación**: ⚠️ Muy sospechoso - transferencia explosiva

### Escenario 5: Beaconing/Malware (Amenaza)
- **Total Fwd Packets**: 5 paquetes
- **Flow Duration**: 100,000,000 μs (100 segundos)
- **Flow Bytes/s**: 500 bytes/s (0.5 KB/s)
- **Interpretación**: ⚠️ Sospechoso - conexión muy larga con poca actividad

---

## 🔍 Cómo Usar Estas Variables para Detectar Amenazas

1. **Combina las tres variables** en scatter plots para identificar patrones
2. **Busca valores extremos**: muy altos o muy bajos pueden ser sospechosos
3. **Analiza relaciones**: las combinaciones anómalas (ej: duración baja + velocidad alta) son más sospechosas
4. **Compara con tráfico normal**: usa `is_threat` para ver diferencias visuales

---

**¡Ahora entiendes qué significan estas variables y cómo usarlas para detectar amenazas!** 🛡️📊

