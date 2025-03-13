# Comunicación Segura con Cifradores de Flujo y Bloque

Este proyecto implementa un sistema de comunicación segura cliente-servidor utilizando diversos algoritmos criptográficos y técnicas de seguridad. El sistema está diseñado para demostrar y analizar dos escenarios principales: cifradores de flujo y cifradores de bloque.

## Tabla de Contenidos
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Escenario 1: Cifradores de Flujo](#escenario-1-cifradores-de-flujo)
- [Escenario 2: Cifradores de Bloque](#escenario-2-cifradores-de-bloque)
- [Análisis de Tráfico con Wireshark](#análisis-de-tráfico-con-wireshark)
- [Consideraciones de Seguridad](#consideraciones-de-seguridad)
- [Estructura del Proyecto](#estructura-del-proyecto)

## Requisitos
- Python 3.6+
- PyCryptodome/PyCryptodomex
- PyDrive2 (para intercambio de claves vía Google Drive)
- Wireshark (para análisis de tráfico)
- Cuenta de Google y credenciales OAuth para API de Google Drive

## Instalación
1. Clone el repositorio:
   ```sh
   git clone https://github.com/usuario/proyecto.git
   cd proyecto
   ```
2. Cree y active un entorno virtual:
   ```sh
   python -m venv env
   source env/bin/activate  # En Linux/macOS
   env\Scripts\activate  # En Windows
   ```
3. Instale las dependencias:
   ```sh
   pip install -r requirements.txt
   ```
4. Configure las credenciales de Google Drive:
   - Cree un proyecto en Google Cloud Console
   - Habilite la API de Google Drive
   - Configure la pantalla de consentimiento OAuth
   - Cree credenciales OAuth para aplicación de escritorio
   - Descargue el archivo JSON de credenciales y guárdelo como `client_secrets.json` en el directorio del proyecto

## Escenario 1: Cifradores de Flujo

### Funcionamiento
1. El Cliente inicia la comunicación con el Servidor y le envía el cifrador de flujo que desea utilizar: **Salsa20** o **ChaCha20**.
2. El Servidor genera y envía al Cliente una llave simétrica de la longitud adecuada:
   - **128 o 256 bits** para Salsa20
   - **256 bits** para ChaCha20
3. Toda la comunicación posterior entre el Cliente y el Servidor se realiza de manera cifrada utilizando el cifrador seleccionado y la llave compartida.
4. Se captura y analiza el tráfico de red desde el lado del Cliente utilizando **Wireshark**.

### Ejecución
1. Inicie el servidor:
   ```sh
   python server.py
   ```
2. Inicie el cliente:
   ```sh
   python client.py
   ```
3. En el cliente:
   - Seleccione la opción **1** para iniciar comunicación segura.
   - Elija el cifrador (**Salsa20** o **ChaCha20**).
   - Para Salsa20, seleccione el tamaño de clave (**128 o 256 bits**).
   - Comience a enviar mensajes cifrados.

## Escenario 2: Cifradores de Bloque

### Funcionamiento
1. El Servidor genera una llave simétrica de **256 bits** para el cifrador de bloque **AES**.
2. La llave es compartida con el Cliente a través de **Google Drive** (simulando un canal alterno).
3. El Cliente inicia la comunicación con el Servidor y especifica:
   - El **modo de operación de AES**: **ECB, CBC o CTR**.
   - La **técnica de seguridad adicional**: ninguna, cifrado doble, cifrado triple o blanqueamiento de llave (*key whitening*).
4. El Servidor genera las llaves adicionales necesarias (si aplica) y las envía cifradas al Cliente utilizando el modo **CBC** con la llave compartida previamente.
5. Toda la comunicación posterior utiliza el modo y la técnica de seguridad seleccionados.

### Técnicas de Seguridad Adicionales
- **Cifrado doble**: Aplica dos operaciones de cifrado consecutivas con dos claves diferentes.
- **Cifrado triple**: Aplica tres operaciones de cifrado consecutivas con tres claves diferentes.
- **Blanqueamiento de llave (Key Whitening)**: Aplica operaciones XOR con material de clave adicional antes y después del cifrado estándar.

### Ejecución
1. Inicie el servidor:
   ```sh
   python server.py
   ```
2. Inicie el cliente:
   ```sh
   python client.py
   ```
3. En el cliente:
   - Seleccione la opción **2** para cifrador de bloque.
   - El cliente descargará automáticamente la clave desde Google Drive.
   - Seleccione el modo de operación **AES** (**ECB, CBC, CTR**).
   - Seleccione la técnica de seguridad adicional.
   - Comience a enviar mensajes cifrados.

## Análisis de Tráfico con Wireshark
Para capturar y analizar el tráfico de red:

1. Abra **Wireshark** y seleccione la interfaz de red apropiada:
   - Para comunicación local: **interfaz de loopback**
   - Para comunicación en red: **interfaz de red correspondiente**
2. Aplique un filtro para el puerto **5050**:
   ```sh
   tcp.port == 5050
   ```
3. Inicie la captura antes de ejecutar el cliente y servidor.
4. Analice los paquetes para observar el protocolo de comunicación y verificar que los mensajes están efectivamente cifrados.

## Consideraciones de Seguridad

### Fortalezas
- Implementación de múltiples algoritmos y modos criptográficos.
- Soporte para técnicas avanzadas como cifrado múltiple y blanqueamiento.
- Separación de la distribución de claves mediante un canal alternativo.
- Borrado seguro de archivos temporales en el servidor.

### Limitaciones
- En un escenario real, la clave principal debería distribuirse por un canal realmente seguro.
- La autenticación de mensajes no está implementada (no hay MAC/HMAC).
- La aplicación no implementa *forward secrecy*.
- No hay gestión de sesiones ni renovación periódica de claves.

## Estructura del Proyecto
### Principales Componentes
- `server.py`: Implementa el servidor que maneja las solicitudes de cifrado, genera claves y administra la comunicación cifrada.
- `client.py`: Implementa el cliente que selecciona algoritmos de cifrado y se comunica con el servidor.
- `clientClass.py`: Contiene la clase Cliente que encapsula la funcionalidad de conexión y comunicación con el servidor.

> **Nota:** Este proyecto es para fines educativos y no debe utilizarse en entornos de producción sin revisiones de seguridad adicionales.
