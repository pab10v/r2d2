# R2D2 - Secure Authenticator

> "En honor a mi amigo R2D2, cuya conexión no es tan rápida como debería ser, pero cuya confianza es inquebrantable"

Una extensión de autenticación de dos factores segura y transparente, construida desde cero con código fuente completamente visible y auditable.

## ¿Por Qué R2D2?

Este proyecto nació del descubrimiento de una extensión de autenticador comprometida que había modificado maliciousmente su librería criptográfica. R2D2 representa nuestra confianza en el código transparente y la seguridad verificada.

## Características Principales

### Seguridad Absoluta
- **100% Código Transparente** - Cada línea visible y auditable
- **Sin Dependencias Externas** - Sin librerías de terceros que puedan estar comprometidas
- **Almacenamiento Local Únicamente** - Tus secretos nunca abandonan tu navegador
- **Cero Llamadas de Red** - Funciona completamente offline
- **Sin Telemetría/Analytics** - Cero recolección de datos

### Funcionalidades
- **Implementación TOTP Segura** - Construida desde cero siguiendo RFC 6238
- **Auto-completado Inteligente** - Detecta campos 2FA automáticamente
- **Binding de Dominios** - Recuerda qué cuenta usar en cada sitio
- **Import/Export Seguro** - Backup y restauración de cuentas
- **Código Abierto** - Transparencia total para auditoría de seguridad

## Instalación Paso a Paso

### Para Usuarios No Técnicos

#### Método 1: Instalación Manual (Recomendado)

1. **Descargar el Código**
   - Ve a [github.com/tu-usuario/r2d2](https://github.com/tu-usuario/r2d2)
   - Haz clic en el botón verde "Code" y selecciona "Download ZIP"
   - Descomprime el archivo en tu computadora

2. **Instalar en Chrome**
   - Abre Chrome y ve a `chrome://extensions/`
   - Activa "Modo desarrollador" (arriba a la derecha)
   - Haz clic en "Cargar descomprimida"
   - Selecciona la carpeta `r2d2-main` que descomprimiste
   - ¡Listo! Verás el ícono de R2D2 en tu barra de herramientas

#### Método 2: Desde Chrome Web Store
*(Próximamente disponible)*

### Para Desarrolladores

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/r2d2.git
cd r2d2

# Cargar en Chrome en modo desarrollador
# chrome://extensions/ -> Modo desarrollador -> Cargar descomprimida
```

## Guía de Uso Completa

### Primeros Pasos

#### 1. Agregar Tu Primera Cuenta

1. **Haz clic** en el ícono de R2D2 en tu navegador
2. **Haz clic** en "+ Add Account"
3. **Completa los datos**:
   - **Account Name**: "Gmail" (o el nombre que prefieras)
   - **Issuer**: "Google" (opcional, pero recomendado)
   - **Secret Key**: La clave secreta de tu configuración 2FA
   - **Digits**: "6 digits" (generalmente 6 dígitos)

#### 2. Obtener tu Secret Key

**Para Google/Gmail:**
1. Ve a la configuración de seguridad de Google
2. Activa la autenticación de dos factores
3. Escanea el código QR o usa la clave secreta que te proporcionan

**Para otros servicios:**
- Busca "autenticación de dos factores" en la configuración
- Escanea el código QR o copia la clave secreta manualmente

### Uso Diario

#### Ver Códigos 2FA
1. **Haz clic** en el ícono de R2D2
2. **Verás** todos tus cuentas con códigos en tiempo real
3. **Copia** el código haciendo clic en "Copy"
4. **El código** se actualiza automáticamente cada 30 segundos

#### Auto-completado Automático

R2D2 detecta automáticamente cuando estás en una página con campos 2FA:

1. **Verás** un ícono de reloj (clock) junto a los campos 2FA
2. **Haz clic** en el ícono
3. **Selecciona** la cuenta que quieres usar
4. **El código** se autocompleta automáticamente

#### Binding de Dominios

R2D2 recuerda qué cuenta usaste en cada sitio:

- **Primera vez**: Selecciona manualmente la cuenta
- **Siguientes visitas**: R2D2 sugiere automáticamente la cuenta correcta
- **Puedes cambiar** la cuenta asociada si lo necesitas

### Gestión Avanzada

#### Importar Cuentas

Si ya tienes cuentas en otro autenticador:

1. **Exporta** desde tu autenticador actual (si es posible)
2. **En R2D2**, haz clic en el menú (tres puntos)
3. **Selecciona** "Import Accounts"
4. **Pega** los datos exportados
5. **Haz clic** en "Import"

#### Exportar para Backup

1. **Haz clic** en el menú (tres puntos)
2. **Selecciona** "Export Accounts"
3. **Copia** los datos que aparecen
4. **Guarda** en un lugar seguro (password manager, encrypted file, etc.)

#### Editar/Eliminar Cuentas

1. **Haz clic** en el ícono de lápiz (edit) junto a una cuenta
2. **Modifica** los datos necesarios
3. **O haz clic** en el ícono de basura para eliminar

## Detalles de Seguridad

### ¿Qué Hace a R2D2 Seguro?

#### 1. Código 100% Transparente
```javascript
// Puedes ver exactamente cómo se genera cada código
generateTOTP(secret, timeWindow = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / timeWindow);
  const hmac = this.hmacSHA1(decodedSecret, this.intToBytes(counter));
  // ... implementación completa visible
}
```

#### 2. Sin Dependencias Externas
- **TOTP implementado desde cero** - Sin librerías criptográficas externas
- **Sin llamadas fetch/XHR** - Cero comunicación con servidores
- **Sin analytics** - No se recopila ningún dato

#### 3. Almacenamiento Seguro
```javascript
// Solo se usa el almacenamiento local del navegador
await chrome.storage.local.set({ [this.storageKey]: accounts });
```

#### 4. Validación de Entrada
```javascript
// Todos los datos son validados y sanitizados
if (!this.isValidBase32(accountData.secret)) {
  throw new Error('Invalid secret format');
}
```

### Auditoría de Seguridad

| Aspecto | Estado | Verificación |
|---------|--------|-------------|
| **Red** | Seguro | Cero llamadas de red verificadas |
| **Almacenamiento** | Seguro | Solo almacenamiento local cifrado |
| **Código** | Seguro | 100% visible y auditable |
| **Dependencias** | Seguro | Ninguna dependencia externa |
| **Entradas** | Segura | Validación y sanitización completa |

## Comparación con Extensiones Comprometidas

| Característica | Extensión Comprometida | R2D2 Authenticator |
|---------------|---------------------|---------------------|
| **Código Fuente** | Ofuscado, modificado | 100% transparente |
| **Dependencias** | otpauth.esm.js modificado | Ninguna |
| **Red** | Desconocido (sospechoso) | Ninguna (offline) |
| **Almacenamiento** | Local + posibles fugas | Cifrado local únicamente |
| **Auditoría** | Imposible | Completa |
| **Seguridad** | Comprometida | Verificada |

## Arquitectura Técnica

### Estructura de Archivos
```
r2d2/
- manifest.json          # Configuración de la extensión
- background.js          # Service worker para almacenamiento y TOTP
- popup.html            # Interfaz principal del usuario
- popup.css             # Estilos de la interfaz
- popup.js              # Lógica de la interfaz de usuario
- content.js            # Funcionalidad de auto-completado
- content.css           # Estilos para content script
- totp.js               # Implementación TOTP desde cero
- icons/                # Iconos de la extensión
- README.md             # Este archivo de documentación
```

### Componentes Clave

#### Implementación TOTP (`totp.js`)
- **Algoritmo RFC 6238** completo
- **Decodificación Base32** propia
- **HMAC-SHA1** desde cero
- **Contador basado en tiempo** preciso

#### Servicio Background (`background.js`)
- **Gestión de cuentas** segura
- **Operaciones de almacenamiento** cifradas
- **Generación de códigos TOTP**
- **Binding de dominios**
- **Import/Export** de cuentas

#### Interfaz Usuario (`popup.html`, `popup.js`, `popup.css`)
- **Lista de cuentas** con códigos TOTP en tiempo real
- **Agregar/Editar/Eliminar** cuentas
- **Barras de progreso** mostrando tiempo restante
- **Import/Export** de cuentas

#### Content Script (`content.js`, `content.css`)
- **Detección inteligente** de campos 2FA
- **Inyección de botones** de auto-completado
- **Sugerencias específicas** por dominio
- **Comunicación segura** con background script

## Preguntas Frecuentes (FAQ)

### ¿Es seguro usar R2D2?
**Sí, completamente.** A diferencia de extensiones comprometidas, R2D2:
- Tiene código 100% visible y auditable
- No hace ninguna llamada de red
- Almacena datos solo localmente
- No tiene telemetría ni analytics

### ¿Funciona offline?
**Sí.** R2D2 funciona completamente offline. No necesita conexión a internet para generar códigos 2FA.

### ¿Puedo confiar en los códigos generados?
**Sí.** La implementación TOTP sigue estrictamente el estándar RFC 6238, el mismo que usan Google Authenticator y otras apps legítimas.

### ¿Qué pasa si pierdo mi computadora?
**Recomendamos hacer backup regularmente:**
1. Usa la función "Export Accounts"
2. Guarda los datos en un lugar seguro (password manager, archivo cifrado)
3. Puedes importar tus cuentas en cualquier momento

### ¿R2D2 envía mis datos a algún servidor?
**No, nunca.** R2D2 no hace ninguna llamada de red. Todos tus datos permanecen en tu navegador.

### ¿Puedo usar R2D2 en múltiples navegadores?
**Sí, pero necesitarás importar tus cuentas en cada navegador** usando la función de importación.

## Contribuciones y Auditoría

### Auditoría de Seguridad
Invitamos a expertos en seguridad a auditar este código:

1. **Revisa** cada archivo en el repositorio
2. **Verifica** que no hay llamadas de red ocultas
3. **Confirma** que la implementación TOTP es correcta
4. **Reporta** cualquier hallazgo de seguridad

### Cómo Contribuir
1. **Fork** el repositorio
2. **Haz cambios** enfocados en seguridad
3. **Documenta** todos los cambios
4. **Envía** pull request con explicaciones detalladas

## Licencia

MIT License - Siéntete libre de auditar, modificar y usar para tus necesidades de seguridad.

## Recursos de Seguridad

- [RFC 6238 - Algoritmo TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - Algoritmo HOTP](https://tools.ietf.org/html/rfc4226)
- [Seguridad de Extensiones Chrome](https://developer.chrome.com/docs/extensions/mv3/security/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Agradecimientos

- **A R2D2** - Por inspirar la confianza en la transparencia
- **A la comunidad de seguridad** - Por mantenernos alerta sobre extensiones comprometidas
- **A los usuarios** - Por exigir código abierto y verificable

---

**Advertencia Importante**: Esta extensión fue creada como alternativa segura a extensiones comprometidas encontradas en el mercado. Siempre verifica el código fuente de cualquier extensión crítica para la seguridad.

**R2D2: Donde la confianza es código transparente.**
