# Login Logger

Aplicación web con un panel de login que siempre devuelve error de credenciales incorrectas. Su único propósito es registrar todos los intentos de acceso con IP, timestamp y credenciales introducidas. Incluye un panel de administración para visualizar los logs en tiempo real.

---

## Despliegue en local

```bash
# 1. Instalar dependencias
npm install

# 2. Arrancar el servidor
npm start
```

El servidor queda disponible en `http://localhost:3000`.
El panel de administración en `http://localhost:3000/admin/logs`.

---

## Credenciales por defecto

| Panel | Usuario | Contraseña |
|---|---|---|
| Admin (visor de logs) | `admin` | `supersecret123` |

> Las credenciales se almacenan como hashes bcrypt. Para cambiarlas, genera un nuevo hash y pásalo como variable de entorno:
> ```bash
> node -e "require('bcryptjs').hash('TU_NUEVA_PASS', 12).then(console.log)"
> ```

---

## Logs que se generan

Todos los logs se guardan en `logs/access.log` en formato JSON, uno por línea. Cada entrada incluye siempre: `timestamp`, `ip`, `method`, `path`, `userAgent` e `language`.

| Evento | Cuándo se registra | Campos adicionales |
|---|---|---|
| `login_attempt` | Cada vez que alguien pulsa "Acceder" en el panel de login | `username`, `password`, `passwordLength` |
| `admin_access` | Acceso correcto al panel de administración | — |
| `admin_access_denied` | Intento fallido de acceso al panel de administración | `attemptedUser` |
| `rate_limit_exceeded` | Una IP supera 20 intentos en 15 minutos | — |
