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
Las credenciales por defecto del panel de administración son **admin:supersecret123**

---

## Logs que se generan

Todos los logs se guardan en `logs/access.log` en formato JSON, uno por línea. Cada entrada incluye siempre: `timestamp`, `ip`, `method`, `path`, `userAgent` e `language`.

| Evento | Cuándo se registra | Campos adicionales |
|---|---|---|
| `login_attempt` | Alguien envía el formulario de login | `username`, `password` (Base64), `passwordLength`, `page` |
| `max_attempts_redirect` | El cliente agota los intentos y es redirigido | `username`, `password` (Base64), `passwordLength`, `page`, `attempts`, `redirectTo` |
| `page_visit` | Se llama a `POST /visit` al cargar una página | `page`, `user` |
| `admin_access` | Acceso correcto al panel de administración | — |
| `admin_access_denied` | Intento fallido de acceso al panel de administración | `attemptedUser`, `password` (Base64), `passwordLength` |
| `rate_limit_exceeded` | Una IP supera 20 intentos en 15 minutos | — |
| `admin_user_added` | Se crea un nuevo usuario administrador desde el panel | `newUser` |
| `admin_password_changed` | Se cambia la contraseña de un usuario administrador | `user` |
| `admin_user_deleted` | Se elimina un usuario administrador desde el panel | `user` |
| `admin_logout` | Se cierra sesión en el panel de administración | — |
| `server_start` | El servidor arranca | `port`, `pid` |
| `not_found` | Petición a una ruta que no existe | — |
| `server_error` | Error interno no controlado (500) | `error` |

# Login Logger — Guía de integración

Servidor Node.js que intercepta y registra credenciales de formularios de login.  
Panel de administración en `/admin/logs`.

---

## Endpoints disponibles

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/visit` | Registra una visita a la página |
| `POST` | `/login` | Registra un intento de login |

---

## Integración mínima

Añade este script en cualquier página que tenga un formulario de login:
```html

  
  
  Entrar



  // 1. Registra la visita al cargar la página
  fetch('/visit', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ page: window.location.pathname }),
  });

  // 2. Registra cada intento de login al hacer submit
  document.getElementById('loginForm').addEventListener('submit', (e) => {
    e.preventDefault();

    fetch('/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        page:     window.location.pathname,
      }),
    });
  });

```

---

## Evento especial: máximo de intentos

Cuando el usuario agota los intentos, envía el evento `MAX_ATTEMPTS_REDIRECT`  
antes de redirigirle. Esto crea una entrada diferenciada en el panel de logs.
```javascript
const MAX_INTENTOS = 3;
const REDIRECT_URL = '/bloqueado';
let intentos = 0;

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  intentos++;

  if (intentos >= MAX_INTENTOS) {
    // Último intento: evento especial + redirección
    await fetch('/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        page:       window.location.pathname,
        event:      'MAX_ATTEMPTS_REDIRECT', // <-- activa el badge 🚨 en el panel
        attempts:   intentos,
        redirectTo: REDIRECT_URL,
      }),
    });
    window.location.href = REDIRECT_URL;
    return;
  }

  // Intento normal
  fetch('/login', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, page: window.location.pathname }),
  });
});
```

---

## Referencia de campos

### `POST /visit`
```json
{
  "page": "/login"
}
```

### `POST /login` — intento normal
```json
{
  "username": "usuario@ejemplo.com",
  "password": "contraseña123",
  "page":     "/login"
}
```

### `POST /login` — máximo de intentos
```json
{
  "username":   "usuario@ejemplo.com",
  "password":   "contraseña123",
  "page":       "/login",
  "event":      "MAX_ATTEMPTS_REDIRECT",
  "attempts":   3,
  "redirectTo": "/bloqueado"
}
```

> **Nota:** las contraseñas se almacenan en Base64 en el log.  
> En el panel de administración puedes hacer clic sobre ellas para decodificarlas.