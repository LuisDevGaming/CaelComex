# Cael Comex — Sitio web + Panel de administración

Rediseño completo de caelcomex.cl con base de datos y panel para editar todo el contenido sin tocar código.

## Cómo iniciarlo

Requisito: **Node.js 22.13 o superior** (usa la base de datos SQLite que ya viene incluida en Node).

```bash
npm install
npm start
```

- Sitio: http://localhost:3000
- Panel: http://localhost:3000/admin

La primera vez se crea la base de datos (`data/caelcomex.db`) con el contenido inicial, y un usuario administrador
cuyas credenciales quedan en `data/credenciales-iniciales.txt`. **Cambia la contraseña desde "Mi cuenta" y borra ese archivo.**

Para elegir tú el usuario y contraseña inicial (solo antes del primer arranque):
`ADMIN_USER=tu_usuario ADMIN_PASSWORD=tu_clave npm start`

## Qué puedes editar desde el panel

| Sección | Qué controla |
|---|---|
| General | Nombre, eslogan, logos, favicon, SEO, barra de anuncio |
| Colores y estilo | Color principal, acento, oscuro y redondeo de esquinas (todo el sitio cambia) |
| Portada | Título, subtítulo, imagen, botones y etiqueta flotante |
| Secciones del inicio | Títulos/textos de cada bloque y mostrar/ocultar cifras, proceso, testimonios, FAQ |
| Sobre nosotros | Fundador, foto, historia, misión y visión |
| Contacto y redes | Teléfono, WhatsApp, correo, dirección, horario, redes, mapa |
| Servicios / Cursos | Crear, editar, duplicar, ocultar, eliminar y reordenar (arrastrando). Cada uno tiene su propia página |
| Proceso, Cifras, Valores, Testimonios, FAQ | Listas editables |
| Páginas extra | Crea páginas nuevas (ej. Política de privacidad) y elige si salen en el menú o en el pie |
| Mensajes | Consultas del formulario de contacto |
| Imágenes y archivos | Biblioteca para subir y reutilizar imágenes |
| Respaldo | Descargar/restaurar todo el contenido en un archivo .json |

## Agregar nuevos campos o secciones

Todo el contenido está definido en `src/schema.js`. Si agregas un campo o una colección nueva ahí,
aparece automáticamente en el panel. Luego úsalo en las plantillas de `src/views.js`.

## Estructura

```
server.js          Servidor (rutas públicas + API del panel)
src/schema.js      Definición del contenido editable
src/seed.js        Contenido inicial
src/db.js          Base de datos SQLite
src/views.js       Plantillas HTML del sitio
src/config.js      Configuración (variables de entorno)
src/backup.js      Respaldos automáticos
scripts/           Utilidades (importar imágenes)
public/            CSS y JS del sitio
admin/             Panel de administración
data/              Base de datos, imágenes subidas y respaldos (no subir a git)
```

## Publicarlo en internet

El sitio guarda todo (base de datos, imágenes subidas y respaldos) en **una sola carpeta**, `DATA_DIR`.
Por eso el hosting debe ofrecer **disco persistente**; sin él, cada redespliegue borraría el contenido.
Los hostings "estáticos" (Netlify, GitHub Pages) o sin disco (Vercel) **no sirven** para este proyecto.

### Antes de publicar (una sola vez)

1. **Trae las imágenes al propio servidor** (hoy se cargan desde el sitio WordPress antiguo):
   ```bash
   npm run importar-imagenes -- --aplicar
   ```
2. Revisa en el panel los textos de ejemplo (testimonio, cifras, misión/visión) y completa precios, dirección y redes.
3. Si quieres llevar el contenido que editaste en tu computador: en el panel → **Respaldo → Crear respaldo ahora**,
   descárgalo y luego súbelo al servidor como `DATA_DIR/caelcomex.db` (junto con la carpeta `DATA_DIR/uploads`).
   Si no, el servidor arranca con el contenido inicial y lo editas desde el panel.

### Variables de entorno

Copia `.env.example` como `.env` (en tu PC) o defínelas en el panel del hosting:

| Variable | Para qué |
|---|---|
| `NODE_ENV=production` | Cookies solo por https, caché larga, cabeceras de seguridad |
| `SITE_URL` | URL pública, ej. `https://www.caelcomex.cl` (sitemap, Google y redes sociales) |
| `DATA_DIR` | Carpeta persistente, ej. `/data` |
| `ADMIN_USER` / `ADMIN_PASSWORD` | Usuario inicial (solo se usa si la base de datos está vacía) |
| `BACKUP_KEEP` | Cuántos respaldos diarios conservar (14 por defecto) |

### Opción A — Render.com (la más simple)

1. Sube este proyecto a un repositorio de GitHub (privado está bien).
2. En Render: **New → Blueprint** y elige el repositorio. Render lee `render.yaml` y crea el servicio con un disco de 1 GB en `/data`.
3. Escribe la `ADMIN_PASSWORD` cuando te la pida.
4. En **Settings → Custom Domains** agrega `www.caelcomex.cl` y copia en tu proveedor de dominio (NIC Chile / DNS) el registro CNAME que te indica. Render emite el certificado https gratis.

### Opción B — Railway, Fly.io o cualquier servicio con Docker

Usa el `Dockerfile` incluido y monta un **volumen persistente en `/data`**. Define las variables de la tabla.

### Opción C — VPS propio (DigitalOcean, Hetzner, etc.)

```bash
git clone <tu-repo> caelcomex && cd caelcomex
npm ci --omit=dev
cp .env.example .env   # edita los valores
npm start              # o con pm2: pm2 start npm --name caelcomex -- start
```
Pon delante Nginx o Caddy para el https (Caddy lo configura solo: `reverse_proxy localhost:3000`).

### Después de publicar

- Entra a `/admin`, cambia la contraseña en **Mi cuenta**.
- Verifica `https://tu-dominio/healthz` (debe responder `{"ok":true}`).
- Envía `https://tu-dominio/sitemap.xml` a Google Search Console.
- Cada día se crea un respaldo automático en `DATA_DIR/backups`; descárgalo periódicamente desde **Panel → Respaldo**.

## Seguridad incluida

Contraseñas cifradas (scrypt), sesiones con cookie `HttpOnly`/`SameSite=Strict`/`Secure`, límite de intentos de
login y de envíos del formulario, filtro anti-spam (honeypot), cabeceras de seguridad (CSP, HSTS, X-Frame-Options),
archivos subidos aislados (sandbox) y todo el contenido escapado contra inyección de código.
