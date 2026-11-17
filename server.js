const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const multer = require('multer');
const compression = require('compression');
const config = require('./src/config');
const store = require('./src/db');
const schema = require('./src/schema');
const views = require('./src/views');
const backup = require('./src/backup');

store.initialize();

const app = express();
const { PORT, UPLOAD_DIR } = config;
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.disable('x-powered-by');
if (config.TRUST_PROXY) app.set('trust proxy', /^\d+$/.test(config.TRUST_PROXY) ? Number(config.TRUST_PROXY) : config.TRUST_PROXY);
app.use(compression());

// Cabeceras de seguridad
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "frame-src https://www.google.com https://maps.google.com",
  "connect-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'",
  "base-uri 'self'",
  "object-src 'none'",
].join('; ');
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (config.isProd && req.secure) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  next();
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));
// CSS/JS llevan ?v=fecha en la URL, así que se pueden guardar en caché mucho tiempo.
app.use('/assets', express.static(path.join(__dirname, 'public'), { maxAge: config.isProd ? '30d' : 0 }));
// Archivos subidos: "sandbox" impide que un SVG o PDF ejecute código en el dominio.
app.use('/uploads', (req, res, next) => { res.setHeader('Content-Security-Policy', 'sandbox; default-src \'none\'; img-src \'self\'; style-src \'unsafe-inline\''); next(); },
  express.static(UPLOAD_DIR, { maxAge: config.isProd ? '30d' : 0 }));
app.use('/admin', (req, res, next) => { res.setHeader('X-Robots-Tag', 'noindex'); res.setHeader('Cache-Control', 'no-cache'); next(); },
  express.static(path.join(__dirname, 'admin')));

// Para el monitoreo del hosting
app.get('/healthz', (req, res) => { store.db.prepare('SELECT 1').get(); res.json({ ok: true }); });

// ---------------- Utilidades ----------------
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean)
  .map((c) => { const i = c.indexOf('='); let v = c.slice(i + 1); try { v = decodeURIComponent(v); } catch { /* cookie malformada */ } return [c.slice(0, i).trim(), v]; }));

const slugify = (s) => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
  .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);

const hits = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const e = hits.get(key) || { n: 0, t: now };
  if (now - e.t > windowMs) { e.n = 0; e.t = now; }
  e.n++; hits.set(key, e);
  return e.n > max;
}
// Limpia contadores viejos cada hora para no acumular memoria
setInterval(() => { const now = Date.now(); for (const [k, e] of hits) if (now - e.t > 3600e3) hits.delete(k); }, 3600e3).unref();

// Limpia los datos según el schema: solo se guardan campos conocidos, con el tipo correcto.
function sanitize(fields, input) {
  const out = {};
  for (const f of fields) {
    let v = input?.[f.name];
    if (f.type === 'boolean') v = !!v;
    else if (f.type === 'number') v = v === '' || v == null ? '' : Number(v);
    else if (f.type === 'list') v = (Array.isArray(v) ? v : String(v || '').split('\n')).map((x) => String(x).trim()).filter(Boolean);
    else v = v == null ? '' : String(v);
    if (f.type === 'slug') v = slugify(v);
    out[f.name] = v;
  }
  return out;
}

// ---------------- Autenticación ----------------
const SESSION_DAYS = 7;
function auth(req, res, next) {
  const token = cookies(req).cc_session;
  if (token) {
    const row = store.db.prepare(`SELECT u.id, u.username, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`).get(token);
    if (row && row.expires_at > Date.now()) { req.user = { id: row.id, username: row.username }; return next(); }
  }
  res.status(401).json({ error: 'No autorizado' });
}
function setSessionCookie(res, token, maxAgeSec) {
  const secure = config.COOKIE_SECURE ? '; Secure' : '';
  res.setHeader('Set-Cookie', `cc_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure}`);
}

app.post('/api/login', (req, res) => {
  if (rateLimit('login:' + req.ip, 10, 15 * 60 * 1000)) return res.status(429).json({ error: 'Demasiados intentos. Espera 15 minutos.' });
  const { username, password } = req.body || {};
  const user = store.db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || ''));
  if (!user || !store.verifyPassword(String(password || ''), user.password_hash)) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  const token = crypto.randomBytes(32).toString('hex');
  store.db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  store.db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, user.id, Date.now() + SESSION_DAYS * 864e5);
  setSessionCookie(res, token, SESSION_DAYS * 86400);
  res.json({ username: user.username });
});
app.post('/api/logout', (req, res) => {
  const token = cookies(req).cc_session;
  if (token) store.db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  setSessionCookie(res, '', 0);
  res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json(req.user));
app.post('/api/account', auth, (req, res) => {
  const { current, username, password } = req.body || {};
  const user = store.db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!store.verifyPassword(String(current || ''), user.password_hash)) return res.status(400).json({ error: 'La contraseña actual no es correcta' });
  if (password && String(password).length < 8) return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres' });
  const newName = String(username || user.username).trim() || user.username;
  store.db.prepare('UPDATE users SET username = ?, password_hash = ? WHERE id = ?')
    .run(newName, password ? store.hashPassword(String(password)) : user.password_hash, user.id);
  res.json({ ok: true, username: newName });
});

// ---------------- API de contenido (protegida) ----------------
app.get('/api/schema', auth, (req, res) => res.json(schema));
app.get('/api/dashboard', auth, (req, res) => {
  const counts = {};
  for (const c of schema.collections) counts[c.key] = store.listItems(c.key).length;
  const unread = store.db.prepare('SELECT COUNT(*) c FROM messages WHERE read = 0').get().c;
  const totalMsgs = store.db.prepare('SELECT COUNT(*) c FROM messages').get().c;
  const media = store.db.prepare('SELECT COUNT(*) c FROM media').get().c;
  const recent = store.db.prepare('SELECT * FROM messages ORDER BY id DESC LIMIT 5').all();
  res.json({ counts, unread, totalMsgs, media, recent });
});

app.get('/api/settings', auth, (req, res) => res.json(store.getAllSettings()));
app.put('/api/settings/:key', auth, (req, res) => {
  const group = schema.settings.find((g) => g.key === req.params.key);
  if (!group) return res.status(404).json({ error: 'Grupo no existe' });
  const value = sanitize(group.fields, req.body);
  store.saveSetting(group.key, value);
  res.json(value);
});

const getCol = (key) => schema.collections.find((c) => c.key === key);
function prepareItem(col, body, excludeId) {
  const data = sanitize(col.fields, body);
  const missing = col.fields.filter((f) => f.required && !data[f.name]).map((f) => f.label);
  if (missing.length) throw new Error('Faltan campos obligatorios: ' + missing.join(', '));
  if (col.hasSlug) {
    let base = data.slug || slugify(data[col.titleField]) || 'item';
    let slug = base, n = 2;
    const taken = new Set(store.listItems(col.key).filter((i) => i.id !== excludeId).map((i) => i.slug));
    while (taken.has(slug)) slug = `${base}-${n++}`;
    data.slug = slug;
  }
  return data;
}

app.get('/api/items/:col', auth, (req, res) => {
  if (!getCol(req.params.col)) return res.status(404).json({ error: 'Colección no existe' });
  res.json(store.listItems(req.params.col));
});
app.post('/api/items/:col', auth, (req, res) => {
  const col = getCol(req.params.col);
  if (!col) return res.status(404).json({ error: 'Colección no existe' });
  try { res.json(store.createItem(col.key, prepareItem(col, req.body), req.body.published !== false)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/items/:col/:id', auth, (req, res) => {
  const col = getCol(req.params.col);
  const item = store.getItem(Number(req.params.id));
  if (!col || !item || item.collection !== col.key) return res.status(404).json({ error: 'No encontrado' });
  try { res.json(store.updateItem(item.id, prepareItem(col, req.body, item.id), req.body.published !== false)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/items/:col/:id', auth, (req, res) => { store.deleteItem(Number(req.params.id)); res.json({ ok: true }); });
app.post('/api/items/:col/reorder', auth, (req, res) => {
  store.reorderItems((req.body.ids || []).map(Number));
  res.json({ ok: true });
});

// Mensajes del formulario de contacto
app.get('/api/messages', auth, (req, res) => res.json(store.db.prepare('SELECT * FROM messages ORDER BY id DESC').all()));
app.put('/api/messages/:id', auth, (req, res) => {
  store.db.prepare('UPDATE messages SET read = ? WHERE id = ?').run(req.body.read ? 1 : 0, Number(req.params.id));
  res.json({ ok: true });
});
app.delete('/api/messages/:id', auth, (req, res) => {
  store.db.prepare('DELETE FROM messages WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Biblioteca de imágenes
const ALLOWED = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif', 'image/svg+xml': '.svg', 'image/x-icon': '.ico', 'application/pdf': '.pdf' };
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ALLOWED[file.mimetype]}`),
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, !!ALLOWED[file.mimetype]),
});
app.get('/api/media', auth, (req, res) => res.json(store.db.prepare('SELECT * FROM media ORDER BY id DESC').all()
  .map((m) => ({ ...m, url: '/uploads/' + m.filename }))));
app.post('/api/media', auth, upload.array('files', 20), (req, res) => {
  if (!req.files?.length) return res.status(400).json({ error: 'Formato no permitido (usa PNG, JPG, WEBP, GIF, SVG, ICO o PDF, máx. 10 MB)' });
  const st = store.db.prepare('INSERT INTO media (filename, original, mime, size) VALUES (?, ?, ?, ?)');
  const out = req.files.map((f) => { st.run(f.filename, f.originalname, f.mimetype, f.size); return { url: '/uploads/' + f.filename, original: f.originalname }; });
  res.json(out);
});
app.delete('/api/media/:id', auth, (req, res) => {
  const m = store.db.prepare('SELECT * FROM media WHERE id = ?').get(Number(req.params.id));
  if (m) {
    fs.rmSync(path.join(UPLOAD_DIR, path.basename(m.filename)), { force: true });
    store.db.prepare('DELETE FROM media WHERE id = ?').run(m.id);
  }
  res.json({ ok: true });
});

// Respaldo completo (exportar / importar)
app.get('/api/backup', auth, (req, res) => {
  const items = store.db.prepare('SELECT collection, data, position, published FROM items ORDER BY collection, position').all();
  res.setHeader('Content-Disposition', `attachment; filename="respaldo-caelcomex-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json({ version: 1, settings: store.getAllSettings(), items: items.map((i) => ({ ...i, data: JSON.parse(i.data) })) });
});
app.post('/api/restore', auth, (req, res) => {
  const b = req.body;
  if (!b || !b.settings || !Array.isArray(b.items)) return res.status(400).json({ error: 'Archivo de respaldo inválido' });
  store.db.exec('BEGIN');
  try {
    for (const g of schema.settings) if (b.settings[g.key]) store.saveSetting(g.key, sanitize(g.fields, b.settings[g.key]));
    store.db.exec('DELETE FROM items');
    const st = store.db.prepare('INSERT INTO items (collection, data, position, published) VALUES (?, ?, ?, ?)');
    for (const i of b.items) { const col = getCol(i.collection); if (col) st.run(col.key, JSON.stringify(sanitize(col.fields, i.data)), i.position || 0, i.published ? 1 : 0); }
    store.db.exec('COMMIT');
    res.json({ ok: true });
  } catch (e) { store.db.exec('ROLLBACK'); res.status(500).json({ error: e.message }); }
});

// Respaldos automáticos de la base de datos (archivos .db completos, incluyen mensajes y usuarios)
app.get('/api/db-backups', auth, (req, res) => res.json(backup.list()));
app.post('/api/db-backups', auth, (req, res) => res.json(backup.create('manual')));
app.get('/api/db-backups/:name', auth, (req, res) => {
  const file = backup.pathFor(req.params.name);
  if (!file) return res.status(404).json({ error: 'No encontrado' });
  res.download(file);
});

// ---------------- Sitio público ----------------
const baseUrl = (req) => config.SITE_URL || `${req.protocol}://${req.get('host')}`;
function ctx(req, extra = {}) {
  const s = store.getAllSettings();
  return {
    s,
    baseUrl: baseUrl(req),
    path: req.path,
    services: store.listItems('services', { onlyPublished: true }),
    pages: store.listItems('pages', { onlyPublished: true }),
    ...extra,
  };
}
const send = (res, html, status = 200) => res.status(status).type('html').send(html);

app.get('/', (req, res) => send(res, views.home(ctx(req, {
  courses: store.listItems('courses', { onlyPublished: true }),
  process: store.listItems('process', { onlyPublished: true }),
  stats: store.listItems('stats', { onlyPublished: true }),
  testimonials: store.listItems('testimonials', { onlyPublished: true }),
  faqs: store.listItems('faqs', { onlyPublished: true }),
}))));
app.get('/servicios', (req, res) => send(res, views.servicesIndex(ctx(req))));
app.get('/servicios/:slug', (req, res, next) => {
  const item = store.findBySlug('services', req.params.slug);
  if (!item) return next();
  send(res, views.service(ctx(req, { item })));
});
app.get('/cursos', (req, res) => send(res, views.coursesIndex(ctx(req, { courses: store.listItems('courses', { onlyPublished: true }) }))));
app.get('/cursos/:slug', (req, res, next) => {
  const item = store.findBySlug('courses', req.params.slug);
  if (!item) return next();
  send(res, views.course(ctx(req, { item, courses: store.listItems('courses', { onlyPublished: true }) })));
});
app.get('/nosotros', (req, res) => send(res, views.about(ctx(req, {
  values: store.listItems('values', { onlyPublished: true }),
  stats: store.listItems('stats', { onlyPublished: true }),
  courses: store.listItems('courses', { onlyPublished: true }),
}))));
app.get('/contacto', (req, res) => send(res, views.contact(ctx(req, { sent: req.query.enviado === '1', error: req.query.error }))));
app.post('/contacto', (req, res) => {
  const b = req.body || {};
  if (b.website) return res.redirect(303, '/contacto?enviado=1'); // honeypot anti-spam
  if (rateLimit('contact:' + req.ip, 5, 60 * 60 * 1000)) return res.redirect(303, '/contacto?error=limite');
  const clip = (v, n) => String(v || '').trim().slice(0, n);
  const m = { name: clip(b.name, 120), email: clip(b.email, 160), phone: clip(b.phone, 40), company: clip(b.company, 120), subject: clip(b.subject, 160), message: clip(b.message, 5000) };
  if (!m.name || !m.message || !/^\S+@\S+\.\S+$/.test(m.email)) return res.redirect(303, '/contacto?error=datos');
  store.db.prepare('INSERT INTO messages (name, email, phone, company, subject, message) VALUES (?, ?, ?, ?, ?, ?)')
    .run(m.name, m.email, m.phone, m.company, m.subject, m.message);
  res.redirect(303, '/contacto?enviado=1');
});
app.get('/sitemap.xml', (req, res) => {
  const base = baseUrl(req);
  const urls = ['/', '/servicios', '/cursos', '/nosotros', '/contacto',
    ...store.listItems('services', { onlyPublished: true }).map((i) => '/servicios/' + i.slug),
    ...store.listItems('courses', { onlyPublished: true }).map((i) => '/cursos/' + i.slug),
    ...store.listItems('pages', { onlyPublished: true }).map((i) => '/' + i.slug)];
  res.type('xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map((u) => `<url><loc>${base}${u}</loc></url>`).join('')}</urlset>`);
});
app.get('/robots.txt', (req, res) => res.type('text').send(`User-agent: *\nDisallow: /admin\nDisallow: /api/\nSitemap: ${baseUrl(req)}/sitemap.xml\n`));

// Páginas extra creadas desde el panel (ej: /politica-privacidad)
app.get('/:slug', (req, res, next) => {
  const item = store.findBySlug('pages', req.params.slug);
  if (!item) return next();
  send(res, views.page(ctx(req, { item })));
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'No encontrado' });
  send(res, views.notFound(ctx(req)), 404);
});

// Errores inesperados: se registran en el log y el visitante ve un mensaje limpio (sin detalles internos).
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error(new Date().toISOString(), req.method, req.originalUrl, err);
  if (res.headersSent) return;
  const status = err.status || err.statusCode || 500;
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'El archivo supera los 10 MB' : err.message });
  if (req.path.startsWith('/api/')) return res.status(status).json({ error: status < 500 ? err.message : 'Error interno del servidor' });
  res.status(status).type('text').send(status < 500 ? 'Solicitud inválida' : 'Ocurrió un error. Inténtalo nuevamente en unos minutos.');
});

const server = app.listen(PORT, () => {
  console.log(`\n  Modo:   ${config.isProd ? 'producción' : 'desarrollo'}\n  Datos:  ${config.DATA_DIR}\n  Sitio:  http://localhost:${PORT}\n  Admin:  http://localhost:${PORT}/admin\n`);
  backup.schedule();
});

// Apagado ordenado (el hosting envía SIGTERM al redesplegar): termina peticiones y cierra la base de datos.
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    server.close(() => { try { store.db.close(); } catch { /* ya cerrada */ } process.exit(0); });
    setTimeout(() => process.exit(0), 8000).unref();
  });
}
