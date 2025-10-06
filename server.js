// server.js — sesión única, reemplaza sesión anterior automáticamente, con claim atómico
// Listo para Railway: incluye /health y raíz '/'
// Corrección completa para CORS (front/back en dominios distintos) y cookies cross-site.

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');
const cors = require('cors');

const app = express();
app.set('trust proxy', 1);

// ====== Config ======
const FRONT_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://german-production-d2b4.up.railway.app')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// ====== Carpetas ======
const DB_DIR = process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');

// ====== CORS (antes de session y rutas) ======
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // permite curl/health
    return FRONT_ORIGINS.includes(origin)
      ? cb(null, true)
      : cb(new Error('CORS not allowed'), false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors({
  origin: FRONT_ORIGINS,
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ====== Sesiones (SQLite) ======
const SESSIONS_DIR = process.env.SESSIONS_DIR || '/data';
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

const store = new SQLiteStore({
  db: 'sessions.sqlite',
  dir: SESSIONS_DIR
});

app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'cambia-esta-clave',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'none',               // requerido para dominios distintos
    secure: true,                   // Railway usa HTTPS
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Promesas para store.get/destroy
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

// Body y estáticos
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ====== DB usuarios ======
const USERS_DB_PATH = process.env.DB_PATH || path.join(DB_DIR, 'usuarios.db');
const dbDir = path.dirname(USERS_DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(USERS_DB_PATH);
db.pragma('journal_mode = wal');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

const DEBUG = process.env.DEBUG_SINGLE_SESSION === '1';
const log = (...a) => DEBUG && console.log('[single-session]', ...a);

// ====== Healthcheck (PUBLICO) ======
app.get('/health', (req, res) => res.status(200).send('OK'));

// ====== Raíz (PUBLICO) ======
app.get('/', (req, res) => {
  const loginFile = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(loginFile)) return res.sendFile(loginFile);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
  <body>
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="usuario" placeholder="usuario" required>
      <input type="password" name="password" placeholder="password" required>
      <button>Entrar</button>
    </form>
  </body></html>`);
});

// ====== Helper: autenticar (ajusta a tu lógica real) ======
function autenticar(username, password) {
  const row = db.prepare('SELECT username, password, session_id FROM users WHERE username = ?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row;
}

// ====== LOGIN: reemplaza SIEMPRE la sesión anterior + claim atómico ======
app.post('/login', async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = usuario || username;
    if (!userField) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(userField, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    // 1) Si había una sesión previa, EXPULSARLA SIEMPRE (reemplazo automático)
    if (user.session_id) {
      await storeDestroy(user.session_id).catch(() => {}); // ignora error si ya expiró
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    // 2) Regenerar sesión para nuevo SID (evita fijación y choques)
    await new Promise((resolve, reject) => {
      req.session.regenerate(err => (err ? reject(err) : resolve()));
    });

    // 3) Claim ATÓMICO: tomar la sesión solo si sigue NULL
    const claim = db.prepare(
      'UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL'
    ).run(req.sessionID, user.username);

    if (claim.changes === 0) {
      // Alguna carrera extrema: otro proceso tomó la sesión en microsegundos
      return res.redirect('/login.html?error=sesion_activa');
    }

    // 4) Completar sesión de app
    req.session.usuario = user.username;
    log('login OK (reemplazo + claim) para', user.username, 'sid:', req.sessionID);
    return res.redirect('/inicio.html');
  } catch (e) {
    console.error(e);
    return res.redirect('/login.html?error=interno');
  }
});

// ====== Middleware: sesión única (API -> JSON 401; páginas -> redirect) ======
async function requiereSesionUnica(req, res, next) {
  try {
    const isApi = req.path.startsWith('/api/');

    if (!req.session?.usuario) {
      return isApi
        ? res.status(401).json({ ok: false, error: 'unauthorized' })
        : res.redirect('/login.html');
    }

    const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!row) {
      return isApi
        ? res.status(401).json({ ok: false, error: 'unauthorized' })
        : res.redirect('/login.html');
    }

    if (!row.session_id) {
      return req.session.destroy(() => {
        return isApi
          ? res.status(401).json({ ok: false, error: 'session_invalid' })
          : res.redirect('/login.html?error=sesion_invalida');
      });
    }

    if (row.session_id !== req.sessionID) {
      return req.session.destroy(() => {
        return isApi
          ? res.status(401).json({ ok: false, error: 'logged_elsewhere' })
          : res.redirect('/login.html?error=conectado_en_otra_maquina');
      });
    }

    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(req.session.usuario);
      return req.session.destroy(() => {
        return isApi
          ? res.status(401).json({ ok: false, error: 'session_expired' })
          : res.redirect('/login.html?error=sesion_expirada');
      });
    }

    next();
  } catch (e) {
    console.error(e);
    const isApi = req.path.startsWith('/api/');
    return isApi
      ? res.status(500).json({ ok: false, error: 'internal' })
      : res.redirect('/login.html?error=interno');
  }
}

// ====== Rutas protegidas ======
app.get('/inicio', requiereSesionUnica, (req, res) => {
  const inicioFile = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(inicioFile)) return res.sendFile(inicioFile);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Inicio</title></head>
  <body><h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>
  <form method="POST" action="/logout"><button>Salir</button></form>
  </body></html>`);
});

app.get('/api/datos', requiereSesionUnica, (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario, sid: req.sessionID });
});

app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session?.usuario });
});

// ====== Logout ======
app.post('/logout', (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;

  req.session.destroy(async () => {
    if (usuario) {
      const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(usuario);
      if (row?.session_id === sid) {
        db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(usuario);
      }
    }
    res.redirect('/login.html?msg=logout');
  });
});

// =====================
//  Helpers para Weather
// =====================
const WEATHER_API_KEY = process.env.WEATHER_API_KEY;
const DEFAULT_STATION_ID = process.env.STATION_ID || 'IALFAR32';

function toYYYYMMDD(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}${m}${d}`;
}

async function jsonFetch(url) {
  const r = await fetch(url, { cache: 'no-store' });
  const text = await r.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    const status = `${r.status} ${r.statusText}`;
    throw new Error(`Respuesta no JSON desde origen (${status})`);
  }
  if (!r.ok) {
    const msg = data?.message || data?.error || `${r.status} ${r.statusText}`;
    const err = new Error(msg);
    err.status = r.status;
    throw err;
  }
  return data;
}

// =====================================
//  Rutas API Weather (públicas/proxy)
//  (sin sesión para evitar 302 en CORS)
// =====================================

// Datos en tiempo real
app.get('/api/weather/current', async (req, res) => {
  try {
    const stationId = (req.query.stationId || DEFAULT_STATION_ID).trim();
    if (!WEATHER_API_KEY) throw new Error('Falta WEATHER_API_KEY');

    const wu = new URL('https://api.weather.com/v2/pws/observations/current');
    wu.searchParams.set('stationId', stationId);
    wu.searchParams.set('format', 'json');
    wu.searchParams.set('units', 'm');
    wu.searchParams.set('apiKey', WEATHER_API_KEY);

    const data = await jsonFetch(wu);
    res.set('Cache-Control', 'no-store');
    res.json(data);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Error' });
  }
});

// Histórico diario por rango
app.get('/api/weather/history', async (req, res) => {
  try {
    const stationId = (req.query.stationId || DEFAULT_STATION_ID).trim();
    const startDate = (req.query.startDate || '').trim();
    const endDate = (req.query.endDate || '').trim();
    if (!startDate || !endDate) throw new Error('Faltan parámetros: startDate y endDate');
    if (!WEATHER_API_KEY) throw new Error('Falta WEATHER_API_KEY');

    const wu = new URL('https://api.weather.com/v2/pws/history/daily');
    wu.searchParams.set('stationId', stationId);
    wu.searchParams.set('format', 'json');
    wu.searchParams.set('units', 'm');
    wu.searchParams.set('startDate', startDate);
    wu.searchParams.set('endDate', endDate);
    wu.searchParams.set('apiKey', WEATHER_API_KEY);

    const data = await jsonFetch(wu);
    res.set('Cache-Control', 'public, max-age=120, s-maxage=300');
    res.json(data);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Error' });
  }
});

// Lluvia total del año actual (suma precipTotal del histórico)
app.get('/api/lluvia/total/year', async (req, res) => {
  try {
    const stationId = (req.query.stationId || DEFAULT_STATION_ID).trim();
    if (!WEATHER_API_KEY) throw new Error('Falta WEATHER_API_KEY');

    const now = new Date();
    const desde = toYYYYMMDD(new Date(now.getFullYear(), 0, 1));
    const hasta = toYYYYMMDD(now);

    const wu = new URL('https://api.weather.com/v2/pws/history/daily');
    wu.searchParams.set('stationId', stationId);
    wu.searchParams.set('format', 'json');
    wu.searchParams.set('units', 'm');
    wu.searchParams.set('startDate', desde);
    wu.searchParams.set('endDate', hasta);
    wu.searchParams.set('apiKey', WEATHER_API_KEY);

    const data = await jsonFetch(wu);
    const observations = Array.isArray(data?.observations) ? data.observations : [];
    const total = observations.reduce((acc, day) => {
      const v = Number(day?.metric?.precipTotal ?? day?.precipTotal ?? 0);
      return acc + (Number.isFinite(v) ? v : 0);
    }, 0);

    res.set('Cache-Control', 'public, max-age=300, s-maxage=900');
    res.json({ total_mm: Number(total.toFixed(1)), year: now.getFullYear(), desde, hasta });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Error' });
  }
});

// === Ruta añadida: total de lluvia acumulada desde API externa configurable ===
app.get('/api/lluvia/total', requiereSesionUnica, async (req, res) => {
  try {
    const apiUrl = process.env.LLUVIA_API_URL;
    if (!apiUrl) {
      return res.status(501).json({ error: 'Config faltante', detalle: 'Define LLUVIA_API_URL en .env con el endpoint de tu API.' });
    }
    const r = await fetch(apiUrl);
    if (!r.ok) throw new Error('API externa HTTP ' + r.status);
    const datos = await r.json();

    const num = (v) => {
      const n = Number(v);
      return Number.isFinite(n) ? n : 0;
      };

    if (typeof datos === 'number' || (typeof datos === 'string' && !Number.isNaN(Number(datos)))) {
      return res.json({ total_mm: num(datos) });
    }

    if (datos && typeof datos === 'object') {
      for (const k of ['total_mm','total','acumulado','acumulado_mm','acumulado_dia_mm']) {
        if (k in datos && (typeof datos[k] === 'number' || typeof datos[k] === 'string')) {
          return res.json({ total_mm: num(datos[k]) });
        }
      }
    }

    const arr = Array.isArray(datos) ? datos
              : (datos && (Array.isArray(datos.items) ? datos.items : (Array.isArray(datos.data) ? datos.data : null)));

    if (arr) {
      const pickAccum = (o) => o?.acumulado_mm ?? o?.acumulado ?? o?.acumulado_dia_mm ?? null;
      let hadAccum = false;
      let byDate = [];
      for (const it of arr) {
        const acc = pickAccum(it);
        if (acc != null) {
          hadAccum = true;
          byDate.push({
            fecha: it?.fecha || it?.date || it?.timestamp || null,
            val: num(acc)
          });
        }
      }
      if (hadAccum) {
        const withFecha = byDate.filter(x => x.fecha);
        if (withFecha.length) {
          withFecha.sort((a,b) => (new Date(a.fecha)) - (new Date(b.fecha)));
          return res.json({ total_mm: num(withFecha[withFecha.length-1].val) });
        }
        const maxVal = byDate.reduce((m,x) => Math.max(m, x.val), 0);
        return res.json({ total_mm: num(maxVal) });
      }

      const total = arr.reduce((acc, d) => {
        const v = d?.mm ?? d?.lluvia ?? d?.precip_mm ?? d?.rain ?? 0;
        return acc + num(v);
      }, 0);
      return res.json({ total_mm: Number(total.toFixed(2)) });
    }

    return res.status(500).json({ error: 'Formato no reconocido', detalle: 'No se encontró un total ni un array utilizable.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'No se pudo calcular el total', detalle: String(e.message || e) });
  }
});
// === Fin ruta añadida ===

// ====== Arranque ======
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 http://0.0.0.0:${PORT} — reemplazo automático de sesión + CORS listo`));














