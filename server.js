// server.js — versión mejorada (cookies dev-friendly, errores claros, lluvia anual/mensual, sesión única)

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

/* ===================== App & entorno ===================== */
const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 8080;
const isProd = process.env.NODE_ENV === 'production';

// Rutas y almacenamiento
const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), 'db', 'usuarios.db');
const SESSIONS_DIR = process.env.SESSIONS_DIR || path.join(process.cwd(), 'db');

// Crear carpetas si no existen
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
fs.mkdirSync(SESSIONS_DIR, { recursive: true });

// Base de datos de usuarios (better-sqlite3)
const db = new Database(DB_PATH);
db.pragma('journal_mode = wal');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    password   TEXT,            -- permitir NULL (tu login solo usa 'usuario')
    session_id TEXT
  )
`).run();

/* ===================== CORS ===================== */
const ORIGINS = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const corsOptions = {
  credentials: true,
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // permitir herramientas locales
    if (ORIGINS.length === 0) return cb(null, true); // sin restricción explícita
    if (ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('CORS origin not allowed: ' + origin));
  },
};
app.use(cors(corsOptions));

/* ===================== Sesiones (dev-friendly) ===================== */
const store = new SQLiteStore({
  dir: SESSIONS_DIR,
  db: 'sessions.sqlite',
});

const cookieSecure = process.env.COOKIE_SECURE === 'true'; // SOLO si lo pones a true
const sameSite = process.env.SAMESITE || (cookieSecure ? 'none' : 'lax');

app.use(session({
  secret: process.env.SESSION_SECRET || 'please_change_me',
  resave: false,
  saveUninitialized: false,
  store,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite,                               // 'lax' en local; 'none' si secure
    secure: cookieSecure,                   // no forzar por NODE_ENV (mejor para localhost)
    maxAge: 1000 * 60 * 60 * 8,             // 8 horas
  }
}));

const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

/* ===================== Body & estáticos ===================== */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(path.join(process.cwd(), 'public'), {
  setHeaders(res) {
    res.setHeader('Cache-Control', 'no-store');
  }
}));

/* ===================== Login y sesión única ===================== */
app.get('/', (req, res) => res.redirect('/inicio'));
app.get('/inicio', requiereSesionUnica, (req, res) =>
  res.sendFile(path.join(process.cwd(), 'public', 'inicio.html'))
);

app.post('/login', async (req, res) => {
  try {
    const user = req.body.usuario?.trim();
    if (!user) return res.redirect('/login.html?error=falta_usuario');

    let found = db.prepare('SELECT * FROM users WHERE username = ?').get(user);
    if (!found) {
      db.prepare('INSERT INTO users (username, password, session_id) VALUES (?, NULL, NULL)').run(user);
      found = { username: user, session_id: null };
      console.log(`👤 Usuario creado automáticamente: ${user}`);
    }

    // Expulsar sesión previa (sesión única)
    if (found.session_id) {
      try { await storeDestroy(found.session_id); } catch {}
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user);
    }

    // Nueva sesión
    await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
    const claim = db.prepare(
      'UPDATE users SET session_id = ? WHERE username = ? AND (session_id IS NULL OR session_id = "")'
    ).run(req.sessionID, user);

    if (claim.changes === 0) {
      // Otro proceso nos pisó: sesión activa
      return res.redirect('/login.html?error=sesion_activa');
    }

    req.session.usuario = user;
    console.log(`✅ Sesión iniciada: ${user} (${req.sessionID})`);
    res.redirect('/inicio');
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
});

app.post('/logout', requiereSesionUnica, async (req, res) => {
  try {
    const user = req.session.usuario;
    if (user) db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user);

    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.status(200).json({ ok: true });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'logout_failed' });
  }
});

async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');
    const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!row?.session_id || row.session_id !== req.sessionID) {
      return res.redirect('/login.html?error=sesion_caducada');
    }
    next();
  } catch (e) {
    console.error('requiereSesionUnica:', e);
    res.redirect('/login.html?error=interno');
  }
}

/* ===================== Utils Weather Underground ===================== */
function requireWU(res) {
  const apiKey = process.env.WU_API_KEY;
  const stationId = process.env.WU_STATION_ID;
  if (!apiKey || !stationId) {
    res.status(400).json({
      error: 'config_missing',
      message: 'Faltan WU_API_KEY o WU_STATION_ID en variables de entorno',
    });
    return null;
  }
  return { apiKey, stationId };
}

function yyyymmdd(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}${m}${day}`;
}

/* ===================== Proxys a WU ===================== */
// Histórico diario PWS (usa startDate y endDate en YYYYMMDD)
app.get('/api/weather/history', requiereSesionUnica, async (req, res) => {
  try {
    const base = requireWU(res);
    if (!base) return;
    const apiKey = base.apiKey;
    const stationId = req.query.stationId || base.stationId;

    const startDate = (req.query.startDate || '').replace(/[^0-9]/g, '');
    const endDate   = (req.query.endDate || '').replace(/[^0-9]/g, '');
    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'bad_range', message: 'Falta startDate y/o endDate (YYYYMMDD)' });
    }

    const url = new URL('https://api.weather.com/v2/pws/history/daily');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', 'm');
    url.searchParams.set('startDate', startDate);
    url.searchParams.set('endDate', endDate);
    url.searchParams.set('apiKey', apiKey);

    const r = await fetch(url, { headers: { 'Accept': 'application/json,text/plain,*/*' } });
    const bodyText = await r.text();
    if (!r.ok) return res.status(r.status).json({ error: 'weather_denied', status: r.status, body: bodyText.slice(0, 500) });

    res.type('application/json').send(bodyText);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'weather_history_failed', message: String(e) });
  }
});

// Observaciones actuales (simple proxy opcional)
app.get('/api/weather/current', requiereSesionUnica, async (req, res) => {
  try {
    const base = requireWU(res);
    if (!base) return;
    const apiKey = base.apiKey;
    const stationId = req.query.stationId || base.stationId;

    const url = new URL('https://api.weather.com/v2/pws/observations/current');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', 'm');
    url.searchParams.set('apiKey', apiKey);

    const r = await fetch(url, { headers: { 'Accept': 'application/json,text/plain,*/*' } });
    const bodyText = await r.text();
    if (!r.ok) return res.status(r.status).json({ error: 'weather_denied', status: r.status, body: bodyText.slice(0, 500) });

    res.type('application/json').send(bodyText);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'weather_current_failed', message: String(e) });
  }
});

/* ===================== Lluvia total mensual ===================== */
app.get('/api/lluvia/total/month', requiereSesionUnica, async (req, res) => {
  try {
    const base = requireWU(res);
    if (!base) return;
    const apiKey = base.apiKey;
    const stationId = req.query.stationId || base.stationId;

    const now = new Date();
    const y = Number(req.query.year)  || now.getFullYear();
    const m = Number(req.query.month) || (now.getMonth() + 1);

    const start = new Date(y, m - 1, 1);
    const end   = new Date(y, m, 0); // último día del mes

    const url = new URL('https://api.weather.com/v2/pws/history/daily');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', 'm');
    url.searchParams.set('startDate', yyyymmdd(start));
    url.searchParams.set('endDate', yyyymmdd(end));
    url.searchParams.set('apiKey', apiKey);

    const r = await fetch(url);
    const data = await (async () => { try { return await r.json(); } catch { return {}; } })();
    if (!r.ok) {
      return res.status(r.status).json({ error: 'weather_denied', status: r.status, details: data });
    }

    const obs = Array.isArray(data?.observations) ? data.observations : [];
    const total = obs.reduce((a, d) => a + (+d?.metric?.precipTotal || 0), 0);

    res.json({ year: +y, month: +m, total_mm: +total.toFixed(2), days: obs.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'month_failed', message: String(e) });
  }
});

/* ===================== Lluvia total anual ===================== */
app.get('/api/lluvia/total/year', requiereSesionUnica, async (req, res) => {
  try {
    const base = requireWU(res);
    if (!base) return;
    const apiKey = base.apiKey;
    const stationId = req.query.stationId || base.stationId;

    const now = new Date();
    const year = now.getFullYear();
    const startDate = `${year}0101`;
    const endDate   = yyyymmdd(now);

    const url = new URL('https://api.weather.com/v2/pws/history/daily');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', 'm');
    url.searchParams.set('startDate', startDate);
    url.searchParams.set('endDate', endDate);
    url.searchParams.set('apiKey', apiKey);

    const r = await fetch(url);
    const data = await (async () => { try { return await r.json(); } catch { return {}; } })();
    if (!r.ok) {
      return res.status(r.status).json({
        error: 'weather_denied',
        status: r.status,
        message: 'Weather Underground rechazó la petición',
        details: data,
      });
    }

    const obs = Array.isArray(data?.observations) ? data.observations : [];
    const total = obs.reduce((a, d) => a + (+d?.metric?.precipTotal || 0), 0);

    // Para el subtítulo del rango en el front
    const desde = `${year}-01-01`;
    const hasta = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;

    res.json({
      year,
      total_mm: +total.toFixed(2),
      desde,
      hasta,
      days: obs.length
    });
  } catch (e) {
    console.error('Error /api/lluvia/total/year:', e);
    res.status(500).json({ error: 'year_failed', message: String(e) });
  }
});

/* Alias por compatibilidad */
app.get('/api/lluvia/total', (req, res) => res.redirect(307, '/api/lluvia/total/year'));

/* ===================== Arranque ===================== */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor activo en puerto ${PORT}`);
  console.log(`   NODE_ENV=${process.env.NODE_ENV || 'development'} | COOKIE_SECURE=${process.env.COOKIE_SECURE || 'false'} | SAMESITE=${sameSite}`);
});






