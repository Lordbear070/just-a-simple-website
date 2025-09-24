// server.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const util = require('util');
const readdir = util.promisify(fs.readdir);
const stat = util.promisify(fs.stat);

const app = express();
const PORT = 3000;

// Config - change these if you want
const DATA_FOLDER = "C:\\Program Files\\Simple website data";
const RAMBLE_FILE = path.join(DATA_FOLDER, "ramble.txt");
const MASTER_FILE = path.join(DATA_FOLDER, "master.hash"); // stores sha384 hash of master password (hex)
const VAULT_FILE = path.join(DATA_FOLDER, "passwords.enc"); // encrypted blob
const VAULT_META = path.join(DATA_FOLDER, "passwords.meta.json"); // stores salt etc

const MUSIC_ROOT = "D:\\music"; // source music folder

// Ensure data folder exists
if (!fs.existsSync(DATA_FOLDER)){
  try {
    fs.mkdirSync(DATA_FOLDER, { recursive: true });
    console.log("Created data folder:", DATA_FOLDER);
  } catch (err) {
    console.error("Could not create data folder. Run as admin or choose another folder.", err);
    process.exit(1);
  }
}

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // local only; if you enable https set true
}));

// serve frontend static files from "public"
app.use(express.static(path.join(__dirname, 'public')));

/* --------- Utility: Crypto --------- */
function sha384Hex(input) {
  return crypto.createHash('sha384').update(input, 'utf8').digest('hex');
}

function deriveKey(masterPassword, salt, iterations = 200000) {
  // returns Buffer (32 bytes)
  return crypto.pbkdf2Sync(masterPassword, salt, iterations, 32, 'sha512');
}

function encryptVault(plaintextJson, masterPassword) {
  const salt = crypto.randomBytes(16);
  const key = deriveKey(masterPassword, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintextJson, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

function decryptVault(encObj, masterPassword) {
  const salt = Buffer.from(encObj.salt, 'base64');
  const iv = Buffer.from(encObj.iv, 'base64');
  const tag = Buffer.from(encObj.tag, 'base64');
  const ct = Buffer.from(encObj.ciphertext, 'base64');
  const key = deriveKey(masterPassword, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString('utf8');
}

/* --------- Auth endpoints --------- */

// Register master password (first time)
app.post('/api/register', (req, res) => {
  const { master } = req.body;
  if (!master || master.length < 6) {
    return res.status(400).json({ ok: false, error: "Master password must be at least 6 characters." });
  }
  if (fs.existsSync(MASTER_FILE)) {
    return res.status(400).json({ ok: false, error: "Master password already set. Use login." });
  }
  const hash = sha384Hex(master);
  fs.writeFileSync(MASTER_FILE, hash, { encoding: 'utf8' });
  req.session.authed = true;
  res.json({ ok: true });
});

// Login
app.post('/api/login', (req, res) => {
  const { master } = req.body;
  if (!master) return res.status(400).json({ ok: false, error: "Missing master password." });
  if (!fs.existsSync(MASTER_FILE)) return res.status(400).json({ ok: false, error: "No master password set. Register first." });
  const saved = fs.readFileSync(MASTER_FILE, 'utf8').trim();
  const hash = sha384Hex(master);
  if (hash === saved) {
    req.session.authed = true;
    // Note: we do not store the password on the server. Client will keep it for encryption/decryption operations.
    res.json({ ok: true });
  } else {
    res.status(401).json({ ok: false, error: "Invalid password." });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/* --------- Middleware to require login for APIs --------- */
function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  res.status(401).json({ ok: false, error: "Not authenticated" });
}

/* --------- Rambleling: simple text editor save/load --------- */
app.get('/api/ramble/load', requireAuth, (req, res) => {
  const content = fs.existsSync(RAMBLE_FILE) ? fs.readFileSync(RAMBLE_FILE, 'utf8') : '';
  res.json({ ok: true, content });
});

app.post('/api/ramble/save', requireAuth, (req, res) => {
  const { content } = req.body;
  try {
    fs.writeFileSync(RAMBLE_FILE, content || '', 'utf8');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.toString() });
  }
});

/* --------- Music: list and stream --------- */

// Helper: recursively list files under MUSIC_ROOT
async function listMusic(dir) {
  let results = [];
  let items = await readdir(dir);
  for (const f of items) {
    const full = path.join(dir, f);
    let s = await stat(full);
    if (s.isDirectory()) {
      const sub = await listMusic(full);
      results = results.concat(sub);
    } else {
      // accept .mp3 and .wav
      if (/\.(mp3|wav)$/i.test(f)) {
        results.push({ path: full, name: path.relative(MUSIC_ROOT, full).replace(/\\/g, "/"), size: s.size });
      }
    }
  }
  return results;
}

// Endpoint: list music
app.get('/api/music/list', requireAuth, async (req, res) => {
  try {
    if (!fs.existsSync(MUSIC_ROOT)) return res.json({ ok: true, files: [] });
    const files = await listMusic(MUSIC_ROOT);
    res.json({ ok: true, files });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.toString() });
  }
});

// Stream file (by relative path)
app.get('/api/music/stream', requireAuth, (req, res) => {
  const rel = req.query.path;
  if (!rel) return res.status(400).json({ ok: false, error: "path query required" });

  // Build absolute path safely
  const full = path.join(MUSIC_ROOT, rel);
  if (!full.startsWith(MUSIC_ROOT)) return res.status(400).json({ ok: false, error: "Invalid path" });
  if (!fs.existsSync(full)) return res.status(404).json({ ok: false, error: "File not found" });

  const statObj = fs.statSync(full);
  const range = req.headers.range;
  if (range) {
    const parts = range.replace(/bytes=/, "").split("-");
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : statObj.size - 1;
    if (start >= statObj.size) {
      res.status(416).send('Requested range not satisfiable\n' + start + ' >= ' + statObj.size);
      return;
    }
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${statObj.size}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': (end - start) + 1,
      'Content-Type': 'audio/mpeg'
    });
    fs.createReadStream(full, { start, end }).pipe(res);
  } else {
    res.writeHead(200, {
      'Content-Length': statObj.size,
      'Content-Type': 'audio/mpeg'
    });
    fs.createReadStream(full).pipe(res);
  }
});

/* --------- Passwords manager: encrypt/decrypt vault --------- */

// Save vault: client sends master password + vault JSON (array of entries); server encrypts and stores
app.post('/api/passwords/save', requireAuth, (req, res) => {
  const { master, vault } = req.body; // vault is JSON string or object
  if (!master || !vault) return res.status(400).json({ ok: false, error: "Missing master or vault." });
  const vaultJson = typeof vault === 'string' ? vault : JSON.stringify(vault);
  try {
    const enc = encryptVault(vaultJson, master);
    fs.writeFileSync(VAULT_FILE, JSON.stringify(enc), 'utf8');
    // write meta so client can know file exists
    fs.writeFileSync(VAULT_META, JSON.stringify({ created: new Date().toISOString() }), 'utf8');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.toString() });
  }
});

// Load vault: client provides master password, server returns decrypted JSON
app.post('/api/passwords/load', requireAuth, (req, res) => {
  const { master } = req.body;
  if (!master) return res.status(400).json({ ok: false, error: "Missing master." });
  try {
    if (!fs.existsSync(VAULT_FILE)) return res.json({ ok: true, vault: [] });
    const enc = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
    const plaintext = decryptVault(enc, master);
    const parsed = JSON.parse(plaintext);
    res.json({ ok: true, vault: parsed });
  } catch (err) {
    res.status(500).json({ ok: false, error: "Unable to decrypt: " + err.toString() });
  }
});

/* --------- Start server --------- */
app.listen(PORT, () => {
  console.log(`Server started at http://localhost:${PORT}`);
});
