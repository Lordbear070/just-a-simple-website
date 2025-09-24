// server.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public")); // serve html/css/js from "public" folder

// === CONFIG ===
const DATA_FOLDER = path.join(process.env.USERPROFILE, "SimpleWebsiteData");
const USERS_FOLDER = path.join(DATA_FOLDER, "users");
if (!fs.existsSync(USERS_FOLDER)) fs.mkdirSync(USERS_FOLDER, { recursive: true });

// sessions stored in memory: token -> username
const sessions = {};

// === HELPERS ===
function hashPassword(pw) {
  return crypto.createHash("sha384").update(pw).digest("hex");
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  const token = auth.slice(7);
  const username = sessions[token];
  if (!username) {
    return res.status(401).json({ ok: false, error: "Invalid session" });
  }
  req.username = username;
  req.userFolder = path.join(USERS_FOLDER, username);
  next();
}

// === AUTH ROUTES ===
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, error: "Missing username or password" });
  if (password.length < 6) return res.json({ ok: false, error: "Password must be at least 6 characters." });

  const userFolder = path.join(USERS_FOLDER, username);
  if (fs.existsSync(userFolder)) return res.json({ ok: false, error: "User already exists" });

  fs.mkdirSync(userFolder, { recursive: true });
  fs.writeFileSync(path.join(userFolder, "master.hash"), hashPassword(password));
  res.json({ ok: true });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const userFolder = path.join(USERS_FOLDER, username);
  if (!fs.existsSync(userFolder)) return res.json({ ok: false, error: "User not found" });

  const savedHash = fs.readFileSync(path.join(userFolder, "master.hash"), "utf8");
  if (hashPassword(password) !== savedHash) {
    return res.json({ ok: false, error: "Invalid password" });
  }

  const token = crypto.randomBytes(24).toString("hex");
  sessions[token] = username;
  res.json({ ok: true, token });
});

// === RAMBLE ===
app.get("/api/ramble", requireAuth, (req, res) => {
  const rambleFile = path.join(req.userFolder, "ramble.txt");
  let text = "";
  if (fs.existsSync(rambleFile)) text = fs.readFileSync(rambleFile, "utf8");
  res.json({ ok: true, text });
});

app.post("/api/ramble", requireAuth, (req, res) => {
  const { text } = req.body;
  const rambleFile = path.join(req.userFolder, "ramble.txt");
  fs.writeFileSync(rambleFile, text || "");
  res.json({ ok: true });
});

// === PASSWORD MANAGER ===
// store encrypted JSON string per user
app.get("/api/passwords", requireAuth, (req, res) => {
  const vaultFile = path.join(req.userFolder, "passwords.json");
  let entries = [];
  if (fs.existsSync(vaultFile)) {
    entries = JSON.parse(fs.readFileSync(vaultFile, "utf8"));
  }
  res.json({ ok: true, entries });
});

app.post("/api/passwords", requireAuth, (req, res) => {
  const vaultFile = path.join(req.userFolder, "passwords.json");
  const { entry } = req.body;
  if (!entry || !entry.website) {
    return res.json({ ok: false, error: "Missing entry or website" });
  }

  let entries = [];
  if (fs.existsSync(vaultFile)) {
    entries = JSON.parse(fs.readFileSync(vaultFile, "utf8"));
  }
  entries.push(entry);
  fs.writeFileSync(vaultFile, JSON.stringify(entries, null, 2));
  res.json({ ok: true });
});

const MUSIC_FOLDER = "D:\\music";

function listFilesRecursive(dir) {
  let results = [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(file => {
    const fullPath = path.join(dir, file.name);
    if (file.isDirectory()) {
      results = results.concat(listFilesRecursive(fullPath));
    } else if (/\.(mp3|wav)$/i.test(file.name)) {
      results.push(fullPath);
    }
  });
  return results;
}

app.get("/api/music", requireAuth, (req, res) => {
  const files = listFilesRecursive(MUSIC_FOLDER);
  res.json({ ok: true, files });
});

app.get("/musicfile", requireAuth, (req, res) => {
  const f = req.query.path;
  if (!f || !f.startsWith(MUSIC_FOLDER)) return res.status(400).end();
  res.sendFile(f);
});

// === TODO: password manager endpoints will go here (similar pattern) ===

// === START SERVER ===
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server started at http://localhost:${PORT}`);
});
