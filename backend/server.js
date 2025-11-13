/**
 * server.js
 * Complete, drop-in backend for myVote (file-based, no native modules)
 *
 * - Node.js + Express + bcryptjs + jsonwebtoken + uuid
 * - Stores data in users.json and elections.json (created automatically)
 * - Endpoints:
 *    POST /api/register
 *    POST /api/login
 *    GET  /api/me
 *    POST /api/elections         (any logged-in user)
 *    GET  /api/elections
 *    GET  /api/elections/:id
 *    GET  /api/elections/:id/candidates
 *
 * Save this file to your backend folder (replace existing server.js),
 * ensure package.json has dependencies (express, cors, dotenv, bcryptjs, jsonwebtoken, uuid),
 * then run:
 *    npm install
 *    npm start
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// files
const USERS_FILE = path.join(__dirname, 'users.json');
const ELECTIONS_FILE = path.join(__dirname, 'elections.json');
const AUDIT_LOG = path.join(__dirname, 'audit.log');

app.use(cors());
app.use(express.json());

// ------------------------
// Utility: file helpers
// ------------------------
function ensureFile(filePath, defaultContent) {
  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultContent, null, 2), 'utf8');
    }
  } catch (e) {
    console.error('ensureFile error', filePath, e);
  }
}

function readJSON(filePath, defaultContent) {
  try {
    ensureFile(filePath, defaultContent);
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw || JSON.stringify(defaultContent));
  } catch (err) {
    console.error('readJSON error', filePath, err);
    return defaultContent;
  }
}

function writeJSON(filePath, obj) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), 'utf8');
  } catch (err) {
    console.error('writeJSON error', filePath, err);
  }
}

// users helpers
function readData() {
  return readJSON(USERS_FILE, { users: [] });
}
function writeData(obj) {
  writeJSON(USERS_FILE, obj);
}

// elections helpers
function readElections() {
  return readJSON(ELECTIONS_FILE, { elections: [] });
}
function writeElections(obj) {
  writeJSON(ELECTIONS_FILE, obj);
}

// simple audit logging
function audit(line) {
  try {
    const ts = new Date().toISOString();
    fs.appendFileSync(AUDIT_LOG, `${ts} | ${line}\n`);
  } catch (e) {
    // ignore logging errors
  }
}

// ------------------------
// Validation helpers
// ------------------------
function isValidEmail(e) {
  return !!e && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}
function isValidPhone(p) {
  return !!p && /^[+\d][\d\s\-]{6,20}$/.test(p);
}

// ------------------------
// Auth helpers
// ------------------------
function signTokenForUser(user) {
  // include id so we can lookup user record later
  const payload = { id: user.id, name: user.name || '', email: user.email || '', phone: user.phone || '' };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}

function getUserFromAuthHeader(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  try {
    const data = jwt.verify(token, JWT_SECRET);
    const db = readData();
    const user = db.users.find(u => u.id === data.id);
    return user || null;
  } catch (err) {
    return null;
  }
}

function requireAdmin(req, res) {
  const user = getUserFromAuthHeader(req);
  if (!user) {
    res.status(401).json({ error: 'Missing or invalid token' });
    return null;
  }
  if (!user.isAdmin) {
    res.status(403).json({ error: 'Admin access required' });
    return null;
  }
  return user;
}

function requireAuth(req, res) {
  const user = getUserFromAuthHeader(req);
  if (!user) {
    res.status(401).json({ error: 'Missing or invalid token' });
    return null;
  }
  return user;
}

// ------------------------
// Routes: Users / Auth
// ------------------------

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, phone, password, age, aadhar, gender } = req.body || {};

    // basic validation
    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ error: 'Name is required and must be at least 2 characters.' });
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password is required and must be at least 6 characters.' });
    }
    if ((!email || email.trim() === '') && (!phone || phone.trim() === '')) {
      return res.status(400).json({ error: 'Either email or phone is required.' });
    }
    if (email && !isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format.' });
    if (phone && !isValidPhone(phone)) return res.status(400).json({ error: 'Invalid phone format.' });

    const db = readData();

    if (email && db.users.find(u => u.email === email.trim())) return res.status(409).json({ error: 'Email already registered.' });
    if (phone && db.users.find(u => u.phone === phone.trim())) return res.status(409).json({ error: 'Phone already registered.' });

    // hash password (bcryptjs)
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const user = {
      id: uuidv4(),
      name: name.trim(),
      email: email ? email.trim() : null,
      phone: phone ? phone.trim() : null,
      password_hash: hash,
      created_at: Date.now(),
      // optional fields
      age: age ? Number(age) : undefined,
      aadhar: aadhar ? String(aadhar) : undefined,
      gender: gender || undefined,
      isAdmin: false
    };

    // push and save
    db.users.push(user);
    writeData(db);

    audit(`register | user:${user.id}`);

    return res.status(201).json({ message: 'User registered successfully', userId: user.id });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/login
app.post('/api/login', (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) return res.status(400).json({ error: 'identifier and password are required' });

    const db = readData();
    const user = db.users.find(u => (u.email === identifier) || (u.phone === identifier));
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signTokenForUser(user);
    audit(`login | user:${user.id}`);
    return res.json({ message: 'Authenticated', token });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/me
app.get('/api/me', (req, res) => {
  const user = getUserFromAuthHeader(req);
  if (!user) return res.status(401).json({ error: 'Missing or invalid token' });
  // return safe user info (no password hash)
  const safe = { id: user.id, name: user.name, email: user.email, phone: user.phone, isAdmin: !!user.isAdmin };
  res.json({ user: safe });
});

// ------------------------
// Routes: Elections
// ------------------------

// POST /api/elections  (any logged-in user)
app.post('/api/elections', (req, res) => {
  try {
    // require any authenticated user (not just admin)
    const authUser = requireAuth(req, res);
    if (!authUser) return;

    // accept either numeric timestamps (ms) or ISO strings for start/end
    const {
      companyName,
      totalSeats,
      start_ts, // can be number (ms) or ISO string
      end_ts,   // same as above
      description = '',
      candidates = []
    } = req.body || {};

    if (!companyName || !totalSeats || !start_ts || !end_ts || !Array.isArray(candidates) || candidates.length === 0) {
      return res.status(400).json({ error: 'companyName, totalSeats, start_ts, end_ts and at least one candidate are required' });
    }

    // normalize timestamps
    const parseToNumber = (v) => {
      if (typeof v === 'number') return Number(v);
      const d = new Date(String(v));
      if (isNaN(d.getTime())) return NaN;
      return d.getTime();
    };

    const s = parseToNumber(start_ts), e = parseToNumber(end_ts), seats = Number(totalSeats);
    if (Number.isNaN(s) || Number.isNaN(e) || s >= e) return res.status(400).json({ error: 'Invalid start/end timestamps' });
    if (!Number.isInteger(seats) || seats <= 0) return res.status(400).json({ error: 'totalSeats must be a positive integer' });

    const electionsDb = readElections();
    const election = {
      id: uuidv4(),
      companyName: String(companyName).trim(),
      totalSeats: seats,
      description: String(description || ''),
      start_ts: s,
      end_ts: e,
      created_by: authUser.id,
      created_at: Date.now(),
      // candidates: each candidate gets an id + votes counter + optional party/manifesto
      candidates: candidates.map(c => ({
        id: uuidv4(),
        name: String(c.name || '').trim(),
        description: c.description || '',
        party: c.party || '',
        manifesto: c.manifesto || '',
        votes: 0
      }))
    };

    // save
    electionsDb.elections.push(election);
    writeElections(electionsDb);

    audit(`create-election | user:${authUser.id} | election:${election.id}`);

    // return full election object so client can immediately use election.id and view candidate list
    return res.status(201).json({ success: true, election });
  } catch (err) {
    console.error('create election error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/elections  (public summary)
app.get('/api/elections', (req, res) => {
  const db = readElections();
  const list = db.elections.map(e => ({
    id: e.id,
    companyName: e.companyName,
    totalSeats: e.totalSeats,
    start_ts: e.start_ts,
    end_ts: e.end_ts,
    description: e.description
  }));
  res.json({ elections: list });
});

// GET /api/elections/:id  (details incl candidates & votes)
app.get('/api/elections/:id', (req, res) => {
  const db = readElections();
  const e = db.elections.find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Election not found' });
  res.json({ election: e });
});

// GET /api/elections/:id/candidates  (id + name + description + party + manifesto)
app.get('/api/elections/:id/candidates', (req, res) => {
  const db = readElections();
  const e = db.elections.find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Election not found' });
  const candidates = e.candidates.map(c => ({
    id: c.id,
    name: c.name,
    description: c.description,
    party: c.party || '',
    manifesto: c.manifesto || ''
  }));
  res.json({ electionId: e.id, candidates });
});

// ------------------------
// Health / fallback
// ------------------------
app.get('/', (req, res) => {
  res.send('myVote backend: API running. Use /api/* endpoints.');
});

// ------------------------
// Start server
// ------------------------
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Users: ${USERS_FILE}`);
  console.log(`Elections: ${ELECTIONS_FILE}`);
});
