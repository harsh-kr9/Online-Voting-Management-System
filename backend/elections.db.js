// elections.routes.js
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('./elections.db');
// optional: jsonwebtoken is only used to decode token payload (does NOT verify)
const jwt = require('jsonwebtoken');

const router = express.Router();

// helper: short id
function generateShortId() {
  return uuidv4().replace(/-/g, '').slice(0, 10);
}

// try to extract user info from Authorization header (no verification here).
function getUserFromAuthHeader(req) {
  const auth = req.headers['authorization'] || req.headers['Authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  try {
    // For demo: decode only. In production replace with jwt.verify(token, SECRET)
    return jwt.decode(token) || null;
  } catch (e) {
    return null;
  }
}

/**
 * POST /api/elections
 * Expected body: { title, description, start, end, eligibility, candidates: [{name,party,manifesto}], publish }
 * Returns: { success: true, election: { id, title, ..., candidates: [...] } }
 */
router.post('/api/elections', async (req, res) => {
  try {
    const body = req.body || {};
    const { title, description = '', start, end, eligibility = 'all', candidates = [], publish = false } = body;

    if (!title || !start || !end) return res.status(400).json({ error: 'title, start and end are required' });
    if (new Date(start) >= new Date(end)) return res.status(400).json({ error: 'end must be after start' });

    const user = getUserFromAuthHeader(req);
    const created_by = user ? (user.email || user.sub || user.id || user.name) : null;

    // create unique id
    let electionId = generateShortId();
    let tries = 0;
    while (db.electionExists(electionId) && tries < 6) {
      electionId = generateShortId(); tries++;
    }
    if (db.electionExists(electionId)) return res.status(500).json({ error: 'Could not generate unique election id' });

    const electionObj = {
      id: electionId,
      title,
      description,
      start_at: new Date(start).toISOString(),
      end_at: new Date(end).toISOString(),
      eligibility,
      publish: publish ? 1 : 0,
      created_by,
      created_at: new Date().toISOString()
    };

    db.insertElection(electionObj);

    const savedCandidates = [];
    if (Array.isArray(candidates)) {
      for (const c of candidates) {
        const name = (c.name || '').trim();
        if (!name) continue;
        const info = db.insertCandidate({
          election_id: electionId,
          name,
          party: c.party || '',
          manifesto: c.manifesto || ''
        });
        savedCandidates.push({ id: info.lastInsertRowid, name, party: c.party || '', manifesto: c.manifesto || '' });
      }
    }

    return res.status(201).json({
      success: true,
      election: {
        id: electionId,
        title,
        description,
        start_at: electionObj.start_at,
        end_at: electionObj.end_at,
        eligibility,
        publish: !!publish,
        created_by,
        created_at: electionObj.created_at,
        candidates: savedCandidates
      }
    });
  } catch (err) {
    console.error('Create election error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/elections/:id
 * returns { election: { ... , candidates: [...] } } or 404
 */
router.get('/api/elections/:id', (req, res) => {
  const id = req.params.id;
  const election = db.getElectionById(id);
  if (!election) return res.status(404).json({ error: 'Election not found' });
  return res.json({ election });
});

/**
 * GET /api/elections/:id/candidates
 * returns { candidates: [...] }
 */
router.get('/api/elections/:id/candidates', (req, res) => {
  const id = req.params.id;
  const candidates = db.getCandidatesByElectionId(id);
  return res.json({ candidates });
});

module.exports = router;
