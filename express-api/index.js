require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').MongoStore;
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const axios = require('axios');
const multer = require('multer');

const User = require('./models/User');
const ScanHistory = require('./models/ScanHistory');

const app = express();
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ai-security-reviewer';
const rawFastApi = process.env.FASTAPI_URL || 'http://localhost:8000';
const FASTAPI_URL = (rawFastApi.startsWith('http://') || rawFastApi.startsWith('https://')) ? rawFastApi : `https://${rawFastApi}`;
const FRONTEND_URL = process.env.FRONTEND_URL || true;
axios.defaults.timeout = 180000;

// Connect to MongoDB
mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 })
  .then(() => console.log('Connected to MongoDB successfully'))
  .catch(() => console.warn('MongoDB unavailable: account and vault endpoints will return 503. Guest scans remain available.'));
mongoose.set('bufferCommands', false);

// Multer memory storage for safe file intake (max 50MB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 50 }
});

// Middleware
app.use(morgan('dev'));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Sessions share the established MongoDB connection. Failed storage never silently
// creates an unauthenticated application or an unhandled rejected promise.
const sessionClient = mongoose.connection.asPromise().then(connection => connection.getClient());
sessionClient.catch(() => {});
const sessionStore = MongoStore.create({
  clientPromise: sessionClient,
  collectionName: 'sessions',
  ttl: 14 * 24 * 60 * 60,
  autoRemove: 'native',
});
sessionStore.collectionP.catch(() => {});
sessionStore.on('error', () => console.warn('Session storage unavailable.'));
const sessionMiddleware = session({
  name: 'reviewer.sid',
  secret: process.env.SESSION_SECRET || 'reviewer-session-secret-key-1337',
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    maxAge: 14 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.COOKIE_SAMESITE || 'lax',
  },
});
app.use((req, res, next) => {
  if (mongoose.connection.readyState !== 1) return next();
  sessionMiddleware(req, res, next);
});

// Auth Middleware
const requireAuth = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
};

app.get('/health', async (req, res) => {
  try {
    const analysis = await axios.get(`${FASTAPI_URL}/health/`, { timeout: 5000 });
    res.json({ status: 'ready', database: mongoose.connection.readyState === 1, analysis: analysis.data });
  } catch {
    res.status(503).json({ status: 'unavailable', error: 'Analysis engine is not reachable.' });
  }
});

app.use((req, res, next) => {
  const needsDatabase = req.path.startsWith('/history') || req.path.startsWith('/api/v1/scans/') ||
    req.path === '/auth/signup' || req.path === '/auth/login' || (req.path === '/auth/me' && req.session?.userId);
  if (needsDatabase && mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Account and vault storage is unavailable. Start MongoDB and restart the gateway.' });
  }
  next();
});

// Helper: Save to History if logged in and not ephemeral
async function persistScanResult(userId, scanResult, ephemeral = false) {
  if (!userId || ephemeral || scanResult.privacy_metadata?.ephemeral_scan) {
    return;
  }
  try {
    const historyItem = new ScanHistory({
      user: userId,
      analysis_id: scanResult.analysis_id,
      scan_type: scanResult.scan_type || 'paste',
      score: scanResult.summary?.security_score ?? 100,
      language: scanResult.language || 'auto',
      critical: scanResult.summary?.critical ?? 0,
      high: scanResult.summary?.high ?? 0,
      medium: scanResult.summary?.medium ?? 0,
      low: scanResult.summary?.low ?? 0,
      summary: scanResult.summary,
      findings: scanResult.findings,
      // Keep findings/snippets, never the complete submitted source.
      files_analyzed: scanResult.files_analyzed || [],
      files_skipped: scanResult.files_skipped || [],
      scanner_status: scanResult.scanner_status || [],
      malware_status: scanResult.malware_status || null,
      privacy_metadata: scanResult.privacy_metadata || {},
      repository_url: scanResult.repository_url || null,
      commit_sha: scanResult.commit_sha || null,
      parent_sha: scanResult.parent_sha || null,
      changed_files: scanResult.changed_files || {},
      new_findings: scanResult.new_findings || [],
      fixed_findings: scanResult.fixed_findings || [],
      persistent_findings: scanResult.persistent_findings || []
    });
    await historyItem.save();
  } catch (err) {
    console.error('Error persisting scan to MongoDB:', err.message);
    scanResult.persistence_warning = 'The report could not be saved to your vault. Export it to keep a copy.';
  }
}

// --- AUTH ROUTES ---
app.get('/auth/me', async (req, res) => {
  try {
    if (!req.session || !req.session.userId) {
      return res.json({ user: null });
    }
    const user = await User.findById(req.session.userId).select('-password');
    if (!user) {
      req.session.destroy();
      return res.json({ user: null });
    }
    res.json({ user });
  } catch (err) {
    console.error('Error fetching current user:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/signup', async (req, res) => {
  try {
    const { password } = req.body;
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (typeof password !== 'string' || password.length < 6 || Buffer.byteLength(password) > 72) return res.status(400).json({ error: 'Password must be at least 6 characters and no more than 72 bytes' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'A valid email address is required' });

    const existingUser = await User.findOne({ $or: [{ username }, { email: email.toLowerCase() }] });
    if (existingUser) {
      return res.status(400).json({ error: existingUser.username === username ? 'Username is taken' : 'Email registered' });
    }

    const user = new User({ username, email, password });
    await user.save();
    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    req.session.userId = user._id;
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    const userObj = user.toObject();
    delete userObj.password;
    res.status(201).json({ user: userObj });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { password } = req.body;
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    if (!username || typeof password !== 'string' || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = await User.findOne({ $or: [{ username }, { email: username.toLowerCase() }] });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    req.session.userId = user._id;
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
    const userObj = user.toObject();
    delete userObj.password;
    res.json({ user: userObj });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

app.post('/auth/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) return res.status(500).json({ error: 'Failed to log out' });
      res.clearCookie('reviewer.sid');
      res.json({ success: true, message: 'Logged out successfully' });
    });
  } else {
    res.json({ success: true, message: 'Logged out successfully' });
  }
});

// Health check endpoint for Render / monitoring
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'express-api', time: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.json({
    service: 'express-api',
    status: 'running',
    version: '2.0.0',
    endpoints: ['/health', '/auth/me', '/auth/login', '/auth/signup', '/api/v1/files/scan']
  });
});

// -------------------------------------------------------------
// V1 API ROUTES (3 MODES)
// -------------------------------------------------------------

// MODE 1: POST /api/v1/files/scan & /analyze (Paste Code / Single File)
const handleSingleScan = async (req, res) => {
  try {
    const { code, language, file_name, ephemeral } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'Code is required for analysis.' });
    }

    const response = await axios.post(`${FASTAPI_URL}/api/v1/files/scan`, {
      code,
      language: language || null,
      file_name: file_name || 'snippet',
      ephemeral: Boolean(ephemeral)
    });

    const scanResult = response.data;
    await persistScanResult(req.session?.userId, scanResult, Boolean(ephemeral));
    res.json(scanResult);
  } catch (err) {
    console.error('Single scan proxy error:', err.message);
    if (err.response) return res.status(err.response.status).json(err.response.data);
    res.status(502).json({ error: 'Failed to communicate with FastAPI analysis service.' });
  }
};

app.post('/analyze', handleSingleScan);
app.post('/api/v1/files/scan', handleSingleScan);

// MODE 2: POST /api/v1/files/scan-batch (File Upload / Batch / Archives)
app.post('/api/v1/files/scan-batch', upload.array('files', 50), async (req, res) => {
  try {
    let filesPayload = [];

    // If sent as multipart files
    if (req.files && req.files.length > 0) {
      if (req.files.reduce((size, file) => size + file.size, 0) > 50 * 1024 * 1024) {
        return res.status(413).json({ error: 'Combined upload exceeds the 50 MB limit.' });
      }
      filesPayload = req.files.map(f => ({
        filename: f.originalname,
        content: f.buffer.toString('base64'),
        encoding: 'base64'
      }));
    } else if (req.body.files) {
      // If sent as JSON array
      filesPayload = typeof req.body.files === 'string' ? JSON.parse(req.body.files) : req.body.files;
    }

    if (!filesPayload || filesPayload.length === 0) {
      return res.status(400).json({ error: 'No files uploaded or provided in payload.' });
    }

    const ephemeral = req.body.ephemeral === 'true' || req.body.ephemeral === true;

    const response = await axios.post(`${FASTAPI_URL}/api/v1/files/scan-batch`, {
      files: filesPayload,
      ephemeral
    });

    const scanResult = response.data;
    await persistScanResult(req.session?.userId, scanResult, ephemeral);
    res.json(scanResult);
  } catch (err) {
    console.error('Batch scan proxy error:', err.message);
    if (err.response) return res.status(err.response.status).json(err.response.data);
    res.status(502).json({ error: 'Failed to communicate with FastAPI analysis service for batch scan.' });
  }
});

// MODE 3: POST /api/v1/commits/analyze (GitHub Repo / Commit)
app.post('/api/v1/commits/analyze', async (req, res) => {
  try {
    const { repository_url, commit_sha, branch, strategy, baseline_findings, ephemeral } = req.body;

    if (!repository_url) {
      return res.status(400).json({ error: 'Repository URL is required.' });
    }

    const response = await axios.post(`${FASTAPI_URL}/api/v1/commits/analyze`, {
      repository_url,
      commit_sha: commit_sha || null,
      branch: branch || null,
      strategy: strategy || 'auto',
      baseline_findings: baseline_findings || [],
      ephemeral: Boolean(ephemeral)
    });

    const scanResult = response.data;
    await persistScanResult(req.session?.userId, scanResult, Boolean(ephemeral));
    res.json(scanResult);
  } catch (err) {
    console.error('Commit analysis proxy error:', err.message);
    if (err.response) return res.status(err.response.status).json(err.response.data);
    res.status(502).json({ error: 'Failed to communicate with FastAPI analysis service for commit scan.' });
  }
});

// GET /api/v1/scans/:scanId
app.get('/api/v1/scans/:scanId', requireAuth, async (req, res) => {
  try {
    const record = await ScanHistory.findOne({ analysis_id: req.params.scanId, user: req.session.userId });
    if (!record) {
      return res.status(404).json({ error: 'Scan record not found.' });
    }
    res.json(record);
  } catch (err) {
    console.error('Error fetching scan record:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE /api/v1/scans/:scanId
app.delete('/api/v1/scans/:scanId', requireAuth, async (req, res) => {
  try {
    const result = await ScanHistory.findOneAndDelete({
      analysis_id: req.params.scanId,
      user: req.session.userId
    });
    if (!result) return res.status(404).json({ error: 'Scan record not found or unauthorized' });
    res.json({ success: true, message: 'Scan record deleted successfully' });
  } catch (err) {
    console.error('Error deleting scan record:', err);
    res.status(500).json({ error: 'Failed to delete scan record' });
  }
});

// --- LEGACY HISTORY ROUTES ---
app.get('/history', requireAuth, async (req, res) => {
  try {
    const history = await ScanHistory.find({ user: req.session.userId }).sort({ timestamp: -1 });
    res.json(history);
  } catch (err) {
    console.error('Error fetching history:', err);
    res.status(500).json({ error: 'Internal server error fetching scan vault' });
  }
});

app.post('/history', requireAuth, async (req, res) => {
  try {
    if (req.body.privacy_metadata?.ephemeral_scan || req.body.is_demo) {
      return res.status(400).json({ error: 'Ephemeral and demo reports cannot be persisted.' });
    }
    const existing = await ScanHistory.findOne({ analysis_id: req.body.analysis_id, user: req.session.userId });
    if (existing) return res.json(existing);

    const historyItem = new ScanHistory({
      ...req.body,
      code: undefined,
      score: req.body.summary?.security_score ?? req.body.score,
      user: req.session.userId
    });
    await historyItem.save();
    res.status(201).json(historyItem);
  } catch (err) {
    console.error('Error saving history record:', err);
    res.status(500).json({ error: 'Failed to save scan record' });
  }
});

app.delete('/history/:analysis_id', requireAuth, async (req, res) => {
  try {
    const result = await ScanHistory.findOneAndDelete({
      analysis_id: req.params.analysis_id,
      user: req.session.userId
    });
    if (!result) return res.status(404).json({ error: 'Scan record not found or unauthorized' });
    res.json({ success: true, message: 'Scan record deleted successfully' });
  } catch (err) {
    console.error('Error deleting scan record:', err);
    res.status(500).json({ error: 'Failed to delete scan record' });
  }
});

app.delete('/history', requireAuth, async (req, res) => {
  try {
    await ScanHistory.deleteMany({ user: req.session.userId });
    res.json({ success: true, message: 'Scan history vault cleared successfully' });
  } catch (err) {
    console.error('Error clearing history:', err);
    res.status(500).json({ error: 'Failed to purge scan history' });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(413).json({ error: `Upload rejected: ${err.message}` });
  }
  if (err instanceof SyntaxError && err.status === 400) {
    return res.status(400).json({ error: 'Invalid JSON payload.' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request exceeds the upload size limit.' });
  }
  console.error('Unhandled application error:', err);
  res.status(500).json({ error: 'An unexpected error occurred on the server' });
});

app.listen(PORT, () => {
  console.log(`Express API Gateway running on http://localhost:${PORT}`);
});
