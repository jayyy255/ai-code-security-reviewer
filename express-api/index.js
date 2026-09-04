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
const path = require('path');
const fs = require('fs');

const User = require('./models/User');
const ScanHistory = require('./models/ScanHistory');

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ai-security-reviewer';
const FASTAPI_URL = process.env.FASTAPI_URL || 'http://localhost:8000';
const FRONTEND_URL = process.env.FRONTEND_URL || true;

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB successfully'))
  .catch(err => console.warn('MongoDB connection notice (will run in ephemeral/memory mode if unconfigured):', err.message));

// Multer memory storage for safe file intake (max 50MB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// Middleware
app.use(morgan('dev'));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Session Configuration
try {
  app.use(session({
    name: 'reviewer.sid',
    secret: process.env.SESSION_SECRET || 'reviewer-session-secret-key-1337',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      collectionName: 'sessions',
      ttl: 14 * 24 * 60 * 60
    }),
    cookie: {
      maxAge: 14 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    }
  }));
} catch (e) {
  console.warn('Session store fallback initialization notice.');
}

// Auth Middleware
const requireAuth = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
};

// Helper: Save to History if logged in and not ephemeral
async function persistScanResult(userId, scanResult, originalCode = null, ephemeral = false) {
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
      // Privacy-conscious: only store code snippet if explicitly small / paste mode
      code: scanResult.scan_type === 'paste' ? originalCode : undefined,
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
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existingUser = await User.findOne({ $or: [{ username }, { email: email.toLowerCase() }] });
    if (existingUser) {
      return res.status(400).json({ error: existingUser.username === username ? 'Username is taken' : 'Email registered' });
    }

    const user = new User({ username, email, password });
    await user.save();
    req.session.userId = user._id;

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
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = await User.findOne({ $or: [{ username }, { email: username.toLowerCase() }] });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    req.session.userId = user._id;
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
    await persistScanResult(req.session?.userId, scanResult, code, Boolean(ephemeral));
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
      filesPayload = req.files.map(f => ({
        filename: f.originalname,
        content: f.buffer.toString('utf-8')
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
    await persistScanResult(req.session?.userId, scanResult, null, ephemeral);
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
    await persistScanResult(req.session?.userId, scanResult, null, Boolean(ephemeral));
    res.json(scanResult);
  } catch (err) {
    console.error('Commit analysis proxy error:', err.message);
    if (err.response) return res.status(err.response.status).json(err.response.data);
    res.status(502).json({ error: 'Failed to communicate with FastAPI analysis service for commit scan.' });
  }
});

// GET /api/v1/scans/:scanId
app.get('/api/v1/scans/:scanId', async (req, res) => {
  try {
    const record = await ScanHistory.findOne({ analysis_id: req.params.scanId });
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
    const existing = await ScanHistory.findOne({ analysis_id: req.body.analysis_id });
    if (existing) return res.json(existing);

    const historyItem = new ScanHistory({
      ...req.body,
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
  console.error('Unhandled application error:', err);
  res.status(500).json({ error: 'An unexpected error occurred on the server' });
});

app.listen(PORT, () => {
  console.log(`Express API Gateway running on http://localhost:${PORT}`);
});
