require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo').MongoStore;
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const axios = require('axios');
const User = require('./models/User');
const ScanHistory = require('./models/ScanHistory');

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const FASTAPI_URL = process.env.FASTAPI_URL || 'http://localhost:8000';
const FRONTEND_URL = process.env.FRONTEND_URL || true;

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(morgan('dev'));
app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Session Configuration
app.use(session({
  name: 'reviewer.sid',
  secret: process.env.SESSION_SECRET || 'reviewer-session-secret-key-1337',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60 // 14 days
  }),
  cookie: {
    maxAge: 14 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Secure cookies in production over HTTPS
    sameSite: 'lax'
  }
}));

// Auth Middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
};

// --- AUTH ROUTES ---

// Check session / get current user
app.get('/auth/me', async (req, res) => {
  try {
    if (!req.session.userId) {
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

// Signup
app.post('/auth/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email: email.toLowerCase() }] 
    });

    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).json({ error: 'Username is already taken' });
      }
      return res.status(400).json({ error: 'Email is already registered' });
    }

    // Create user
    const user = new User({ username, email, password });
    await user.save();

    // Log user in
    req.session.userId = user._id;

    const userObj = user.toObject();
    delete userObj.password;

    res.status(201).json({ user: userObj });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({
      $or: [
        { username: username },
        { email: username.toLowerCase() }
      ]
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Set session
    req.session.userId = user._id;

    const userObj = user.toObject();
    delete userObj.password;

    res.json({ user: userObj });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Logout
app.post('/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Failed to log out' });
    }
    res.clearCookie('reviewer.sid');
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

// --- SCAN PROXY ROUTE ---

// Proxy scan requests to FastAPI
app.post('/analyze', async (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code || !language) {
      return res.status(400).json({ error: 'Code and language are required' });
    }

    // Call FastAPI service
    const response = await axios.post(`${FASTAPI_URL}/analyze/`, {
      code,
      language
    });

    const scanResult = response.data;

    // If user is logged in, automatically save scan result to history
    if (req.session.userId) {
      const historyItem = new ScanHistory({
        user: req.session.userId,
        analysis_id: scanResult.analysis_id,
        score: scanResult.summary.security_score,
        language: language,
        critical: scanResult.summary.critical,
        high: scanResult.summary.high,
        medium: scanResult.summary.medium,
        low: scanResult.summary.low,
        summary: scanResult.summary,
        findings: scanResult.findings,
        code: code
      });
      await historyItem.save();
    }

    res.json(scanResult);
  } catch (err) {
    console.error('Code analysis service error:', err.message);
    if (err.response) {
      return res.status(err.response.status).json(err.response.data);
    }
    res.status(502).json({ error: 'Failed to communicate with FastAPI scanner service.' });
  }
});

// --- HISTORY ROUTES (USER SPECIFIC) ---

// Get all history for logged-in user
app.get('/history', requireAuth, async (req, res) => {
  try {
    const history = await ScanHistory.find({ user: req.session.userId })
      .sort({ timestamp: -1 });
    res.json(history);
  } catch (err) {
    console.error('Error fetching history:', err);
    res.status(500).json({ error: 'Internal server error fetching scan vault' });
  }
});

// Save scan result to history (e.g. sync from guest local storage)
app.post('/history', requireAuth, async (req, res) => {
  try {
    const {
      analysis_id,
      timestamp,
      score,
      language,
      critical,
      high,
      medium,
      low,
      summary,
      findings,
      code
    } = req.body;

    if (!analysis_id || !code) {
      return res.status(400).json({ error: 'Invalid scan record details' });
    }

    const existing = await ScanHistory.findOne({ analysis_id });
    if (existing) {
      return res.json(existing);
    }

    const historyItem = new ScanHistory({
      user: req.session.userId,
      analysis_id,
      timestamp: timestamp || new Date(),
      score,
      language,
      critical: critical || 0,
      high: high || 0,
      medium: medium || 0,
      low: low || 0,
      summary,
      findings,
      code
    });

    await historyItem.save();
    res.status(201).json(historyItem);
  } catch (err) {
    console.error('Error saving history record:', err);
    res.status(500).json({ error: 'Failed to save scan record' });
  }
});

// Delete specific scan record from user's history
app.delete('/history/:analysis_id', requireAuth, async (req, res) => {
  try {
    const result = await ScanHistory.findOneAndDelete({
      analysis_id: req.params.analysis_id,
      user: req.session.userId
    });

    if (!result) {
      return res.status(404).json({ error: 'Scan record not found or unauthorized' });
    }

    res.json({ success: true, message: 'Scan record deleted successfully' });
  } catch (err) {
    console.error('Error deleting scan record:', err);
    res.status(500).json({ error: 'Failed to delete scan record' });
  }
});

// Clear all history for the logged-in user
app.delete('/history', requireAuth, async (req, res) => {
  try {
    await ScanHistory.deleteMany({ user: req.session.userId });
    res.json({ success: true, message: 'Scan history vault cleared successfully' });
  } catch (err) {
    console.error('Error clearing history:', err);
    res.status(500).json({ error: 'Failed to purge scan history' });
  }
});

// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
  console.error('Unhandled application error:', err);
  res.status(500).json({ error: 'An unexpected error occurred on the server' });
});

app.listen(PORT, () => {
  console.log(`Express API Gateway running on http://localhost:${PORT}`);
});
