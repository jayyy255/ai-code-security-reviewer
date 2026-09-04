const mongoose = require('mongoose');

const ScanHistorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  analysis_id: {
    type: String,
    required: true,
    unique: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  scan_type: {
    type: String,
    enum: ['paste', 'upload', 'commit', 'batch'],
    default: 'paste'
  },
  score: {
    type: Number,
    required: true
  },
  language: {
    type: String,
    default: 'auto'
  },
  critical: {
    type: Number,
    default: 0
  },
  high: {
    type: Number,
    default: 0
  },
  medium: {
    type: Number,
    default: 0
  },
  low: {
    type: Number,
    default: 0
  },
  summary: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  findings: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  // Privacy conscious: raw code optional, not stored for full repositories by default
  code: {
    type: String,
    required: false
  },
  files_analyzed: {
    type: [String],
    default: []
  },
  files_skipped: {
    type: [String],
    default: []
  },
  scanner_status: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },
  malware_status: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  privacy_metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  repository_url: {
    type: String,
    default: null
  },
  commit_sha: {
    type: String,
    default: null
  },
  parent_sha: {
    type: String,
    default: null
  },
  changed_files: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  new_findings: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },
  fixed_findings: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },
  persistent_findings: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  }
});

module.exports = mongoose.model('ScanHistory', ScanHistorySchema);
