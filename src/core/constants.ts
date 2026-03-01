// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Configuration constants for the risk intelligence system
 */

/**
 * Feature Weights & Normalization Constants
 * 
 * SCORING METHOD:
 * 1. Each feature produces a value (0.0 to 1.0) based on its severity
 * 2. Multiply value × weight for each feature
 * 3. Sum all products to get final score
 * 4. Convert to percentage (0-100%)
 * 
 * WEIGHT PRIORITY (importance in final calculation):
 * - IP Address: 0.30 (30% of total score if maxed)
 * - Suspicious TLD: 0.25 (25% of total score if maxed)
 * - Keywords: 0.20 (20% of total score if maxed)
 * - Suspicious Port: 0.10 (10% of total score if maxed)
 * - Subdomains: 0.08 (8% of total score if maxed)
 * - URL Length: 0.03 (3% of total score if maxed)
 * - Dot Count: 0.02 (2% of total score if maxed)
 * - Path Depth: 0.01 (1% of total score if maxed)
 * - Query Params: 0.01 (1% of total score if maxed)
 * Total = 1.0 (100%)
 */
export const FEATURE_WEIGHTS = {
  IP_ADDRESS: 0.30,        // Critical: Direct IP usage (strongest phishing signal)
  SUSPICIOUS_TLD: 0.25,    // Critical: Bad domain extensions
  SUSPICIOUS_KEYWORDS: 0.20, // High: Phishing keywords
  SUSPICIOUS_PORT: 0.10,   // Medium: Non-standard ports
  SUBDOMAIN_COUNT: 0.08,   // Medium: Subdomain obfuscation
  URL_LENGTH: 0.03,        // Low: Abnormal length
  DOT_COUNT: 0.02,         // Low: Too many dots
  PATH_DEPTH: 0.01,        // Low: Deep path structure
  QUERY_PARAMS: 0.01,      // Low: Excessive parameters
} as const;

/**
 * Normalization thresholds for converting raw values to 0-1 scale
 */
export const NORMALIZATION = {
  URL_LENGTH: {
    MIN: 20,      // URLs shorter than this = 0.0
    MAX: 200,     // URLs longer than this = 1.0
    SAFE: 50,     // Typical safe URL length
  },
  DOT_COUNT: {
    MIN: 1,       // Minimum dots (domain.com)
    MAX: 10,      // More than this = 1.0 risk
    SAFE: 2,      // Normal dot count
  },
  SUBDOMAIN_COUNT: {
    MIN: 0,       // No subdomains
    MAX: 6,       // More than this = 1.0 risk
    SAFE: 1,      // www.example.com
  },
  KEYWORD_COUNT: {
    MIN: 0,       // No keywords
    MAX: 5,       // More than this = 1.0 risk
  },
  PATH_DEPTH: {
    MIN: 0,       // Root path
    MAX: 10,      // More than this = 1.0 risk
    SAFE: 2,      // Typical depth
  },
  QUERY_PARAM_COUNT: {
    MIN: 0,       // No parameters
    MAX: 15,      // More than this = 1.0 risk
    SAFE: 3,      // Normal param count
  },
} as const;

// Risk threshold (60% = HIGH RISK)
export const RISK_THRESHOLD = 60;

// Suspicious indicators
export const SUSPICIOUS_KEYWORDS = [
  'login',
  'verify',
  'secure',
  'update',
  'account',
  'banking',
  'paypal',
  'signin',
  'password',
  'confirm',
  'authenticate',
  'validation',
  'suspended',
  'unusual',
  'activity',
] as const;

export const SUSPICIOUS_TLDS = [
  'xyz',
  'top',
  'click',
  'info',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'buzz',
  'loan',
] as const;

export const SUSPICIOUS_PORTS = [
  8080,
  3000,
  4000,
  5000,
  8000,
  8888,
] as const;

// Cache settings
export const CACHE_DURATION_MS = 60 * 60 * 1000; // 1 hour
export const MAX_CACHE_ENTRIES = 1000;

// Tooltip settings - optimized for ultrafast response
export const TOOLTIP_CONFIG = {
  maxReasons: 3,
  showDelay: 0, // Instant display
  hideDelay: 100, // Quick hide
  offsetX: 10,
  offsetY: 10,
} as const;

// Panel settings
export const PANEL_CONFIG = {
  zIndex: 2147483647, // Max z-index
  animationDuration: 200,
} as const;

// Debug mode (using Vite's import.meta.env)
export const DEBUG_MODE = false; // Disabled to reduce console spam

// Message types
export const MESSAGE_TYPES = {
  ANALYZE_URL: 'ANALYZE_URL',
  GET_CACHED_RESULT: 'GET_CACHED_RESULT',
  CLEAR_CACHE: 'CLEAR_CACHE',
  OPEN_INCOGNITO: 'OPEN_INCOGNITO',
} as const;
