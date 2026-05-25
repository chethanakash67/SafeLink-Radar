// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * ML Model Inference — onnxruntime-web
 *
 * Loads public/model.onnx (a RandomForest trained in Python) and runs
 * inference to get a malicious-probability score (0.0 – 1.0).
 *
 * Feature vector order MUST match ml/features.py  FEATURE_NAMES:
 *   0  url_length
 *   1  dot_count
 *   2  subdomain_count
 *   3  has_ip_address
 *   4  suspicious_keyword_count
 *   5  suspicious_tld
 *   6  has_suspicious_port
 *   7  path_depth
 *   8  query_param_count
 *   9  https
 *  10  digit_ratio
 *  11  hyphen_count
 *  12  at_symbol
 *  13  double_slash_in_path
 *  14  brand_squatting
 *  15  entropy
 */

import * as ort from 'onnxruntime-web';
import type { URLFeatures } from './types';

// ─── Constants ──────────────────────────────────────────────────────────────

const MODEL_PATH = chrome.runtime.getURL('model.onnx');

const KNOWN_BRANDS = new Set([
  'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
  'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox',
  'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
]);

// ─── Singleton session ───────────────────────────────────────────────────────

let _session: ort.InferenceSession | null = null;
let _loading: Promise<ort.InferenceSession> | null = null;

async function getSession(): Promise<ort.InferenceSession> {
  if (_session) return _session;
  if (_loading) return _loading;

  _loading = ort.InferenceSession.create(MODEL_PATH, {
    executionProviders: ['wasm'],
    graphOptimizationLevel: 'all',
  }).then((sess: ort.InferenceSession) => {
    _session = sess;
    return sess;
  });

  return _loading;
}

// ─── Extra feature helpers (not in urlAnalyzer.ts) ──────────────────────────

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  const n = s.length;
  return -Object.values(freq).reduce((acc, f) => {
    const p = f / n;
    return acc + p * Math.log2(p);
  }, 0);
}

function digitRatio(hostname: string): number {
  if (!hostname) return 0;
  const digits = hostname.split('').filter((c) => c >= '0' && c <= '9').length;
  return digits / hostname.length;
}

function isBrandSquatting(hostname: string): boolean {
  const parts = hostname.split('.');
  if (parts.length < 2) return false;
  const registered = parts[parts.length - 2].toLowerCase();
  // Exact match on registered domain → likely legitimate
  if (KNOWN_BRANDS.has(registered)) return false;
  // Brand keyword elsewhere in hostname → squatting signal
  const full = hostname.toLowerCase();
  for (const brand of KNOWN_BRANDS) {
    if (full.includes(brand)) return true;
  }
  return false;
}

// ─── Feature vector builder ──────────────────────────────────────────────────

/**
 * Build the 16-element Float32Array that the ONNX model expects.
 * The url string is needed for a few features that URLFeatures doesn't store.
 */
export function buildFeatureVector(features: URLFeatures, url: string): Float32Array {
  let parsedHostname = '';
  let isHttps = 0;
  let hasAtSymbol = 0;
  let hasDoubleSlashInPath = 0;

  try {
    const parsed = new URL(url);
    parsedHostname = parsed.hostname.toLowerCase();
    isHttps = parsed.protocol === 'https:' ? 1 : 0;
    hasAtSymbol = url.includes('@') ? 1 : 0;
    hasDoubleSlashInPath = parsed.pathname.includes('//') ? 1 : 0;
  } catch {
    // keep defaults
  }

  return new Float32Array([
    features.length,                                   //  0 url_length
    features.dotCount,                                 //  1 dot_count
    features.subdomainCount,                           //  2 subdomain_count
    features.hasIPAddress ? 1 : 0,                     //  3 has_ip_address
    features.suspiciousKeywords.length,                //  4 suspicious_keyword_count
    features.suspiciousTLD ? 1 : 0,                    //  5 suspicious_tld
    features.hasSuspiciousPort ? 1 : 0,                //  6 has_suspicious_port
    features.pathDepth,                                //  7 path_depth
    features.queryParamCount,                          //  8 query_param_count
    isHttps,                                           //  9 https
    digitRatio(parsedHostname),                        // 10 digit_ratio
    (parsedHostname.match(/-/g) ?? []).length,         // 11 hyphen_count
    hasAtSymbol,                                       // 12 at_symbol
    hasDoubleSlashInPath,                              // 13 double_slash_in_path
    isBrandSquatting(parsedHostname) ? 1 : 0,          // 14 brand_squatting
    shannonEntropy(parsedHostname),                    // 15 entropy
  ]);
}

// ─── Public inference API ────────────────────────────────────────────────────

export interface MLResult {
  /** Raw probability of being malicious (0.0 – 1.0) */
  maliciousProb: number;
  /**
   * Calibrated score (0–100) used for blending.
   * Probabilities below BENIGN_CEILING are mapped to 0 (safe).
   * Probabilities above MALICIOUS_FLOOR are mapped to 100 (dangerous).
   * Everything in between is linearly scaled.
   *
   * Calibration rationale: the RandomForest trained on this dataset
   * compresses all probabilities into roughly 0.40–0.90 because many
   * structural features (dot count, subdomain count) appear in both
   * legitimate deep-path URLs and phishing URLs.  We therefore only
   * trust the model when it is highly confident.
   */
  mlScore: number;
  /** Whether the model session loaded successfully */
  modelAvailable: boolean;
}

/**
 * Probability calibration thresholds.
 * Below BENIGN_CEILING  → treated as 0  (definitely safe)
 * Above MALICIOUS_FLOOR → treated as 100 (definitely malicious)
 * Between              → linearly mapped to 0-100
 */
const BENIGN_CEILING   = 0.70; // below this → model says benign
const MALICIOUS_FLOOR  = 0.90; // above this → model is highly confident malicious

function calibrate(prob: number): number {
  if (prob <= BENIGN_CEILING)  return 0;
  if (prob >= MALICIOUS_FLOOR) return 100;
  return Math.round(
    ((prob - BENIGN_CEILING) / (MALICIOUS_FLOOR - BENIGN_CEILING)) * 100,
  );
}

/**
 * Run the ONNX model and return a calibrated malicious score.
 * Falls back gracefully (mlScore = -1) if the model is unavailable.
 */
export async function runMLInference(
  features: URLFeatures,
  url: string,
): Promise<MLResult> {
  try {
    const session = await getSession();

    const featureVector = buildFeatureVector(features, url);
    const tensor = new ort.Tensor('float32', featureVector, [1, featureVector.length]);

    const inputName = session.inputNames[0];
    const feeds: Record<string, ort.Tensor> = { [inputName]: tensor };
    const results = await session.run(feeds);

    // ONNX RandomForest outputs: output_label (int64) + output_probability (map/float)
    // skl2onnx with zipmap:false → probabilities tensor shape [1, 2]
    const probOutput = results['output_probability'] ?? results[session.outputNames[1]];

    let maliciousProb = 0.5; // fallback
    if (probOutput?.data) {
      // Float32Array: [benign_prob, malicious_prob]
      maliciousProb = (probOutput.data as Float32Array)[1];
    }

    return {
      maliciousProb,
      mlScore: calibrate(maliciousProb),
      modelAvailable: true,
    };
  } catch (err) {
    // Model not loaded (first run, wasm not available, etc.)
    console.warn('[SafeLink-Radar] ML model unavailable, using rule-based only:', err);
    return { maliciousProb: 0, mlScore: -1, modelAvailable: false };
  }
}
