// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Risk Scoring Engine - Weighted Feature Scoring + ML Blending
 *
 * CALCULATION METHOD:
 * 1. Rule-based score: Σ(normalized_feature × weight) × 100  (0-100)
 * 2. ML score: RandomForest malicious probability × 100       (0-100)
 * 3. Blended score: 0.45 × rule + 0.55 × ml  (when ML available)
 *                   falls back to rule-only when ML unavailable
 */

import type { URLFeatures, RiskAnalysisResult } from './types';
import { FEATURE_WEIGHTS, NORMALIZATION, RISK_THRESHOLD } from './constants';
import { runMLInference } from './mlModel';

/**
 * Blend weights — ML carries slightly more weight when available.
 * Tune these to taste after evaluating on real traffic.
 */
const ML_WEIGHT   = 0.55;
const RULE_WEIGHT = 0.45;

/**
 * Async version: runs rule-based scoring AND ML inference, then blends.
 * Use this in background.ts / messagingService where async is fine.
 */
export async function calculateRiskAsync(
  features: URLFeatures,
  url: string,
): Promise<RiskAnalysisResult> {
  const ruleResult = calculateRisk(features);
  const mlResult   = await runMLInference(features, url);

  let finalScore: number;
  const mlScore = mlResult.mlScore;

  if (mlResult.modelAvailable && mlScore >= 0) {
    const reasons = [...ruleResult.reasons];

    if (mlScore === 0) {
      // Model is confident this is benign — trust rule engine but soften it slightly
      finalScore = Math.min(100, Math.max(0, ruleResult.score * 0.75));
    } else if (mlScore === 100) {
      // Model is highly confident malicious — take the maximum of both
      finalScore = Math.max(ruleResult.score, 85);
      reasons.unshift(`🤖 ML model is highly confident this URL is malicious`);
    } else {
      // Partial ML signal — weighted blend
      finalScore = Math.min(
        100,
        Math.max(0, RULE_WEIGHT * ruleResult.score + ML_WEIGHT * mlScore),
      );
      // Only annotate if ML diverges significantly from rule score
      const delta = mlScore - ruleResult.score;
      if (delta > 25) {
        reasons.unshift(`🤖 ML model flags elevated risk (${mlScore}% confidence)`);
      }
    }

    return {
      score: Math.round(finalScore),
      ruleScore: Math.round(ruleResult.score),
      mlScore: Math.round(mlScore),
      reasons: prioritizeReasons(reasons, finalScore),
      features,
      timestamp: Date.now(),
    };
  }

  // ML unavailable — return rule-based result with mlScore = -1
  return { ...ruleResult, mlScore: -1 };
}

/**
 * Synchronous rule-based scorer (used as fallback & internally).
 * calculateRiskAsync is preferred when you need ML.
 */
export function calculateRisk(features: URLFeatures): RiskAnalysisResult {
  const reasons: string[] = [];
  let weightedSum = 0; // Sum of (value × weight) for all features

  // ============================================
  // 1. IP ADDRESS (Weight: 0.30)
  // ============================================
  const ipValue = features.hasIPAddress ? 1.0 : 0.0;
  weightedSum += ipValue * FEATURE_WEIGHTS.IP_ADDRESS;
  
  if (ipValue > 0) {
    reasons.push('🔴 CRITICAL: URL uses IP address instead of domain name');
  }

  // ============================================
  // 2. SUSPICIOUS TLD (Weight: 0.25)
  // ============================================
  const tldValue = features.suspiciousTLD ? 1.0 : 0.0;
  weightedSum += tldValue * FEATURE_WEIGHTS.SUSPICIOUS_TLD;
  
  if (tldValue > 0) {
    reasons.push(`🔴 CRITICAL: Suspicious top-level domain (.${features.tld})`);
  }

  // ============================================
  // 3. SUSPICIOUS KEYWORDS (Weight: 0.20)
  // ============================================
  const keywordValue = normalizeValue(
    features.suspiciousKeywords.length,
    NORMALIZATION.KEYWORD_COUNT.MIN,
    NORMALIZATION.KEYWORD_COUNT.MAX
  );
  weightedSum += keywordValue * FEATURE_WEIGHTS.SUSPICIOUS_KEYWORDS;
  
  if (keywordValue > 0) {
    reasons.push(`🟠 HIGH: Suspicious keywords (${features.suspiciousKeywords.length}): ${features.suspiciousKeywords.join(', ')}`);
  }

  // ============================================
  // 4. SUSPICIOUS PORT (Weight: 0.10)
  // ============================================
  const portValue = features.hasSuspiciousPort ? 1.0 : 0.0;
  weightedSum += portValue * FEATURE_WEIGHTS.SUSPICIOUS_PORT;
  
  if (portValue > 0) {
    reasons.push('🟡 MEDIUM: Non-standard port number detected');
  }

  // ============================================
  // 5. SUBDOMAIN COUNT (Weight: 0.08)
  // ============================================
  const subdomainValue = normalizeValue(
    features.subdomainCount,
    NORMALIZATION.SUBDOMAIN_COUNT.MIN,
    NORMALIZATION.SUBDOMAIN_COUNT.MAX
  );
  weightedSum += subdomainValue * FEATURE_WEIGHTS.SUBDOMAIN_COUNT;
  
  if (subdomainValue > 0.3) { // Only report if significant
    reasons.push(`🟡 MEDIUM: Multiple subdomains (${features.subdomainCount})`);
  }

  // ============================================
  // 6. URL LENGTH (Weight: 0.03)
  // ============================================
  const lengthValue = normalizeValue(
    features.length,
    NORMALIZATION.URL_LENGTH.SAFE,
    NORMALIZATION.URL_LENGTH.MAX
  );
  weightedSum += lengthValue * FEATURE_WEIGHTS.URL_LENGTH;
  
  if (lengthValue > 0.5) { // Only report if notably long
    reasons.push(`🔵 Low: Long URL (${features.length} characters)`);
  }

  // ============================================
  // 7. DOT COUNT (Weight: 0.02)
  // ============================================
  const dotValue = normalizeValue(
    features.dotCount,
    NORMALIZATION.DOT_COUNT.SAFE,
    NORMALIZATION.DOT_COUNT.MAX
  );
  weightedSum += dotValue * FEATURE_WEIGHTS.DOT_COUNT;
  
  if (dotValue > 0.5) {
    reasons.push(`🔵 Low: High dot count (${features.dotCount})`);
  }

  // ============================================
  // 8. PATH DEPTH (Weight: 0.01)
  // ============================================
  const pathValue = normalizeValue(
    features.pathDepth,
    NORMALIZATION.PATH_DEPTH.SAFE,
    NORMALIZATION.PATH_DEPTH.MAX
  );
  weightedSum += pathValue * FEATURE_WEIGHTS.PATH_DEPTH;
  
  if (pathValue > 0.5) {
    reasons.push(`🔵 Low: Deep path structure (${features.pathDepth} levels)`);
  }

  // ============================================
  // 9. QUERY PARAMETERS (Weight: 0.01)
  // ============================================
  const queryValue = normalizeValue(
    features.queryParamCount,
    NORMALIZATION.QUERY_PARAM_COUNT.SAFE,
    NORMALIZATION.QUERY_PARAM_COUNT.MAX
  );
  weightedSum += queryValue * FEATURE_WEIGHTS.QUERY_PARAMS;
  
  if (queryValue > 0.5) {
    reasons.push(`🔵 Low: Many query parameters (${features.queryParamCount})`);
  }

  // ============================================
  // Convert weighted sum to percentage (0-100)
  // ============================================
  const finalScore = Math.min(100, Math.max(0, weightedSum * 100));

  return {
    score: finalScore,
    ruleScore: finalScore,
    mlScore: -1,
    reasons: prioritizeReasons(reasons, finalScore),
    features,
    timestamp: Date.now(),
  };
}

/**
 * Normalize a value to 0.0-1.0 scale
 * @param value - Raw feature value
 * @param min - Minimum threshold (below this = 0.0)
 * @param max - Maximum threshold (above this = 1.0)
 * @returns Normalized value between 0.0 and 1.0
 */
function normalizeValue(value: number, min: number, max: number): number {
  if (value <= min) return 0.0;
  if (value >= max) return 1.0;
  return (value - min) / (max - min);
}

/**
 * Prioritize and limit reasons based on score
 */
function prioritizeReasons(reasons: string[], score: number): string[] {
  // For low scores, show fewer reasons
  if (score < RISK_THRESHOLD) {
    return reasons.slice(0, 2);
  }
  
  // For high scores, show more reasons (max 5)
  return reasons.slice(0, 5);
}

/**
 * Determine risk level based on score
 */
export function getRiskLevel(score: number): 'low' | 'medium' | 'high' {
  if (score < 40) return 'low';
  if (score < RISK_THRESHOLD) return 'medium';
  return 'high';
}

/**
 * Format score for display
 */
export function formatScore(score: number): string {
  return `${Math.round(score)}%`;
}
