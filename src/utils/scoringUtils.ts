// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Scoring Utilities
 * Helper functions for risk score calculations and formatting
 */

import type { RiskLevel } from '../core/types';
import { RISK_THRESHOLD } from '../core/constants';

/**
 * Normalize score to 0-100 range
 */
export function normalizeScore(score: number, max: number = 100): number {
  return Math.min(100, Math.max(0, (score / max) * 100));
}

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): RiskLevel {
  if (score < 40) return 'low';
  if (score < RISK_THRESHOLD) return 'medium';
  return 'high';
}

/**
 * Get color for risk level
 */
export function getRiskColor(level: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    low: '#22c55e',    // Green
    medium: '#f59e0b', // Orange
    high: '#ef4444',   // Red
  };
  return colors[level];
}

/**
 * Get color from score
 */
export function getScoreColor(score: number): string {
  const level = getRiskLevel(score);
  return getRiskColor(level);
}

/**
 * Format score as percentage
 */
export function formatPercentage(score: number): string {
  return `${Math.round(score)}%`;
}

/**
 * Format score with label
 */
export function formatScoreWithLabel(score: number): string {
  const level = getRiskLevel(score);
  const levelText = level.charAt(0).toUpperCase() + level.slice(1);
  return `${formatPercentage(score)} (${levelText} Risk)`;
}

/**
 * Check if score is above threshold
 */
export function isHighRisk(score: number): boolean {
  return score >= RISK_THRESHOLD;
}

/**
 * Get risk description
 */
export function getRiskDescription(level: RiskLevel): string {
  const descriptions: Record<RiskLevel, string> = {
    low: 'This link appears to be relatively safe.',
    medium: 'This link has some suspicious characteristics. Proceed with caution.',
    high: 'This link shows multiple red flags and may be dangerous.',
  };
  return descriptions[level];
}

/**
 * Calculate confidence score (0-100)
 * Based on number of indicators detected
 */
export function calculateConfidence(indicatorCount: number): number {
  // More indicators = higher confidence in assessment
  const baseConfidence = 50;
  const confidencePerIndicator = 10;
  const maxConfidence = 95;
  
  const confidence = baseConfidence + (indicatorCount * confidencePerIndicator);
  return Math.min(maxConfidence, confidence);
}

/**
 * Weight a score by a factor
 */
export function applyWeight(score: number, weight: number): number {
  return score * weight;
}

/**
 * Clamp a number between min and max
 */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * Round to specified decimal places
 */
export function roundTo(value: number, decimals: number = 2): number {
  const multiplier = Math.pow(10, decimals);
  return Math.round(value * multiplier) / multiplier;
}
