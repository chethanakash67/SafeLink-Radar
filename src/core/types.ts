// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Core type definitions for the risk intelligence system
 */

export interface URLFeatures {
  length: number;
  dotCount: number;
  subdomainCount: number;
  hasIPAddress: boolean;
  suspiciousKeywords: string[];
  suspiciousTLD: boolean;
  tld: string;
  protocol: string;
  hasSuspiciousPort: boolean;
  pathDepth: number;
  hasQueryParams: boolean;
  queryParamCount: number;
}

export interface RiskAnalysisResult {
  score: number;
  reasons: string[];
  features: URLFeatures;
  timestamp: number;
}

export interface CacheEntry {
  result: RiskAnalysisResult;
  expiresAt: number;
}

export interface RuntimeMessage {
  type: 'ANALYZE_URL' | 'GET_CACHED_RESULT' | 'CLEAR_CACHE' | 'OPEN_INCOGNITO';
  payload: any;
}

export interface AnalyzeURLMessage extends RuntimeMessage {
  type: 'ANALYZE_URL';
  payload: {
    url: string;
  };
}

export interface MessageResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

export type RiskLevel = 'low' | 'medium' | 'high';

export interface TooltipConfig {
  maxReasons: number;
  showDelay: number;
  hideDelay: number;
}

export interface PanelAction {
  type: 'OPEN_NEW_TAB' | 'OPEN_INCOGNITO' | 'VIEW_DETAILS' | 'CONTINUE_ANYWAY' | 'CLOSE';
  url?: string;
}
