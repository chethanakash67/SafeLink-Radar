// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * URL Feature Extraction
 * Pure function - no side effects, no external dependencies
 */

import type { URLFeatures } from './types';
import { SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, SUSPICIOUS_PORTS } from './constants';

/**
 * Extract security-relevant features from a URL
 */
export function analyzeURL(urlString: string): URLFeatures {
  let parsedURL: URL;
  
  try {
    parsedURL = new URL(urlString);
  } catch (error) {
    // If URL parsing fails, return minimal features
    return createEmptyFeatures(urlString);
  }

  const hostname = parsedURL.hostname.toLowerCase();
  const protocol = parsedURL.protocol;
  const pathname = parsedURL.pathname;
  const search = parsedURL.search;
  const port = parsedURL.port;

  // Extract features
  const length = urlString.length;
  const dotCount = countOccurrences(urlString, '.');
  const subdomainCount = calculateSubdomainCount(hostname);
  const hasIPAddress = isIPAddress(hostname);
  const suspiciousKeywords = findSuspiciousKeywords(urlString.toLowerCase());
  const tld = extractTLD(hostname);
  const suspiciousTLD = isSuspiciousTLD(tld);
  const hasSuspiciousPort = isSuspiciousPort(port);
  const pathDepth = calculatePathDepth(pathname);
  const hasQueryParams = search.length > 0;
  const queryParamCount = countQueryParams(search);

  return {
    length,
    dotCount,
    subdomainCount,
    hasIPAddress,
    suspiciousKeywords,
    suspiciousTLD,
    tld,
    protocol,
    hasSuspiciousPort,
    pathDepth,
    hasQueryParams,
    queryParamCount,
  };
}

/**
 * Create empty features for invalid URLs
 */
function createEmptyFeatures(urlString: string): URLFeatures {
  return {
    length: urlString.length,
    dotCount: 0,
    subdomainCount: 0,
    hasIPAddress: false,
    suspiciousKeywords: [],
    suspiciousTLD: false,
    tld: '',
    protocol: '',
    hasSuspiciousPort: false,
    pathDepth: 0,
    hasQueryParams: false,
    queryParamCount: 0,
  };
}

/**
 * Count occurrences of a character in a string
 */
function countOccurrences(str: string, char: string): number {
  return (str.match(new RegExp(`\\${char}`, 'g')) || []).length;
}

/**
 * Calculate subdomain count
 * example.com -> 0
 * www.example.com -> 1
 * sub.www.example.com -> 2
 */
function calculateSubdomainCount(hostname: string): number {
  const parts = hostname.split('.');
  
  // Minimum valid domain has 2 parts (e.g., example.com)
  if (parts.length <= 2) {
    return 0;
  }
  
  // Subdomain count is total parts minus domain and TLD
  return parts.length - 2;
}

/**
 * Check if hostname is an IP address
 */
function isIPAddress(hostname: string): boolean {
  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  
  // IPv6 pattern (simplified)
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  
  return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname);
}

/**
 * Find suspicious keywords in URL
 */
function findSuspiciousKeywords(url: string): string[] {
  const found: string[] = [];
  
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (url.includes(keyword)) {
      found.push(keyword);
    }
  }
  
  return found;
}

/**
 * Extract TLD from hostname
 */
function extractTLD(hostname: string): string {
  const parts = hostname.split('.');
  return parts.length > 0 ? parts[parts.length - 1] : '';
}

/**
 * Check if TLD is suspicious
 */
function isSuspiciousTLD(tld: string): boolean {
  return SUSPICIOUS_TLDS.includes(tld as any);
}

/**
 * Check if port is suspicious
 */
function isSuspiciousPort(port: string): boolean {
  if (!port) return false;
  const portNum = parseInt(port, 10);
  return SUSPICIOUS_PORTS.includes(portNum as any);
}

/**
 * Calculate path depth
 * /path/to/page -> 3
 */
function calculatePathDepth(pathname: string): number {
  if (pathname === '/' || pathname === '') return 0;
  
  const segments = pathname.split('/').filter(segment => segment.length > 0);
  return segments.length;
}

/**
 * Count query parameters
 */
function countQueryParams(search: string): number {
  if (!search || search === '?') return 0;
  
  // Remove leading '?'
  const queryString = search.startsWith('?') ? search.slice(1) : search;
  
  if (queryString.length === 0) return 0;
  
  return queryString.split('&').length;
}
