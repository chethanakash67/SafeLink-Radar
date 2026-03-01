// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Cache Service
 * Manages in-memory caching of URL analysis results
 */

import type { RiskAnalysisResult, CacheEntry } from '../core/types';
import { CACHE_DURATION_MS, MAX_CACHE_ENTRIES } from '../core/constants';

class CacheService {
  private cache: Map<string, CacheEntry>;

  constructor() {
    this.cache = new Map();
  }

  /**
   * Store analysis result in cache
   */
  set(url: string, result: RiskAnalysisResult): void {
    // Limit cache size
    if (this.cache.size >= MAX_CACHE_ENTRIES) {
      this.evictOldest();
    }

    const entry: CacheEntry = {
      result,
      expiresAt: Date.now() + CACHE_DURATION_MS,
    };

    this.cache.set(url, entry);
  }

  /**
   * Retrieve cached result if available and not expired
   */
  get(url: string): RiskAnalysisResult | null {
    const entry = this.cache.get(url);

    if (!entry) {
      return null;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(url);
      return null;
    }

    return entry.result;
  }

  /**
   * Check if URL is cached and valid
   */
  has(url: string): boolean {
    return this.get(url) !== null;
  }

  /**
   * Clear entire cache
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Remove a specific URL from cache
   */
  delete(url: string): boolean {
    return this.cache.delete(url);
  }

  /**
   * Get cache statistics
   */
  getStats(): { size: number; maxSize: number } {
    return {
      size: this.cache.size,
      maxSize: MAX_CACHE_ENTRIES,
    };
  }

  /**
   * Evict oldest entry when cache is full
   */
  private evictOldest(): void {
    const firstKey = this.cache.keys().next().value;
    if (firstKey) {
      this.cache.delete(firstKey);
    }
  }

  /**
   * Clean expired entries (for periodic maintenance)
   */
  cleanExpired(): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [url, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(url);
        cleaned++;
      }
    }

    return cleaned;
  }
}

// Export singleton instance
export const cacheService = new CacheService();
