// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Click Interceptor
 * Intercepts clicks on high-risk links
 */

import type { RiskAnalysisResult } from '../core/types';
import { DEBUG_MODE } from '../core/constants';
import { stopEvent } from '../utils/domUtils';
import { isHighRisk } from '../utils/scoringUtils';
import { showSafetyPanel } from './safetyPanel';
import { sendToBackground } from '../services/messagingService';

/**
 * Initialize click interception
 */
export function initClickInterceptor(): void {
  if (DEBUG_MODE) {
    console.log('Initializing click interceptor');
  }

  // Add capture-phase listener to intercept before other handlers
  document.addEventListener('click', handleClick, true);

  if (DEBUG_MODE) {
    console.log('Click interceptor initialized');
  }
}

/**
 * Stop click interception
 */
export function stopClickInterceptor(): void {
  document.removeEventListener('click', handleClick, true);
  
  if (DEBUG_MODE) {
    console.log('🛑 Click interceptor stopped');
  }
}

/**
 * Handle click events on links
 */
async function handleClick(event: MouseEvent): Promise<void> {
  // DISABLED: Don't auto-intercept link clicks
  // Users must click the tooltip card to see safety panel
  // This allows normal browsing while showing risk tooltips
  return;
}

/**
 * Find link element from click target
 */
function findLinkElement(element: HTMLElement | null): HTMLAnchorElement | null {
  if (!element) return null;

  // Check if element itself is a link
  if (element.tagName === 'A') {
    return element as HTMLAnchorElement;
  }

  // Check parents (click might be on child element like image or span)
  let current: HTMLElement | null = element;
  let depth = 0;
  const maxDepth = 5; // Prevent infinite loops

  while (current && depth < maxDepth) {
    if (current.tagName === 'A') {
      return current as HTMLAnchorElement;
    }
    current = current.parentElement;
    depth++;
  }

  return null;
}

/**
 * Check if URL should be skipped
 */
function isSpecialURL(url: string): boolean {
  // Skip javascript:, mailto:, tel:, etc.
  const specialProtocols = ['javascript:', 'mailto:', 'tel:', 'data:', 'blob:'];
  
  for (const protocol of specialProtocols) {
    if (url.startsWith(protocol)) {
      return true;
    }
  }

  // Skip anchor links
  if (url.startsWith('#')) {
    return true;
  }

  return false;
}
