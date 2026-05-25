// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Content Script Entry Point
 * Initializes all content-layer modules
 */

import { DEBUG_MODE } from '../core/constants';
import { initLinkObserver, stopLinkObserver, cleanupTooltips } from './linkObserver';
import { initClickInterceptor, stopClickInterceptor } from './clickInterceptor';

/**
 * Initialize content script
 */
function init(): void {
  if (DEBUG_MODE) {
    console.group('🚀 AI Risk Intelligence Extension - Content Script');
    console.log('Page:', window.location.href);
    console.log('Ready State:', document.readyState);
    console.groupEnd();
  }

  try {
    // Initialize observers and interceptors
    initLinkObserver();
    initClickInterceptor();

    if (DEBUG_MODE) {
      console.log('Content script initialized successfully');
    }
  } catch (error) {
    console.error('Failed to initialize content script:', error);
  }
}

/**
 * Cleanup on unload
 */
function cleanup(): void {
  if (DEBUG_MODE) {
    console.log('🧹 Cleaning up content script');
  }

  try {
    stopLinkObserver();
    stopClickInterceptor();
    cleanupTooltips();
  } catch (error) {
    console.error('Error during cleanup:', error);
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  // On some special pages (PDF viewer, chrome-extension://) the body may
  // not exist yet even when readyState is 'complete'. Defer one tick.
  if (document.body) {
    init();
  } else {
    requestAnimationFrame(init);
  }
}

// Cleanup on page unload
window.addEventListener('beforeunload', cleanup);

// Handle page navigation (SPA support)
window.addEventListener('popstate', () => {
  if (DEBUG_MODE) {
    console.log('🔄 Navigation detected, reinitializing...');
  }
  cleanup();
  init();
});
