// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Background Service Worker
 * Handles URL analysis requests and caching
 */

import { analyzeURL } from '../core/urlAnalyzer';
import { calculateRiskAsync } from '../core/riskEngine';
import { cacheService } from '../services/cacheService';
import {
  isValidMessage,
  createSuccessResponse,
  createErrorResponse,
} from '../services/messagingService';
import { DEBUG_MODE, MESSAGE_TYPES } from '../core/constants';
import type { RuntimeMessage, RiskAnalysisResult, AnalyzeURLMessage } from '../core/types';

/**
 * Initialize background service worker
 */
function init(): void {
  if (DEBUG_MODE) {
    console.group('🚀 AI Risk Intelligence Extension - Background Worker');
    console.log('Service worker initialized');
    console.groupEnd();
  }

  // Listen for messages from content scripts
  chrome.runtime.onMessage.addListener(
    (
      message: any,
      sender: { tab?: any; url?: string; id?: string },
      sendResponse: (response: any) => void
    ) => {
      handleMessage(message, sender)
        .then(sendResponse)
        .catch((error) => {
          console.error('Message handling error:', error);
          sendResponse(createErrorResponse(error.message));
        });

      // Return true to indicate async response
      return true;
    }
  );

  // Periodic cache cleanup (every 10 minutes)
  setInterval(() => {
    const cleaned = cacheService.cleanExpired();
    if (DEBUG_MODE && cleaned > 0) {
      console.log(`🧹 Cleaned ${cleaned} expired cache entries`);
    }
  }, 10 * 60 * 1000);

  if (DEBUG_MODE) {
    console.log('✅ Background worker ready');
  }
}

/**
 * Handle incoming messages
 */
async function handleMessage(
  message: any,
  sender: { tab?: any; url?: string; id?: string }
): Promise<any> {
  // Validate message structure
  if (!isValidMessage(message)) {
    return createErrorResponse('Invalid message format');
  }

  const runtimeMessage = message as RuntimeMessage;

  if (DEBUG_MODE) {
    console.group('📥 Received message');
    console.log('Type:', runtimeMessage.type);
    console.log('From:', sender.tab?.url || 'Extension');
    console.log('Payload:', runtimeMessage.payload);
    console.groupEnd();
  }

  // Route message to appropriate handler
  switch (runtimeMessage.type) {
    case MESSAGE_TYPES.ANALYZE_URL:
      return await handleAnalyzeURL(runtimeMessage as AnalyzeURLMessage);

    case MESSAGE_TYPES.GET_CACHED_RESULT:
      return handleGetCachedResult(runtimeMessage);

    case MESSAGE_TYPES.CLEAR_CACHE:
      return handleClearCache();

    case MESSAGE_TYPES.OPEN_INCOGNITO:
      try {
        const payload = runtimeMessage.payload || {};
        const openUrl = typeof payload.url === 'string' ? payload.url : undefined;
        if (!openUrl) {
          return createErrorResponse('Invalid URL for incognito open');
        }

        // Attempt to open the URL in a new incognito window
        // Note: requires appropriate extension permissions (windows)
        chrome.windows.create({ url: openUrl, incognito: true }, (win) => {
          if (DEBUG_MODE) {
            console.log('Opened incognito window:', win?.id);
          }
        });

        return createSuccessResponse({ opened: true });
      } catch (err) {
        return createErrorResponse(err instanceof Error ? err.message : 'Failed to open incognito window');
      }

    default:
      return createErrorResponse(`Unknown message type: ${runtimeMessage.type}`);
  }
}

/**
 * Handle URL analysis request
 */
async function handleAnalyzeURL(message: AnalyzeURLMessage): Promise<any> {
  const { url } = message.payload;

  if (!url || typeof url !== 'string') {
    return createErrorResponse('Invalid URL');
  }

  try {
    // Check cache first
    const cached = cacheService.get(url);
    if (cached) {
      if (DEBUG_MODE) {
        console.log('💾 Cache hit for:', url);
      }
      return createSuccessResponse(cached);
    }

    // Analyze URL
    if (DEBUG_MODE) {
      console.group('🔍 Analyzing URL');
      console.log('URL:', url);
    }

    const features = analyzeURL(url);
    const result = await calculateRiskAsync(features, url);

    if (DEBUG_MODE) {
      console.log('Score:', result.score);
      console.log('Reasons:', result.reasons);
      console.groupEnd();
    }

    // Cache result
    cacheService.set(url, result);

    return createSuccessResponse<RiskAnalysisResult>(result);
  } catch (error) {
    console.error('Analysis error:', error);
    return createErrorResponse(
      error instanceof Error ? error.message : 'Analysis failed'
    );
  }
}

/**
 * Handle get cached result request
 */
function handleGetCachedResult(message: RuntimeMessage): any {
  const { url } = message.payload;

  if (!url || typeof url !== 'string') {
    return createErrorResponse('Invalid URL');
  }

  const cached = cacheService.get(url);
  
  if (cached) {
    return createSuccessResponse(cached);
  }

  return createErrorResponse('No cached result found');
}

/**
 * Handle clear cache request
 */
function handleClearCache(): any {
  try {
    const stats = cacheService.getStats();
    cacheService.clear();

    if (DEBUG_MODE) {
      console.log('🧹 Cache cleared:', stats);
    }

    return createSuccessResponse({ cleared: stats.size });
  } catch (error) {
    return createErrorResponse(
      error instanceof Error ? error.message : 'Failed to clear cache'
    );
  }
}

/**
 * Handle extension installation
 */
chrome.runtime.onInstalled.addListener(
  (details: { reason: string; previousVersion?: string }) => {
    if (details.reason === 'install') {
      if (DEBUG_MODE) {
        console.log('🎉 Extension installed');
      }
    } else if (details.reason === 'update') {
      if (DEBUG_MODE) {
        console.log('🔄 Extension updated');
      }
      // Clear cache on update
      cacheService.clear();
    }
  }
);

// Initialize on load
init();
