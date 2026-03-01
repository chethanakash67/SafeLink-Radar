// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Messaging Service
 * Handles chrome.runtime message passing with type safety
 */

import type { RuntimeMessage, MessageResponse } from '../core/types';
import { DEBUG_MODE } from '../core/constants';

/**
 * Send message to background service worker
 */
export async function sendToBackground<T = any>(
  message: RuntimeMessage
): Promise<MessageResponse<T>> {
  try {
    if (DEBUG_MODE) {
      console.group('📤 Sending message to background');
      console.log('Type:', message.type);
      console.log('Payload:', message.payload);
      console.groupEnd();
    }

    const response = await chrome.runtime.sendMessage(message);

    if (DEBUG_MODE) {
      console.group('📥 Received response from background');
      console.log('Success:', response.success);
      console.log('Data:', response.data);
      console.groupEnd();
    }

    return response;
  } catch (error) {
    if (DEBUG_MODE) {
      console.error('❌ Messaging error:', error);
    }

    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown messaging error',
    };
  }
}

/**
 * Send message to content script
 */
export async function sendToContent<T = any>(
  tabId: number,
  message: RuntimeMessage
): Promise<MessageResponse<T>> {
  try {
    if (DEBUG_MODE) {
      console.group('📤 Sending message to content');
      console.log('Tab ID:', tabId);
      console.log('Type:', message.type);
      console.log('Payload:', message.payload);
      console.groupEnd();
    }

    const response = await chrome.tabs.sendMessage(tabId, message);

    return response;
  } catch (error) {
    if (DEBUG_MODE) {
      console.error('❌ Messaging error:', error);
    }

    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown messaging error',
    };
  }
}

/**
 * Validate message structure
 */
export function isValidMessage(message: any): message is RuntimeMessage {
  return (
    message &&
    typeof message === 'object' &&
    'type' in message &&
    'payload' in message &&
    typeof message.type === 'string'
  );
}

/**
 * Create success response
 */
export function createSuccessResponse<T>(data: T): MessageResponse<T> {
  return {
    success: true,
    data,
  };
}

/**
 * Create error response
 */
export function createErrorResponse(error: string): MessageResponse {
  return {
    success: false,
    error,
  };
}
