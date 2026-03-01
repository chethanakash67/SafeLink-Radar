// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Global type declarations for Chrome Extension APIs and Vite
 * This file helps TypeScript understand globals before npm install
 */

// Extend global ImportMeta for Vite
declare global {
  interface ImportMeta {
    readonly env: {
      readonly MODE: string;
      readonly DEV: boolean;
      readonly PROD: boolean;
      readonly SSR: boolean;
    };
  }

  // Minimal Chrome API types (will be replaced by @types/chrome after npm install)
  const chrome: {
    runtime: {
      sendMessage(message: any): Promise<any>;
      sendMessage(extensionId: string, message: any): Promise<any>;
      onMessage: {
        addListener(
          callback: (
            message: any,
            sender: {
              tab?: any;
              frameId?: number;
              id?: string;
              url?: string;
              origin?: string;
            },
            sendResponse: (response: any) => void
          ) => boolean | void
        ): void;
      };
      onInstalled: {
        addListener(
          callback: (details: { reason: string; previousVersion?: string; id?: string }) => void
        ): void;
      };
    };
    tabs: {
      sendMessage(tabId: number, message: any): Promise<any>;
    };
  };
}

export {};
