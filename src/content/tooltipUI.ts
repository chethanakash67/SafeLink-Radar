// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Tooltip UI Component
 * Displays risk information on hover
 */

import type { RiskAnalysisResult } from '../core/types';
import { TOOLTIP_CONFIG } from '../core/constants';
import { createElement, removeElement } from '../utils/domUtils';
import { formatPercentage, getRiskLevel } from '../utils/scoringUtils';

const TOOLTIP_ID = 'ai-risk-tooltip';

let currentTooltip: HTMLElement | null = null;
let showTimeout: number | null = null;
let hideTimeout: number | null = null;

// Console logging controls
let logDebounceTimer: number | null = null;
let lastLogTime: number = 0;
let logCount: number = 0;
const LOG_DEBOUNCE_MS = 300; // Wait 300ms before logging (filters quick hovers)
const LOG_RATE_LIMIT_MS = 2000; // Max 1 log per 2 seconds

// Track how many times each URL has been logged
const urlLogTracker = new Map<string, number>();

function getConsolePalette(): {
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  headerBg: string;
  headerBorder: string;
  divider: string;
} {
  const isDarkTheme = window.matchMedia('(prefers-color-scheme: dark)').matches;

  if (isDarkTheme) {
    return {
      textPrimary: '#f4f4f5',
      textSecondary: '#d4d4d8',
      textMuted: '#a1a1aa',
      headerBg: '#111111',
      headerBorder: '#3f3f46',
      divider: '#3f3f46',
    };
  }

  return {
    textPrimary: '#111111',
    textSecondary: '#2e2e33',
    textMuted: '#52525b',
    headerBg: '#f4f4f5',
    headerBorder: '#d4d4d8',
    divider: '#71717a',
  };
}

/**
 * Show tooltip near target element
 */
export function showTooltip(
  _targetElement: HTMLElement,
  result: RiskAnalysisResult,
  mouseX: number,
  mouseY: number,
  url: string
): void {
  // Clear all timeouts
  if (hideTimeout) {
    clearTimeout(hideTimeout);
    hideTimeout = null;
  }
  if (showTimeout) {
    clearTimeout(showTimeout);
    showTimeout = null;
  }

  // Remove old tooltip immediately when switching links
  if (currentTooltip) {
    removeElement(currentTooltip);
    currentTooltip = null;
  }

  // Debounced console logging (300ms delay + rate limiting + duplicate tracking)
  scheduleConsoleLog(url, result);

  // Show immediately - no delay
  currentTooltip = createTooltipElement(result);
  (document.body ?? document.documentElement).appendChild(currentTooltip);
  positionTooltip(currentTooltip, mouseX, mouseY);
}

/**
 * Hide tooltip
 */
export function hideTooltip(): void {
  // Clear any pending show
  if (showTimeout) {
    clearTimeout(showTimeout);
    showTimeout = null;
  }

  // Clear any pending console log (user moved away before debounce completed)
  if (logDebounceTimer) {
    clearTimeout(logDebounceTimer);
    logDebounceTimer = null;
  }

  // Hide immediately - no delay
  if (currentTooltip) {
    removeElement(currentTooltip);
    currentTooltip = null;
  }
}

/**
 * Force immediate tooltip removal
 */
export function removeTooltip(): void {
  if (showTimeout) {
    clearTimeout(showTimeout);
    showTimeout = null;
  }
  if (hideTimeout) {
    clearTimeout(hideTimeout);
    hideTimeout = null;
  }
  if (logDebounceTimer) {
    clearTimeout(logDebounceTimer);
    logDebounceTimer = null;
  }
  if (currentTooltip) {
    removeElement(currentTooltip);
    currentTooltip = null;
  }
}

/**
 * Create simple tooltip with just score (clickable)
 */
function createTooltipElement(result: RiskAnalysisResult): HTMLElement {
  const level = getRiskLevel(result.score);
  const monochromeScoreColor: Record<'low' | 'medium' | 'high', string> = {
    low: '#a1a1aa',
    medium: '#d4d4d8',
    high: '#f4f4f5',
  };

  const tooltip = createElement('div', {
    attributes: {
      id: TOOLTIP_ID,
      role: 'button',
      'aria-label': 'Click to view details',
      tabindex: '0',
    },
    classes: ['ai-risk-tooltip', `risk-${level}`],
  });

  // Large score display
  const scoreLabel = createElement('div', {
    classes: ['tooltip-score'],
    text: formatPercentage(result.score),
  });
  scoreLabel.style.color = monochromeScoreColor[level];
  scoreLabel.style.fontSize = '20px';
  scoreLabel.style.fontWeight = 'bold';

  const levelLabel = createElement('div', {
    classes: ['tooltip-level'],
    text: `${level.toUpperCase()} RISK`,
  });
  levelLabel.style.fontSize = '9px';
  levelLabel.style.marginTop = '2px';

  tooltip.appendChild(scoreLabel);
  tooltip.appendChild(levelLabel);

  // Make tooltip clickable - show safety panel on click  
  tooltip.style.cursor = 'pointer';
  tooltip.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    // Dispatch custom event to trigger safety panel
    const event = new CustomEvent('ai-show-safety-panel', { 
      detail: { result },
      bubbles: true
    });
    document.dispatchEvent(event);
  });

  return tooltip;
}

/**
 * Position tooltip near mouse cursor
 */
function positionTooltip(tooltip: HTMLElement, mouseX: number, mouseY: number): void {
  const offsetX = TOOLTIP_CONFIG.offsetX;
  const offsetY = TOOLTIP_CONFIG.offsetY;

  let left = mouseX + offsetX;
  let top = mouseY + offsetY;

  // Ensure tooltip stays within viewport
  const tooltipRect = tooltip.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;

  // Adjust horizontal position
  if (left + tooltipRect.width > viewportWidth) {
    left = mouseX - tooltipRect.width - offsetX;
  }

  // Adjust vertical position
  if (top + tooltipRect.height > viewportHeight) {
    top = mouseY - tooltipRect.height - offsetY;
  }

  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
}

/**
 * Schedule console log with debouncing, rate limiting, and duplicate tracking
 */
function scheduleConsoleLog(url: string, result: RiskAnalysisResult): void {
  // Clear any pending log
  if (logDebounceTimer) {
    clearTimeout(logDebounceTimer);
    logDebounceTimer = null;
  }

  // Debounce: Wait 300ms before logging (filters accidental quick hovers)
  logDebounceTimer = window.setTimeout(() => {
    const now = Date.now();
    
    // Check how many times this URL has been logged
    const loggedCount = urlLogTracker.get(url) || 0;
    
    // 1st time: Full log (if rate limit allows)
    // 2nd time: Brief "already analyzed" message
    // 3rd+ time: No log at all
    if (loggedCount >= 2) {
      // 3rd+ time: Silent (no log)
      logDebounceTimer = null;
      return;
    }
    
    // Rate limit: Only log if 2+ seconds since last log
    if (now - lastLogTime >= LOG_RATE_LIMIT_MS) {
      if (loggedCount === 0) {
        // First time: Full detailed log
        logRiskDetailsToConsole(url, result);
        urlLogTracker.set(url, 1);
      } else if (loggedCount === 1) {
        // Second time: Brief "already analyzed" message
        logAlreadyAnalyzed(url, result);
        urlLogTracker.set(url, 2);
      }
      lastLogTime = now;
    }
    
    logDebounceTimer = null;
  }, LOG_DEBOUNCE_MS);
}

/**
 * Log brief "already analyzed" message for 2nd hover
 */
function logAlreadyAnalyzed(url: string, result: RiskAnalysisResult): void {
  const level = getRiskLevel(result.score);
  const palette = getConsolePalette();
  
  console.log(
    `%cLink already analyzed: ${formatPercentage(result.score)} ${level.toUpperCase()} RISK`,
    `color: ${palette.textMuted}; font-size: 12px; font-style: italic;`
  );
  console.log(
    `%c  ${url.length > 100 ? url.substring(0, 100) + '...' : url}`,
    `color: ${palette.textMuted}; font-size: 11px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;`
  );
}

/**
 * Log detailed risk analysis to console (collapsed by default) - First hover only
 */
function logRiskDetailsToConsole(url: string, result: RiskAnalysisResult): void {
  logCount++;

  const level = getRiskLevel(result.score);
  const timestamp = new Date().toLocaleTimeString();
  const palette = getConsolePalette();
  
  // Style for console logging
  const headerStyle = `
    background: ${palette.headerBg};
    color: ${palette.textPrimary};
    font-size: 13px;
    font-weight: 700;
    padding: 6px 10px;
    border: 1px solid ${palette.headerBorder};
    border-radius: 0;
  `;
  
  const reasonStyle = `
    color: ${palette.textMuted};
    font-size: 12px;
    padding: 2px 0;
  `;

  // Use groupCollapsed - user can expand if interested
  console.groupCollapsed(
    `%cLink #${logCount} | ${formatPercentage(result.score)} ${level.toUpperCase()} RISK | ${timestamp}`,
    headerStyle
  );
  
  // URL preview
  console.log('%c--------------------------------', `color: ${palette.divider}`);
  console.log('%cURL', `color: ${palette.textPrimary}; font-weight: 700; font-size: 12px`);
  console.log(`%c  ${url}`, `color: ${palette.textMuted}; font-size: 11px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;`);
  
  // Simple explanation section
  console.log('%c--------------------------------', `color: ${palette.divider}`);
  console.log('%cRisk Summary', `color: ${palette.textPrimary}; font-weight: 700; font-size: 12px`);
  
  const explanations = getSimpleExplanations(result);
  if (explanations.length > 0) {
    explanations.forEach(exp => {
      console.log(`%c  ${exp.title}`, `color: ${palette.textSecondary}; font-weight: 600; font-size: 12px;`);
      console.log(`%c     ${exp.explanation}`, `color: ${palette.textMuted}; font-size: 11px;`);
    });
  } else {
    console.log(`%c  No major threat indicators detected.`, `color: ${palette.textSecondary}; font-size: 12px;`);
  }
  
  // Technical reasons (for developers/advanced users)
  if (result.reasons && result.reasons.length > 0) {
    console.log('%c--------------------------------', `color: ${palette.divider}`);
    console.log('%cTechnical Risk Indicators', `color: ${palette.textPrimary}; font-weight: 700; font-size: 12px`);
    result.reasons.forEach((reason, index) => {
      console.log(`%c  ${index + 1}. ${reason}`, reasonStyle);
    });
  }
  
  // Feature breakdown
  console.log('%c--------------------------------', `color: ${palette.divider}`);
  console.log('%cFeature Analysis', `color: ${palette.textPrimary}; font-weight: 700; font-size: 12px`);
  console.log(`%c  URL Length: ${result.features.length} chars`, `color: ${palette.textSecondary}`);
  console.log(`%c  Subdomains: ${result.features.subdomainCount}`, `color: ${palette.textSecondary}`);
  console.log(`%c  Dot Count: ${result.features.dotCount}`, `color: ${palette.textSecondary}`);
  console.log(`%c  Path Depth: ${result.features.pathDepth}`, `color: ${palette.textSecondary}`);
  console.log(`%c  Query Params: ${result.features.queryParamCount}`, `color: ${palette.textSecondary}`);
  console.log(`%c  IP Address: ${result.features.hasIPAddress ? 'Yes' : 'No'}`, result.features.hasIPAddress ? `color: ${palette.textPrimary}` : `color: ${palette.textMuted}`);
  console.log(`%c  Suspicious TLD: ${result.features.suspiciousTLD ? `.${result.features.tld}` : 'No'}`, result.features.suspiciousTLD ? `color: ${palette.textPrimary}` : `color: ${palette.textMuted}`);
  console.log(`%c  Suspicious Port: ${result.features.hasSuspiciousPort ? 'Yes' : 'No'}`, result.features.hasSuspiciousPort ? `color: ${palette.textPrimary}` : `color: ${palette.textMuted}`);
  
  if (result.features.suspiciousKeywords.length > 0) {
    console.log(`%c  Keywords Found: ${result.features.suspiciousKeywords.join(', ')}`, `color: ${palette.textSecondary}`);
  } else {
    console.log(`%c  Keywords Found: None`, `color: ${palette.textMuted}`);
  }
  
  console.log('%c--------------------------------', `color: ${palette.divider}`);
  console.groupEnd();
}

/**
 * Get concise explanations for detected risks
 */
function getSimpleExplanations(result: RiskAnalysisResult): Array<{title: string, explanation: string}> {
  const explanations: Array<{title: string, explanation: string}> = [];
  
  // IP Address
  if (result.features.hasIPAddress) {
    explanations.push({
      title: 'Using IP Address Instead of Domain',
      explanation: 'Real websites use names like "google.com", not numbers. Scammers use IPs to hide their identity.',
    });
  }
  
  // Suspicious TLD
  if (result.features.suspiciousTLD) {
    explanations.push({
      title: `Cheap Domain Extension (.${result.features.tld})`,
      explanation: 'Extensions like .xyz, .tk are free/cheap and commonly used by scammers. Trusted sites use .com, .org, .edu.',
    });
  }
  
  // Suspicious Keywords
  if (result.features.suspiciousKeywords.length > 0) {
    explanations.push({
      title: `Phishing Keywords Detected (${result.features.suspiciousKeywords.join(', ')})`,
      explanation: 'Words like "login", "verify", "secure" create urgency to trick you into entering passwords on fake sites.',
    });
  }
  
  // Suspicious Port
  if (result.features.hasSuspiciousPort) {
    explanations.push({
      title: 'Non-Standard Port Number',
      explanation: 'Normal websites use port 80/443. Unusual ports (8080, 3000) often indicate testing servers or attackers.',
    });
  }
  
  // Too Many Subdomains
  if (result.features.subdomainCount > 3) {
    explanations.push({
      title: `Too Many Subdomains (${result.features.subdomainCount})`,
      explanation: 'Scammers use complex URLs like "login.secure.verify.fake.com" to confuse you. Real domain is right before last dot!',
    });
  }
  
  // Long URL (only if critically long)
  if (result.features.length > 120) {
    explanations.push({
      title: `Very Long URL (${result.features.length} characters)`,
      explanation: 'Attackers create long URLs to hide malicious parts. Shorter URLs are usually safer.',
    });
  }
  
  return explanations;
}
