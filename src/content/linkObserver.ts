// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Link Observer
 * Monitors DOM for links and attaches hover listeners
 */

import type { RiskAnalysisResult } from '../core/types';
import { DEBUG_MODE } from '../core/constants';
import { showTooltip, hideTooltip, removeTooltip } from './tooltipUI';
import { sendToBackground } from '../services/messagingService';
import { showSafetyPanel } from './safetyPanel';
import { analyzeURL } from '../core/urlAnalyzer';

const observedLinks = new WeakSet<HTMLAnchorElement>();
const observedActionElements = new WeakSet<HTMLElement>();
const preloadCache = new Map<string, RiskAnalysisResult>(); // Fast local cache

let observer: MutationObserver | null = null;
let currentLinkData: { url: string; result: RiskAnalysisResult } | null = null;
let globalDownloadClickAttached = false;

const EXECUTABLE_EXTENSIONS = new Set([
  'exe', 'msi', 'bat', 'cmd', 'scr', 'pif', 'com', 'cpl', 'jar', 'vbs', 'js', 'ps1', 'apk', 'dmg', 'pkg', 'appimage',
]);

const ARCHIVE_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'img',
]);

const DOCUMENT_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf',
]);

const HIGH_RISK_DOWNLOAD_KEYWORDS = [
  'crack',
  'keygen',
  'activator',
  'serial',
  'license-key',
  'warez',
  'nulled',
  'torrent',
  'patch',
  'full-version',
];

const DOWNLOAD_TRIGGER_KEYWORDS = [
  'download',
  'installer',
  'setup',
  'install',
  'dmg',
  'pkg',
  'exe',
  'msi',
];

const URL_CANDIDATE_ATTRIBUTES = [
  'href',
  'data-href',
  'data-url',
  'data-link',
  'data-download',
  'data-download-url',
  'data-target-url',
];

const ACTION_ELEMENT_SELECTOR = [
  'button',
  '[role="button"]',
  'input[type="button"]',
  'input[type="submit"]',
  'input[type="image"]',
].join(', ');

interface DownloadRiskResult {
  score: number;
  fileName: string;
  extension: string;
  reasons: string[];
  safestAction: string;
}

/**
 * Initialize link observation
 */
export function initLinkObserver(): void {
  if (DEBUG_MODE) {
    console.log('Initializing link observer');
  }

  // Listen for safety panel requests from tooltip clicks
  document.addEventListener('ai-show-safety-panel', ((_e: CustomEvent) => {
    if (currentLinkData) {
      showSafetyPanel(currentLinkData.url, currentLinkData.result);
    }
  }) as EventListener);

  // Observe existing links
  observeExistingLinks();
  observeExistingActionElements();

  // Set up mutation observer for dynamic content
  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const element = node as HTMLElement;
            
            // Check if node itself is a link
            if (element.tagName === 'A') {
              attachLinkListeners(element as HTMLAnchorElement);
            }
            
            // Check for links within node
            const links = element.querySelectorAll('a');
            links.forEach((link) => attachLinkListeners(link));

            // Check for button-like action elements within node
            if (element.matches(ACTION_ELEMENT_SELECTOR)) {
              attachActionElementListeners(element);
            }
            const actionElements = element.querySelectorAll(ACTION_ELEMENT_SELECTOR);
            actionElements.forEach((actionElement) => attachActionElementListeners(actionElement as HTMLElement));
          }
        });
      }
    }
  });

  // Start observing — document.body can be null on special pages (PDFs, chrome://, etc.)
  const observeTarget = document.body ?? document.documentElement;
  if (!observeTarget) {
    if (DEBUG_MODE) {
      console.warn('No observable DOM node found — link observer not started');
    }
    return;
  }
  observer.observe(observeTarget, {
    childList: true,
    subtree: true,
  });

  if (!globalDownloadClickAttached) {
    document.addEventListener('click', handleGlobalDownloadClick, true);
    globalDownloadClickAttached = true;
  }

  if (DEBUG_MODE) {
    console.log('Link observer initialized');
  }
}

/**
 * Stop link observation
 */
export function stopLinkObserver(): void {
  if (observer) {
    observer.disconnect();
    observer = null;
  }

  if (globalDownloadClickAttached) {
    document.removeEventListener('click', handleGlobalDownloadClick, true);
    globalDownloadClickAttached = false;
  }
  
  if (DEBUG_MODE) {
    console.log('🛑 Link observer stopped');
  }
}

/**
 * Observe all existing links on page
 */
function observeExistingLinks(): void {
  const links = document.querySelectorAll('a');
  
  if (DEBUG_MODE) {
    console.log(`📊 Found ${links.length} existing links`);
  }
  
  links.forEach((link) => attachLinkListeners(link));
}

function observeExistingActionElements(): void {
  const actionElements = document.querySelectorAll(ACTION_ELEMENT_SELECTOR);
  actionElements.forEach((element) => attachActionElementListeners(element as HTMLElement));
}

/**
 * Attach hover listeners to a link
 */
function attachLinkListeners(link: HTMLAnchorElement): void {
  // Skip if already observed
  if (observedLinks.has(link)) {
    return;
  }

  // Skip if no href
  if (!link.href) {
    return;
  }

  // Mark as observed
  observedLinks.add(link);

  // Mouse enter - show tooltip
  link.addEventListener('mouseenter', handleMouseEnter);

  // Mouse leave - hide tooltip
  link.addEventListener('mouseleave', handleMouseLeave);

  // Mouse move - update tooltip position
  link.addEventListener('mousemove', handleMouseMove);

  // Click - intercept if risk score >30%
  link.addEventListener('click', handleLinkClick, true);
}

function attachActionElementListeners(element: HTMLElement): void {
  if (observedActionElements.has(element)) return;
  if (element.tagName === 'A') return;

  const hasResolvableUrl = !!resolveActionUrl(element);
  if (!hasResolvableUrl && !isLikelyDownloadControl(element)) {
    return;
  }

  observedActionElements.add(element);

  element.addEventListener('mouseenter', handleActionMouseEnter);
  element.addEventListener('mouseleave', handleMouseLeave);
  element.addEventListener('mousemove', handleMouseMove);
  element.addEventListener('click', handleActionClick, true);
}

/**
 * Handle mouse enter event - ultrafast with preload cache
 */
async function handleMouseEnter(event: MouseEvent): Promise<void> {
  const link = event.currentTarget as HTMLAnchorElement;
  const url = link.href;

  if (!url) return;

  try {
    // Check preload cache first for instant response
    let result = preloadCache.get(url);
    
    if (result) {
      // Instant display from cache
      currentLinkData = { url, result };
      showTooltip(link, result, event.clientX, event.clientY, url);
      return;
    }

    // Request analysis from background
    const response = await sendToBackground<RiskAnalysisResult>({
      type: 'ANALYZE_URL',
      payload: { url },
    });

    if (response.success && response.data) {
      result = response.data;
      
      // Store in preload cache for next time
      preloadCache.set(url, result);
      
      // Limit cache size
      if (preloadCache.size > 100) {
        const firstKey = preloadCache.keys().next().value;
        if (firstKey !== undefined) preloadCache.delete(firstKey);
      }
      
      // Store current link data for safety panel
      currentLinkData = { url, result };
      
      showTooltip(link, result, event.clientX, event.clientY, url);
    }
  } catch (error) {
    if (DEBUG_MODE) {
      console.error('Error analyzing URL on hover:', error);
    }
  }
}

/**
 * Handle mouse leave event
 */
function handleMouseLeave(_event: MouseEvent): void {
  // Clear current link data after a delay
  setTimeout(() => {
    currentLinkData = null;
  }, 150);
  
  hideTooltip();
}

/**
 * Handle mouse move event (for tooltip repositioning)
 */
function handleMouseMove(_event: MouseEvent): void {
  // Tooltip position is set on initial show
  // We don't reposition on every move to avoid performance issues
}

/**
 * Handle link click - show confirmation for risky links
 */
function handleLinkClick(event: MouseEvent): void {
  const link = event.currentTarget as HTMLAnchorElement;
  const url = link.href;

  if (isDownloadCandidate(link, url)) {
    const downloadRisk = analyzeDownloadRisk(url, link);
    if (downloadRisk.score >= 30) {
      event.preventDefault();
      event.stopPropagation();
      showDownloadRiskConfirmation(url, downloadRisk);
      return;
    }
    // Low-risk downloads (<30%) are allowed.
    return;
  }

  // Check if we have analysis data for this link
  const cachedResult = preloadCache.get(url);
  
  if (cachedResult && cachedResult.score > 30) {
    // Prevent default navigation
    event.preventDefault();
    event.stopPropagation();
    
    // Show custom confirmation dialog
    showRiskConfirmation(url, cachedResult);
  }
  // If score ≤30 or no data, allow normal navigation
}

async function handleActionMouseEnter(event: MouseEvent): Promise<void> {
  const element = event.currentTarget as HTMLElement;
  const resolvedUrl = resolveActionUrl(element);
  const url = resolvedUrl || (isLikelyDownloadControl(element) ? window.location.href : null);
  if (!url) return;

  try {
    let result = preloadCache.get(url);

    if (result) {
      currentLinkData = { url, result };
      showTooltip(element, result, event.clientX, event.clientY, url);
      return;
    }

    const response = await sendToBackground<RiskAnalysisResult>({
      type: 'ANALYZE_URL',
      payload: { url },
    });

    if (response.success && response.data) {
      result = response.data;
      preloadCache.set(url, result);

      if (preloadCache.size > 100) {
        const firstKey = preloadCache.keys().next().value;
        if (firstKey !== undefined) preloadCache.delete(firstKey);
      }

      currentLinkData = { url, result };
      showTooltip(element, result, event.clientX, event.clientY, url);
    }
  } catch (error) {
    if (DEBUG_MODE) {
      console.error('Error analyzing action URL on hover:', error);
    }
  }
}

function handleGlobalDownloadClick(event: MouseEvent): void {
  if (event.defaultPrevented) return;

  const target = event.target as HTMLElement | null;
  if (!target) return;

  // Anchor elements are already handled by per-link listeners.
  if (findClosestAnchor(target)) return;

  const candidate = extractDownloadUrlCandidate(target);
  if (!candidate) return;

  const { element, url } = candidate;
  if (!isDownloadCandidate(element, url)) return;

  const downloadRisk = analyzeDownloadRisk(url, element);
  if (downloadRisk.score < 30) return;

  event.preventDefault();
  event.stopPropagation();
  showDownloadRiskConfirmation(url, downloadRisk);
}

function handleActionClick(event: MouseEvent): void {
  const element = event.currentTarget as HTMLElement;
  const url = resolveActionUrl(element);
  if (!url) return;
  if (!isDownloadCandidate(element, url)) return;

  const downloadRisk = analyzeDownloadRisk(url, element);
  if (downloadRisk.score < 30) return;

  event.preventDefault();
  event.stopPropagation();
  showDownloadRiskConfirmation(url, downloadRisk);
}

function isDownloadCandidate(element: HTMLElement, url: string): boolean {
  if (element.hasAttribute('download')) return true;

  const lower = url.toLowerCase();
  if (/(download|attachment|filename=|file=)/i.test(lower)) return true;

  const textCue = getDownloadCueText(element);
  if (DOWNLOAD_TRIGGER_KEYWORDS.some((k) => textCue.includes(k))) return true;

  try {
    const parsed = new URL(url);
    const pathname = decodeURIComponent(parsed.pathname || '');
    const name = pathname.split('/').pop() || '';
    const ext = name.includes('.') ? name.split('.').pop()?.toLowerCase() || '' : '';
    if (EXECUTABLE_EXTENSIONS.has(ext) || ARCHIVE_EXTENSIONS.has(ext) || DOCUMENT_EXTENSIONS.has(ext)) {
      return true;
    }
  } catch {
    // Ignore invalid URL parse
  }

  return false;
}

function analyzeDownloadRisk(url: string, sourceElement: HTMLElement): DownloadRiskResult {
  const reasons: string[] = [];
  let score = 0;

  let fileName = 'downloaded file';
  let extension = '';

  try {
    const parsed = new URL(url);
    const pathname = decodeURIComponent(parsed.pathname || '');
    fileName = pathname.split('/').pop() || fileName;
    extension = fileName.includes('.') ? (fileName.split('.').pop() || '').toLowerCase() : '';

    if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
      score += 45;
      reasons.push(`Executable file type detected (.${extension}).`);
    } else if (extension && ARCHIVE_EXTENSIONS.has(extension)) {
      score += 15;
      reasons.push(`Archive file detected (.${extension}). Archives can hide malicious payloads.`);
    } else if (extension && DOCUMENT_EXTENSIONS.has(extension)) {
      score += 5;
      reasons.push(`Document file detected (.${extension}). Verify source before opening.`);
    } else if (extension) {
      score += 10;
      reasons.push(`Unknown or uncommon file type (.${extension}).`);
    } else {
      score += 10;
      reasons.push('No clear file extension found.');
    }

    if (parsed.protocol === 'http:') {
      score += 10;
      reasons.push('File is delivered over HTTP (not HTTPS).');
    }

    const urlFeatures = analyzeURL(url);
    if (urlFeatures.hasIPAddress) {
      score += 20;
      reasons.push('Download host uses an IP address instead of a domain.');
    }
    if (urlFeatures.suspiciousTLD) {
      score += 20;
      reasons.push(`Download host uses a suspicious TLD (.${urlFeatures.tld}).`);
    }
    if (urlFeatures.hasSuspiciousPort) {
      score += 15;
      reasons.push('Download host uses a non-standard port.');
    }
    if (urlFeatures.subdomainCount > 3) {
      score += 10;
      reasons.push(`Host contains many subdomains (${urlFeatures.subdomainCount}).`);
    }
  } catch {
    score += 20;
    reasons.push('Could not validate download URL format.');
  }

  const combinedText = `${url} ${fileName} ${getDownloadCueText(sourceElement)}`.toLowerCase();
  const matchedKeywords = HIGH_RISK_DOWNLOAD_KEYWORDS.filter((k) => combinedText.includes(k));
  if (matchedKeywords.length > 0) {
    score += 35;
    reasons.push(`High-risk download terms found: ${matchedKeywords.join(', ')}.`);
  }

  if (/\.(pdf|jpg|png|docx?|xlsx?)\.(exe|scr|bat|cmd|js|vbs|jar)$/i.test(fileName)) {
    score += 35;
    reasons.push('Double extension pattern detected (possible disguised executable).');
  }

  score = Math.min(100, Math.max(0, score));
  const safestAction = score >= 30
    ? 'Scan file URL first. Use Incognito only if scan results are clean.'
    : 'Risk is low. Download can proceed.';

  return {
    score,
    fileName,
    extension,
    reasons,
    safestAction,
  };
}

function findClosestAnchor(element: HTMLElement): HTMLAnchorElement | null {
  return element.closest('a[href]');
}

function getDownloadCueText(element: HTMLElement): string {
  const id = element.id || '';
  const className = typeof element.className === 'string' ? element.className : '';
  const ariaLabel = element.getAttribute('aria-label') || '';
  const text = element.textContent || '';
  return `${id} ${className} ${ariaLabel} ${text}`.toLowerCase();
}

function extractDownloadUrlCandidate(element: HTMLElement): { element: HTMLElement; url: string } | null {
  let current: HTMLElement | null = element;
  let depth = 0;

  while (current && depth < 7) {
    const url = readUrlFromElement(current);
    if (url) {
      return { element: current, url };
    }
    current = current.parentElement;
    depth += 1;
  }

  return null;
}

function resolveActionUrl(element: HTMLElement): string | null {
  const directCandidate = extractDownloadUrlCandidate(element);
  if (directCandidate?.url) return directCandidate.url;

  const form = element.closest('form');
  if (form) {
    const action = normalizeUrl(form.getAttribute('action'));
    if (action) return action;
  }

  return null;
}

function isLikelyDownloadControl(element: HTMLElement): boolean {
  const cueText = getDownloadCueText(element);
  return DOWNLOAD_TRIGGER_KEYWORDS.some((keyword) => cueText.includes(keyword));
}

function readUrlFromElement(element: HTMLElement): string | null {
  for (const attr of URL_CANDIDATE_ATTRIBUTES) {
    const value = element.getAttribute(attr);
    const normalized = normalizeUrl(value);
    if (normalized) return normalized;
  }

  for (const [key, value] of Object.entries(element.dataset || {})) {
    const lowerKey = key.toLowerCase();
    if (!/(url|href|download|link)/.test(lowerKey)) continue;
    const normalized = normalizeUrl(value);
    if (normalized) return normalized;
  }

  const onclickValue = element.getAttribute('onclick');
  if (onclickValue) {
    const extracted = extractUrlFromOnClick(onclickValue);
    if (extracted) return extracted;
  }

  return null;
}

function extractUrlFromOnClick(onclickCode: string): string | null {
  const patterns = [
    /window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/i,
    /location\.href\s*=\s*['"]([^'"]+)['"]/i,
    /window\.open\(\s*['"]([^'"]+)['"]/i,
  ];

  for (const pattern of patterns) {
    const match = onclickCode.match(pattern);
    if (match?.[1]) {
      const normalized = normalizeUrl(match[1]);
      if (normalized) return normalized;
    }
  }

  return null;
}

function normalizeUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;

  const value = raw.trim();
  if (!value) return null;

  if (value.startsWith('#')) return null;
  if (/^(javascript:|mailto:|tel:|data:|blob:)/i.test(value)) return null;

  try {
    return new URL(value, window.location.href).href;
  } catch {
    return null;
  }
}

/**
 * Per-indicator safety guidance
 */
type RecommendedActionType =
  | 'OPEN_INCOGNITO'
  | 'SCAN_FIRST'
  | 'MANUAL_VERIFY'
  | 'DO_NOT_OPEN';

interface IndicatorGuidance {
  signal: string;
  reason: string;
  safestOption: string;
}

function getIndicatorGuidance(result: RiskAnalysisResult): IndicatorGuidance[] {
  const items: IndicatorGuidance[] = [];

  if (result.features.hasIPAddress) {
    items.push({
      signal: 'IP address used instead of domain',
      reason: 'Numeric hosts are common in phishing and temporary malicious infrastructure.',
      safestOption: 'Do not open directly. Scan first in VirusTotal, then use an isolated browser profile only if required.',
    });
  }
  if (result.features.suspiciousTLD) {
    items.push({
      signal: `High-risk domain extension (.${result.features.tld})`,
      reason: 'Low-cost TLDs are frequently abused for throwaway phishing sites.',
      safestOption: 'Scan first and avoid entering personal or payment data.',
    });
  }
  if (result.features.suspiciousKeywords.length > 0) {
    items.push({
      signal: `Suspicious terms in URL: ${result.features.suspiciousKeywords.join(', ')}`,
      reason: 'Urgency terms like login/verify/secure are often used for credential theft.',
      safestOption: 'Do not trust this path. Open the official website manually from a fresh tab/bookmark.',
    });
  }
  if (result.features.hasSuspiciousPort) {
    items.push({
      signal: 'Non-standard port detected',
      reason: 'Unexpected ports can indicate non-production, unsafe, or attacker-controlled services.',
      safestOption: 'Avoid direct open. Verify the official URL and port from trusted documentation.',
    });
  }
  if (result.features.subdomainCount > 3) {
    items.push({
      signal: `Too many subdomains (${result.features.subdomainCount})`,
      reason: 'Subdomain stacking is used to hide the real registered domain.',
      safestOption: 'Check the registered domain before opening. If needed, use incognito and no login.',
    });
  }
  if (result.features.dotCount > 5) {
    items.push({
      signal: `High dot count (${result.features.dotCount})`,
      reason: 'Excess separators can be used to imitate trusted hostnames.',
      safestOption: 'Verify domain ownership first, then open only in isolated mode.',
    });
  }
  if (result.features.length > 100) {
    items.push({
      signal: `Unusually long URL (${result.features.length} chars)`,
      reason: 'Long URLs can hide malicious parameters and redirect chains.',
      safestOption: 'Scan the full URL first and avoid submitting any forms.',
    });
  }

  if (items.length === 0) {
    items.push({
      signal: 'General heuristic warning',
      reason: 'Multiple minor indicators were detected.',
      safestOption: 'Prefer incognito and avoid entering credentials.',
    });
  }

  return items;
}

function getDetailedExplanation(result: RiskAnalysisResult): string {
  const items = getIndicatorGuidance(result);
  return `
    <div style="margin-bottom: 18px; border: 1px solid #3f3f46; background: #18181b; padding: 14px;">
      <div style="color: #f5f5f5; font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 10px;">
        Flagged Signals And Safest Options
      </div>
      <div style="display: grid; gap: 10px;">
        ${items.slice(0, 6).map((item) => `
          <div style="border: 1px solid #3f3f46; background: #111111; padding: 10px;">
            <div style="color: #f4f4f5; font-size: 12px; font-weight: 700; margin-bottom: 4px;">${item.signal}</div>
            <div style="color: #a1a1aa; font-size: 12px; line-height: 1.5; margin-bottom: 6px;">${item.reason}</div>
            <div style="color: #d4d4d8; font-size: 12px; line-height: 1.5;"><strong>Best safer option:</strong> ${item.safestOption}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function getRecommendedAction(result: RiskAnalysisResult): {
  type: RecommendedActionType;
  title: string;
  description: string;
  buttonLabel: string;
} {
  if (result.score >= 85) {
    return {
      type: 'DO_NOT_OPEN',
      title: 'Recommended action',
      description: 'Do not open this link. Risk is very high.',
      buttonLabel: 'Do Not Open (Recommended)',
    };
  }

  if (result.features.hasIPAddress || result.features.suspiciousTLD || result.features.hasSuspiciousPort) {
    return {
      type: 'SCAN_FIRST',
      title: 'Recommended action',
      description: 'Scan this URL first. Open only after a clean scan result.',
      buttonLabel: 'Scan Link First (Recommended)',
    };
  }

  if (
    result.features.suspiciousKeywords.length > 0 ||
    result.features.subdomainCount > 3 ||
    result.features.dotCount > 5
  ) {
    return {
      type: 'MANUAL_VERIFY',
      title: 'Recommended action',
      description: 'Verify the official domain manually. Avoid opening this exact link directly.',
      buttonLabel: 'Verify Domain First (Recommended)',
    };
  }

  return {
    type: 'OPEN_INCOGNITO',
    title: 'Recommended action',
    description: 'If you must continue, open in incognito and avoid logging in.',
    buttonLabel: 'Continue with Safety (Incognito)',
  };
}

function getVirusTotalUrl(url: string): string {
  return 'https://www.virustotal.com/gui/url/' + btoa(url).replace(/=/g, '') + '/detection';
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through
  }

  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    (document.body ?? document.documentElement).appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    return true;
  } catch {
    return false;
  }
}

function openInIncognito(url: string): void {
  sendToBackground({ type: 'OPEN_INCOGNITO', payload: { url } })
    .then((res) => {
      if (!res.success) {
        alert(
          'Could not open an Incognito window automatically.\n\n' +
          'Please open it manually: Ctrl+Shift+N (or ⌘+Shift+N), then paste the link.'
        );
      }
    })
    .catch(() => {
      alert(
        'Could not open an Incognito window automatically.\n\n' +
        'Please open it manually: Ctrl+Shift+N (or ⌘+Shift+N), then paste the link.'
      );
    });
}

function showDownloadRiskConfirmation(url: string, result: DownloadRiskResult): void {
  const level = result.score >= 80 ? 'Critical' : result.score >= 60 ? 'High' : 'Elevated';

  const overlay = document.createElement('div');
  overlay.id = 'ai-download-risk-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.82);
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    animation: fadeIn 0.14s linear;
  `;

  const dialog = document.createElement('div');
  dialog.style.cssText = `
    background: #0a0a0a;
    border: 1px solid #a1a1aa;
    border-radius: 0;
    padding: 24px;
    max-width: 560px;
    max-height: 85vh;
    width: 90%;
    overflow-y: auto;
    box-shadow: 0 18px 40px rgba(0, 0, 0, 0.55);
    animation: slideIn 0.14s ease-out;
  `;

  dialog.innerHTML = `
    <style>
      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      @keyframes slideIn {
        from { transform: translateY(8px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
    </style>
    <div style="margin-bottom: 16px;">
      <h2 style="color: #ffffff; font-size: 22px; font-weight: 700; margin: 0 0 6px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
        ${Math.round(result.score)}% Download Risk
      </h2>
      <p style="color: #a1a1aa; font-size: 13px; margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
        Risk level: ${level}
      </p>
      <div style="background: #111111; border: 1px solid #27272a; padding: 8px 10px; margin-top: 12px; font-size: 11px; color: #d4d4d8; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;">
        ${result.fileName}
      </div>
    </div>

    <div style="margin-bottom: 16px; border: 1px solid #3f3f46; background: #18181b; padding: 12px;">
      <div style="color: #f4f4f5; font-size: 12px; font-weight: 700; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.06em;">
        Detected Problems
      </div>
      <ul style="margin: 0; padding-left: 18px; color: #d4d4d8; font-size: 12px; line-height: 1.6;">
        ${result.reasons.slice(0, 8).map((reason) => `<li>${reason}</li>`).join('')}
      </ul>
      <div style="margin-top: 10px; color: #a1a1aa; font-size: 12px;">
        <strong style="color:#f4f4f5;">Safest option:</strong> ${result.safestAction}
      </div>
    </div>

    <div style="display: flex; gap: 10px; margin-top: 18px;">
      <button id="ai-download-scan" style="
        flex: 1;
        background: #ffffff;
        color: #0a0a0a;
        border: 1px solid #ffffff;
        border-radius: 0;
        padding: 12px 14px;
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
      ">
        Scan File Link
      </button>
      <button id="ai-download-incognito" style="
        flex: 1;
        background: #27272a;
        color: #f4f4f5;
        border: 1px solid #71717a;
        border-radius: 0;
        padding: 12px 14px;
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
      ">
        Continue with Incognito
      </button>
      <button id="ai-download-risk" style="
        flex: 1;
        background: #18181b;
        color: #f4f4f5;
        border: 1px solid #52525b;
        border-radius: 0;
        padding: 12px 14px;
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
      ">
        Continue with Risk
      </button>
    </div>
  `;

  overlay.appendChild(dialog);
  (document.body ?? document.documentElement).appendChild(overlay);

  const scanBtn = dialog.querySelector('#ai-download-scan') as HTMLButtonElement;
  const incognitoBtn = dialog.querySelector('#ai-download-incognito') as HTMLButtonElement;
  const riskBtn = dialog.querySelector('#ai-download-risk') as HTMLButtonElement;

  scanBtn.onclick = () => {
    window.open(getVirusTotalUrl(url), '_blank', 'noopener,noreferrer');
    overlay.remove();
  };
  incognitoBtn.onclick = () => {
    openInIncognito(url);
    overlay.remove();
  };
  riskBtn.onclick = () => {
    window.location.href = url;
    overlay.remove();
  };

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.remove();
  });
}

/**
 * Show custom risk confirmation dialog with detailed explanations
 */
function showRiskConfirmation(url: string, result: RiskAnalysisResult): void {
  const level = result.score >= 60 ? 'High' : result.score >= 40 ? 'Medium' : 'Elevated';
  const borderColor = result.score >= 60 ? '#f5f5f5' : result.score >= 40 ? '#a1a1aa' : '#71717a';
  const recommended = getRecommendedAction(result);
  
  // Create modal overlay
  const overlay = document.createElement('div');
  overlay.id = 'ai-risk-confirmation-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.82);
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    animation: fadeIn 0.14s linear;
  `;

  // Create dialog
  const dialog = document.createElement('div');
  dialog.style.cssText = `
    background: #0a0a0a;
    border: 1px solid ${borderColor};
    border-radius: 0;
    padding: 24px;
    max-width: 560px;
    max-height: 85vh;
    width: 90%;
    overflow-y: auto;
    box-shadow: 0 18px 40px rgba(0, 0, 0, 0.55);
    animation: slideIn 0.14s ease-out;
  `;

  // Get detailed explanations
  const detailedExplanations = getDetailedExplanation(result);

  dialog.innerHTML = `
    <style>
      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      @keyframes slideIn {
        from { transform: translateY(8px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      #ai-risk-confirmation-overlay::-webkit-scrollbar {
        width: 6px;
      }
      #ai-risk-confirmation-overlay::-webkit-scrollbar-track {
        background: #111111;
      }
      #ai-risk-confirmation-overlay::-webkit-scrollbar-thumb {
        background: #52525b;
      }
      #ai-risk-confirmation-overlay::-webkit-scrollbar-thumb:hover {
        background: #71717a;
      }
    </style>
    <div style="margin-bottom: 20px;">
      <h2 style="color: #ffffff; font-size: 22px; font-weight: 700; margin: 0 0 6px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
        ${Math.round(result.score)}% Risk Score
      </h2>
      <p style="color: #a1a1aa; font-size: 13px; margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
        Risk level: ${level}
      </p>
      <div style="background: #111111; border: 1px solid #27272a; padding: 8px 10px; margin-top: 12px; font-size: 11px; color: #d4d4d8; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;">
        ${url.length > 80 ? url.substring(0, 80) + '...' : url}
      </div>
    </div>
    
    <div style="margin-bottom: 18px;">
      ${detailedExplanations}
      
      <div style="border: 1px solid #3f3f46; background: #111111; padding: 12px;">
        <div style="color: #f4f4f5; font-size: 12px; font-weight: 700; margin-bottom: 4px;">
          ${recommended.title}
        </div>
        <div style="color: #d4d4d8; font-size: 12px; line-height: 1.6;">
          ${recommended.description}
        </div>
      </div>
    </div>
    
    <div style="display: flex; gap: 10px; margin-top: 18px;">
      <button id="ai-continue-safely" style="
        flex: 1;
        background: #ffffff;
        color: #0a0a0a;
        border: 1px solid #ffffff;
        border-radius: 0;
        padding: 12px 14px;
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
        transition: background 0.12s linear, color 0.12s linear;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        letter-spacing: 0.01em;
      ">
        ${recommended.buttonLabel}
      </button>
      <button id="ai-open-incognito" style="
        flex: 1;
        background: #27272a;
        color: #f4f4f5;
        border: 1px solid #71717a;
        border-radius: 0;
        padding: 12px 14px;
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
        transition: background 0.12s linear, border-color 0.12s linear;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        letter-spacing: 0.01em;
      ">
        Continue with Incognito
      </button>
      <button id="ai-ignore-risk" style="
        flex: 1;
        background: #18181b;
        color: #f4f4f5;
        border: 1px solid #52525b;
        border-radius: 0;
        padding: 12px 14px;
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
        transition: background 0.12s linear, border-color 0.12s linear;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        letter-spacing: 0.01em;
      ">
        Continue in Current Tab
      </button>
    </div>
  `;

  overlay.appendChild(dialog);
  (document.body ?? document.documentElement).appendChild(overlay);

  // Add hover effects
  const safeBtn = dialog.querySelector('#ai-continue-safely') as HTMLButtonElement;
  const incognitoBtn = dialog.querySelector('#ai-open-incognito') as HTMLButtonElement;
  const riskBtn = dialog.querySelector('#ai-ignore-risk') as HTMLButtonElement;

  safeBtn.addEventListener('mouseenter', () => {
    safeBtn.style.background = '#e4e4e7';
    safeBtn.style.color = '#09090b';
  });
  safeBtn.addEventListener('mouseleave', () => {
    safeBtn.style.background = '#ffffff';
    safeBtn.style.color = '#0a0a0a';
  });

  incognitoBtn.addEventListener('mouseenter', () => {
    incognitoBtn.style.background = '#3f3f46';
    incognitoBtn.style.borderColor = '#a1a1aa';
  });
  incognitoBtn.addEventListener('mouseleave', () => {
    incognitoBtn.style.background = '#27272a';
    incognitoBtn.style.borderColor = '#71717a';
  });

  riskBtn.addEventListener('mouseenter', () => {
    riskBtn.style.background = '#27272a';
    riskBtn.style.borderColor = '#71717a';
  });
  riskBtn.addEventListener('mouseleave', () => {
    riskBtn.style.background = '#18181b';
    riskBtn.style.borderColor = '#52525b';
  });

  // Handle button clicks
  safeBtn.addEventListener('click', () => {
    if (recommended.type === 'DO_NOT_OPEN') {
      overlay.remove();
      return;
    }

    if (recommended.type === 'SCAN_FIRST') {
      window.open(getVirusTotalUrl(url), '_blank', 'noopener,noreferrer');
      overlay.remove();
      return;
    }

    if (recommended.type === 'MANUAL_VERIFY') {
      copyToClipboard(url).then((copied) => {
        const copiedText = copied ? 'The URL was copied to your clipboard.\n\n' : '';
        alert(
          copiedText +
          'Open the official website manually from a trusted bookmark or by typing the known domain.\n' +
          'Do not sign in through this suspicious link.'
        );
      });
      overlay.remove();
      return;
    }

    openInIncognito(url);
    overlay.remove();
  });

  incognitoBtn.addEventListener('click', () => {
    openInIncognito(url);
    overlay.remove();
  });

  riskBtn.addEventListener('click', () => {
    window.location.href = url;
    overlay.remove();
  });

  // Close on overlay click
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) {
      overlay.remove();
    }
  });

  // ESC key to close
  const handleEscape = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      overlay.remove();
      document.removeEventListener('keydown', handleEscape);
    }
  };
  document.addEventListener('keydown', handleEscape);
}

/**
 * Clean up all tooltips (useful for navigation)
 */
export function cleanupTooltips(): void {
  removeTooltip();
}
