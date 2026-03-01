// SPDX-License-Identifier: MIT
// Copyright (c) 2026 chethanakash67

/**
 * Safety Panel Component
 * Full-page overlay for high-risk link interception
 */

import type { RiskAnalysisResult, PanelAction } from '../core/types';
import { PANEL_CONFIG, MESSAGE_TYPES } from '../core/constants';
import { sendToBackground } from '../services/messagingService';
import { createElement, removeElement, stopEvent } from '../utils/domUtils';
import { formatPercentage, getScoreColor, getRiskLevel, getRiskDescription } from '../utils/scoringUtils';

const PANEL_ID = 'ai-risk-safety-panel';

let currentPanel: HTMLElement | null = null;
let panelResolve: ((action: PanelAction) => void) | null = null;

/**
 * Show safety panel and wait for user action
 */
export function showSafetyPanel(url: string, result: RiskAnalysisResult): Promise<PanelAction> {
  return new Promise((resolve) => {
    // Remove existing panel if any
    removeSafetyPanel();

    panelResolve = resolve;
    currentPanel = createPanelElement(url, result);
    document.body.appendChild(currentPanel);

    // Prevent background scrolling
    document.body.style.overflow = 'hidden';
  });
}

/**
 * Remove safety panel
 */
export function removeSafetyPanel(): void {
  if (currentPanel) {
    removeElement(currentPanel);
    currentPanel = null;
    panelResolve = null;
    document.body.style.overflow = '';
  }
}

/**
 * Create panel DOM element
 */
function createPanelElement(url: string, result: RiskAnalysisResult): HTMLElement {
  const level = getRiskLevel(result.score);
  const color = getScoreColor(result.score);
  const description = getRiskDescription(level);

  // Overlay
  const overlay = createElement('div', {
    attributes: {
      id: PANEL_ID,
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': 'panel-title',
    },
    classes: ['ai-risk-panel-overlay'],
  });
  overlay.style.zIndex = String(PANEL_CONFIG.zIndex);

  // Panel container
  const panel = createElement('div', {
    classes: ['ai-risk-panel', `risk-${level}`],
  });

  // Close button
  const closeBtn = createElement('button', {
    classes: ['panel-close'],
    attributes: {
      'aria-label': 'Close',
    },
    text: '×',
  });
  closeBtn.onclick = () => handleAction({ type: 'CLOSE' });
  panel.appendChild(closeBtn);

  // Warning icon
  const icon = createElement('div', {
    classes: ['panel-icon'],
    html: '⚠️',
  });
  panel.appendChild(icon);

  // Title
  const title = createElement('h2', {
    attributes: {
      id: 'panel-title',
    },
    classes: ['panel-title'],
    text: 'Potentially Dangerous Link Detected',
  });
  panel.appendChild(title);

  // Score display
  const scoreContainer = createElement('div', {
    classes: ['panel-score-container'],
  });

  const scoreValue = createElement('div', {
    classes: ['panel-score'],
    text: formatPercentage(result.score),
  });
  scoreValue.style.color = color;

  const scoreLabel = createElement('div', {
    classes: ['panel-score-label'],
    text: `${level.toUpperCase()} RISK`,
  });

  scoreContainer.appendChild(scoreValue);
  scoreContainer.appendChild(scoreLabel);
  panel.appendChild(scoreContainer);

  // Description
  const desc = createElement('p', {
    classes: ['panel-description'],
    text: description,
  });
  panel.appendChild(desc);

  // URL display
  const urlContainer = createElement('div', {
    classes: ['panel-url-container'],
  });

  const urlLabel = createElement('div', {
    classes: ['panel-url-label'],
    text: 'Target URL:',
  });

  const urlValue = createElement('div', {
    classes: ['panel-url'],
    text: url,
  });

  urlContainer.appendChild(urlLabel);
  urlContainer.appendChild(urlValue);
  panel.appendChild(urlContainer);

  // Reasons
  if (result.reasons.length > 0) {
    const reasonsContainer = createElement('div', {
      classes: ['panel-reasons-container'],
    });

    const reasonsTitle = createElement('h3', {
      classes: ['panel-reasons-title'],
      text: 'Why is this flagged?',
    });
    reasonsContainer.appendChild(reasonsTitle);

    const reasonsList = createElement('ul', {
      classes: ['panel-reasons'],
    });

    for (const reason of result.reasons) {
      const item = createElement('li', {
        text: reason,
      });
      reasonsList.appendChild(item);
    }

    reasonsContainer.appendChild(reasonsList);
    panel.appendChild(reasonsContainer);
  }

  // Actions - Only 2 buttons as requested
  const actionsContainer = createElement('div', {
    classes: ['panel-actions'],
  });

  // Continue with Safety — always opens in a new Incognito window
  const safeBtn = createActionButton(
    '🔒 Continue with Safety (Incognito)',
    'primary',
    () => handleAction({ type: 'OPEN_INCOGNITO', url })
  );

  // Continue Anyway button (Risk option)
  const riskBtn = createActionButton(
    '⚠️ Take Risk (Current Tab)',
    'danger',
    () => handleAction({ type: 'CONTINUE_ANYWAY', url })
  );

  actionsContainer.appendChild(safeBtn);
  actionsContainer.appendChild(riskBtn);
  panel.appendChild(actionsContainer);

  // Safe steps (Pareto - top recommended actions)
  const safeSteps = createSafeStepsSection(url);
  panel.appendChild(safeSteps);

  // Details section (initially hidden)
  const detailsSection = createDetailsSection(result);
  panel.appendChild(detailsSection);

  overlay.appendChild(panel);

  // Prevent click propagation
  panel.onclick = (e) => stopEvent(e);

  return overlay;
}

/**
 * Create action button
 */
function createActionButton(
  text: string,
  variant: 'primary' | 'secondary' | 'danger',
  onClick: () => void
): HTMLElement {
  const button = createElement('button', {
    classes: ['panel-button', `button-${variant}`],
    text,
  });
  button.onclick = onClick;
  return button;
}

/**
 * Create details section
 */
function createDetailsSection(result: RiskAnalysisResult): HTMLElement {
  const section = createElement('div', {
    classes: ['panel-details'],
    attributes: {
      'aria-hidden': 'true',
    },
  });
  section.style.display = 'none';

  const title = createElement('h3', {
    text: 'Extracted Features',
  });
  section.appendChild(title);

  const featuresList = createElement('dl', {
    classes: ['panel-features'],
  });

  const features = result.features;
  const featureEntries = [
    { label: 'URL Length', value: features.length },
    { label: 'Dot Count', value: features.dotCount },
    { label: 'Subdomain Count', value: features.subdomainCount },
    { label: 'Uses IP Address', value: features.hasIPAddress ? 'Yes' : 'No' },
    { label: 'Top-Level Domain', value: features.tld },
    { label: 'Protocol', value: features.protocol },
    { label: 'Path Depth', value: features.pathDepth },
    { label: 'Query Parameters', value: features.queryParamCount },
  ];

  for (const entry of featureEntries) {
    const dt = createElement('dt', { text: entry.label });
    const dd = createElement('dd', { text: String(entry.value) });
    featuresList.appendChild(dt);
    featuresList.appendChild(dd);
  }

  section.appendChild(featuresList);

  return section;
}

/**
 * Create prioritized safe steps section (Pareto: high-impact steps first)
 */
function createSafeStepsSection(url: string): HTMLElement {
  const container = createElement('div', {
    classes: ['panel-safe-steps'],
  });

  const title = createElement('h3', {
    text: '🛡️ How to open safely (most effective first)',
  });
  container.appendChild(title);

  const list = createElement('ol', { classes: ['panel-safe-list'] });

  // ── #1  Open in Incognito  (highest impact — automated) ────────────────
  const li1 = createElement('li', {
    text: 'Open in a private Incognito window — no cookies, history, or stored credentials are shared.',
  });
  const btn1 = createActionButton(
    '🔒 Open in Incognito',
    'secondary',
    () => handleAction({ type: 'OPEN_INCOGNITO', url })
  );
  li1.appendChild(btn1);
  list.appendChild(li1);

  // ── #2  Copy + sandbox  (high impact — manual) ──────────────────────────
  const li2 = createElement('li', {
    text: 'Copy the link and inspect it in a sandbox (VM, online analyser, or isolated profile) before visiting.',
  });
  const btn2 = createActionButton('📋 Copy Link', 'secondary', () => {
    try {
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(url);
      } else {
        const ta = document.createElement('textarea');
        ta.value = url;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      alert('✅ Link copied to clipboard.\n\nPaste it into a sandbox, VM, or analysis tool.');
    } catch (e) {
      alert('Unable to copy automatically.\nManually copy: ' + url);
    }
  });
  li2.appendChild(btn2);
  list.appendChild(li2);

  // ── #3  Analyse externally  (high impact — automated) ───────────────────
  const li3 = createElement('li', {
    text: 'Scan this link with an external threat-intelligence service before visiting it.',
  });
  const btnVT = createActionButton('🔍 VirusTotal', 'secondary', () => {
    const vtUrl = 'https://www.virustotal.com/gui/url/' + btoa(url).replace(/=/g, '') + '/detection';
    window.open(vtUrl, '_blank', 'noopener,noreferrer');
  });
  const btnUS = createActionButton('🔍 urlscan.io', 'secondary', () => {
    const scanUrl = 'https://urlscan.io/search/#page.domain:' + encodeURIComponent(new URL(url).hostname);
    window.open(scanUrl, '_blank', 'noopener,noreferrer');
  });
  li3.appendChild(btnVT);
  li3.appendChild(btnUS);
  list.appendChild(li3);

  // ── #4  Manual incognito tip  (medium impact — when button fails) ────────
  const li4 = createElement('li', {
    text: "If the Incognito button doesn't work: right-click the link → \"Open in Incognito/Private Window\", or copy it and use Ctrl+Shift+N (⌘+Shift+N on Mac) to open a new Incognito tab manually.",
  });
  list.appendChild(li4);

  container.appendChild(list);

  return container;
}

/**
 * Handle panel action
 */
function handleAction(action: PanelAction): void {
  if (action.type === 'VIEW_DETAILS') {
    // Toggle details visibility
    const panel = currentPanel;
    if (panel) {
      const detailsSection = panel.querySelector('.panel-details') as HTMLElement;
      if (detailsSection) {
        const isHidden = detailsSection.style.display === 'none';
        detailsSection.style.display = isHidden ? 'block' : 'none';
        detailsSection.setAttribute('aria-hidden', String(!isHidden));
      }
    }
    return;
  }

  if (action.type === 'OPEN_NEW_TAB' && action.url) {
    // Default: open in a normal new tab (keeps previous behavior for code paths that use OPEN_NEW_TAB)
    window.open(action.url, '_blank', 'noopener,noreferrer');
  }

  if (action.type === 'OPEN_INCOGNITO' && action.url) {
    // Send a message to the background worker to open an incognito window.
    // No fallback to a normal tab — the user explicitly asked for incognito.
    sendToBackground({ type: MESSAGE_TYPES.OPEN_INCOGNITO, payload: { url: action.url } })
      .then((res) => {
        if (!res.success) {
          alert(
            '⚠️ Could not open an Incognito window automatically.\n\n' +
            'To open this link in Incognito manually:\n' +
            '1. Copy the link using the "Copy Link" button.\n' +
            '2. Open a new Incognito window (Ctrl+Shift+N / ⌘+Shift+N).\n' +
            '3. Paste the link in the address bar and press Enter.\n\n' +
            'If the button never works, make sure the extension is allowed in Incognito:\n' +
            'chrome://extensions → this extension → Allow in Incognito.'
          );
        }
      })
      .catch(() => {
        alert(
          '⚠️ Could not open an Incognito window automatically.\n\n' +
          'To open this link in Incognito manually:\n' +
          '1. Copy the link using the "Copy Link" button.\n' +
          '2. Open a new Incognito window (Ctrl+Shift+N / ⌘+Shift+N).\n' +
          '3. Paste the link in the address bar and press Enter.\n\n' +
          'If the button never works, make sure the extension is allowed in Incognito:\n' +
          'chrome://extensions → this extension → Allow in Incognito.'
        );
      });
  }

  if (action.type === 'CONTINUE_ANYWAY' && action.url) {
    window.location.href = action.url;
  }

  // Resolve promise and remove panel
  if (panelResolve) {
    panelResolve(action);
  }
  removeSafetyPanel();
}
