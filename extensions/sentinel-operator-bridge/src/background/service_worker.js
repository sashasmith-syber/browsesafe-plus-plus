// Sentinel Operator Bridge - Service Worker
// Enforcement point for operator-only command gate

import { sanitizeContent, sanitizeText } from '../lib/sanitize_content.js';
import { sanitizeNetwork } from '../lib/sanitize_network.js';

/**
 * Allowed commands from the operator panel only
 */
const ALLOWED_COMMANDS = new Set([
  'read_page',
  'set_directive',
  'start_capture',
  'stop_capture',
  'get_capture',
  'screenshot',
  'sanitize_content',
  'sanitize_network'
]);

/**
 * Exact URL of the operator panel page. The side panel is the ONLY origin
 * trusted to issue commands; matched exactly, never by substring.
 */
const PANEL_URL = chrome.runtime.getURL('src/panel/panel.html');

/**
 * Persistent state - survives MV3 service worker termination.
 * chrome.storage.session is memory-backed and cleared when the browser
 * session ends; it never syncs and never persists beyond the profile.
 */
const DEFAULT_STATE = {
  captureActive: false,
  capturedContent: [],
  directives: [],
  currentTab: null
};

async function getState() {
  const { bridgeState } = await chrome.storage.session.get('bridgeState');
  return bridgeState ?? { ...DEFAULT_STATE };
}

async function setState(patch) {
  const merged = { ...(await getState()), ...patch };
  await chrome.storage.session.set({ bridgeState: merged });
  return merged;
}

/**
 * Check if sender is from a tab (page context) - untrusted
 * @param {Object} sender - Message sender
 * @returns {boolean}
 */
function isFromTab(sender) {
  return sender.tab && sender.tab.id !== undefined;
}

/**
 * Check if sender is the side panel (operator) - trusted.
 * Exact URL match: substring checks are spoofable by any extension page
 * whose URL merely contains the needle string.
 * @param {Object} sender - Message sender
 * @returns {boolean}
 */
function isFromPanel(sender) {
  return sender.url === PANEL_URL;
}

/**
 * Validate command is allowed
 * @param {string} command - Command to validate
 * @returns {boolean}
 */
function isAllowedCommand(command) {
  return ALLOWED_COMMANDS.has(command);
}

/**
 * Handle messages from content scripts (data only, never commands)
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Any message from a tab is treated as DATA, never a command
  if (isFromTab(sender)) {
    // Sanitize all content from tabs
    if (message.type === 'page_content') {
      const sanitized = sanitizeContent(message.data);

      // Store if capture is active (async: state lives in chrome.storage.session)
      (async () => {
        const s = await getState();
        if (s.captureActive && s.currentTab === sender.tab.id) {
          await setState({
            capturedContent: [
              ...s.capturedContent,
              {
                tabId: sender.tab.id,
                url: sender.tab.url,
                timestamp: Date.now(),
                ...sanitized
              }
            ]
          });
        }
        sendResponse({
          type: 'sanitized_content',
          data: sanitized,
          fromTab: true
        });
      })();
      return true; // async response
    }

    if (message.type === 'network_request') {
      const sanitized = sanitizeNetwork(message.data);
      sendResponse({
        type: 'sanitized_network',
        data: sanitized,
        fromTab: true
      });
      return;
    }

    // Any other message from tab is ignored (security)
    sendResponse({ error: 'Messages from tabs are data-only' });
    return;
  }

  // Handle messages from the panel (operator) - the ONLY command source.
  // The old '|| !sender.tab' fallback trusted any non-tab sender; removed.
  if (isFromPanel(sender)) {
    const { command, data } = message;

    // Validate command is in allowlist
    if (!isAllowedCommand(command)) {
      sendResponse({ error: `Command '${command}' not allowed` });
      return;
    }

    // Execute command
    handleCommand(command, data, sendResponse);
    return true; // Keep message channel open for async response
  }

  // Unknown sender - reject
  sendResponse({ error: 'Unknown sender' });
});

/**
 * Handle operator commands
 */
async function handleCommand(command, data, sendResponse) {
  try {
    switch (command) {
      case 'read_page': {
        // Read page content from current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
          sendResponse({ error: 'No active tab' });
          return;
        }

        await setState({ currentTab: tab.id });

        const result = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => document.documentElement.outerHTML
        });

        if (result && result[0] && result[0].result) {
          const sanitized = sanitizeContent(result[0].result);
          sendResponse({ data: sanitized });
        } else {
          sendResponse({ error: 'Failed to read page' });
        }
        break;
      }

      case 'set_directive': {
        if (typeof data !== 'string') {
          sendResponse({ error: 'Directive must be a string' });
          return;
        }
        // Sanitize directive text
        const sanitized = sanitizeText(data);
        if (sanitized.verdict !== 'SAFE') {
          sendResponse({ error: 'Directive contains unsafe content', findings: sanitized.findings });
          return;
        }
        const s = await getState();
        const directives = [...s.directives, { text: sanitized.text, timestamp: Date.now() }];
        await setState({ directives });
        sendResponse({ success: true, directives });
        break;
      }

      case 'start_capture':
        await setState({ captureActive: true, capturedContent: [] });
        sendResponse({ success: true, message: 'Capture started' });
        break;

      case 'stop_capture': {
        const s = await setState({ captureActive: false });
        sendResponse({
          success: true,
          message: 'Capture stopped',
          capturedCount: s.capturedContent.length
        });
        break;
      }

      case 'get_capture': {
        const s = await getState();
        sendResponse({
          success: true,
          content: s.capturedContent,
          active: s.captureActive
        });
        break;
      }

      case 'screenshot': {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!activeTab) {
          sendResponse({ error: 'No active tab' });
          return;
        }

        const screenshot = await chrome.tabs.captureVisibleTab(null, {
          format: 'png',
          quality: 80
        });

        sendResponse({ success: true, screenshot });
        break;
      }

      case 'sanitize_content': {
        const sanitizedContent = sanitizeContent(data);
        sendResponse({ data: sanitizedContent });
        break;
      }

      case 'sanitize_network': {
        const sanitizedNetwork = sanitizeNetwork(data);
        sendResponse({ data: sanitizedNetwork });
        break;
      }

      default:
        sendResponse({ error: `Unknown command: ${command}` });
    }
  } catch (error) {
    console.error('Command execution error:', error);
    sendResponse({ error: error.message });
  }
}

// Initialize
console.log('Sentinel Operator Bridge service worker loaded');
