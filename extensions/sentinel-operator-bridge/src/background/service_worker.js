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
 * State management
 */
let state = {
  captureActive: false,
  capturedContent: [],
  directives: [],
  currentTab: null
};

/**
 * Check if sender is from a tab (page context) - untrusted
 * @param {Object} sender - Message sender
 * @returns {boolean}
 */
function isFromTab(sender) {
  return sender.tab && sender.tab.id !== undefined;
}

/**
 * Check if sender is from the side panel (operator) - trusted
 * @param {Object} sender - Message sender
 * @returns {boolean}
 */
function isFromPanel(sender) {
  return sender.url && sender.url.includes('sidepanel.html');
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
      
      // Store if capture is active
      if (state.captureActive && state.currentTab === sender.tab.id) {
        state.capturedContent.push({
          tabId: sender.tab.id,
          url: sender.tab.url,
          timestamp: Date.now(),
          ...sanitized
        });
      }
      
      sendResponse({
        type: 'sanitized_content',
        data: sanitized,
        fromTab: true
      });
      return;
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
  
  // Handle messages from panel (operator)
  if (isFromPanel(sender) || !sender.tab) {
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
      case 'read_page':
        // Read page content from current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
          sendResponse({ error: 'No active tab' });
          return;
        }
        
        state.currentTab = tab.id;
        
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
        
      case 'set_directive':
        if (typeof data === 'string') {
          // Sanitize directive text
          const sanitized = sanitizeText(data);
          if (sanitized.verdict === 'SAFE') {
            state.directives.push({
              text: sanitized.text,
              timestamp: Date.now()
            });
            sendResponse({ success: true, directives: state.directives });
          } else {
            sendResponse({ error: 'Directive contains unsafe content', findings: sanitized.findings });
          }
        } else {
          sendResponse({ error: 'Directive must be a string' });
        }
        break;
        
      case 'start_capture':
        state.captureActive = true;
        state.capturedContent = [];
        sendResponse({ success: true, message: 'Capture started' });
        break;
        
      case 'stop_capture':
        state.captureActive = false;
        sendResponse({ 
          success: true, 
          message: 'Capture stopped',
          capturedCount: state.capturedContent.length
        });
        break;
        
      case 'get_capture':
        sendResponse({ 
          success: true,
          content: state.capturedContent,
          active: state.captureActive
        });
        break;
        
      case 'screenshot':
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
        
      case 'sanitize_content':
        const sanitizedContent = sanitizeContent(data);
        sendResponse({ data: sanitizedContent });
        break;
        
      case 'sanitize_network':
        const sanitizedNetwork = sanitizeNetwork(data);
        sendResponse({ data: sanitizedNetwork });
        break;
        
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
