// Sentinel Operator Bridge - Service Worker
// Enforcement point for operator-only command gate
// Strict fail-closed security: only extension UI can invoke commands

import { sanitizeContent, sanitizeText } from '../lib/sanitize_content.js';
import { sanitizeNetwork } from '../lib/sanitize_network.js';
import {
  ALLOWED_COMMANDS,
  isOperatorSender,
  validateCommandMessage,
  createFailClosedResponse,
  initSecurityState,
  persistSecurityState,
  isArmed,
  STATE_KEYS
} from '../lib/security.js';
import { logAuditEvent, REDACTED } from '../lib/audit_log.js';

/**
 * State management - persisted in chrome.storage.session
 * Service workers sleep after ~30s inactivity, so globals are lost
 */
let state = {
  captureActive: false,
  capturedContent: [],
  directives: [],
  currentTab: null,
  armed: false,
  armedUntil: 0,
  killSwitch: false
};

// AbortController for in-flight work
let abortController = null;

/**
 * Hydrate state from storage on worker wake
 */
async function hydrateState() {
  try {
    const stored = await initSecurityState();
    state.armed = stored.armed || false;
    state.armedUntil = stored.armedUntil || 0;
    state.killSwitch = stored.killSwitch || false;
    
    // Clear expired armed state
    if (state.armed && Date.now() > state.armedUntil) {
      state.armed = false;
      state.armedUntil = 0;
      await persistSecurityState({
        armed: false,
        armedUntil: 0,
        killSwitch: state.killSwitch
      });
    }
    
    console.log('Sentinel: State hydrated from storage');
  } catch (error) {
    console.error('Sentinel: State hydration error:', error);
    // Fail-closed: start with disarmed state
    state.armed = false;
    state.armedUntil = 0;
    state.killSwitch = false;
  }
}

/**
 * Persist security state
 */
async function saveState() {
  try {
    await persistSecurityState({
      armed: state.armed,
      armedUntil: state.armedUntil,
      killSwitch: state.killSwitch
    });
  } catch (error) {
    console.error('Sentinel: State persistence error:', error);
  }
}

/**
 * Check if extension is currently armed and not killed
 * @returns {boolean}
 */
function checkArmed() {
  // Check kill switch first
  if (state.killSwitch) {
    return false;
  }
  
  // Check armed state with timeout
  if (!state.armed) {
    return false;
  }
  
  if (state.armedUntil && Date.now() > state.armedUntil) {
    state.armed = false;
    state.armedUntil = 0;
    saveState();
    return false;
  }
  
  return true;
}

/**
 * Abort all in-flight work
 */
function abortInFlightWork() {
  if (abortController) {
    abortController.abort();
    abortController = null;
  }
}

/**
 * Handle messages with strict validation
 */
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  // Hydrate state on every message (worker may have slept)
  await hydrateState();
  
  // ALWAYS validate sender first - fail closed
  if (!isOperatorSender(sender)) {
    await logAuditEvent({
      type: 'message',
      action: 'REJECTED',
      reason: 'Unauthorized sender',
      senderId: sender?.id,
      senderUrl: sender?.url,
      timestamp: Date.now()
    });
    
    sendResponse(createFailClosedResponse('Unauthorized sender'));
    return;
  }
  
  // Validate message structure and command
  const validation = validateCommandMessage(message);
  
  if (!validation.valid) {
    await logAuditEvent({
      type: 'message',
      action: 'REJECTED',
      reason: validation.error,
      command: validation.command,
      timestamp: Date.now()
    });
    
    sendResponse(createFailClosedResponse(validation.error));
    return;
  }
  
  // Handle ping separately
  if (validation.command === 'ping') {
    sendResponse({ type: 'pong', status: 'ready' });
    return;
  }
  
  // Check kill switch before any command
  if (state.killSwitch) {
    await logAuditEvent({
      type: 'kill_switch',
      action: 'BLOCKED',
      command: validation.command,
      timestamp: Date.now()
    });
    
    sendResponse(createFailClosedResponse('Kill switch engaged - all actions blocked'));
    return;
  }
  
  // Check if armed (for dangerous commands)
  const requiresArmed = ['read_page', 'set_directive', 'start_capture', 'screenshot'];
  if (requiresArmed.includes(validation.command) && !checkArmed()) {
    await logAuditEvent({
      type: 'command',
      action: 'BLOCKED',
      reason: 'Not armed',
      command: validation.command,
      timestamp: Date.now()
    });
    
    sendResponse(createFailClosedResponse('Extension not armed - use arm command first'));
    return;
  }
  
  // Execute command
  try {
    const result = await handleCommand(validation.command, message.data, sendResponse);
    
    await logAuditEvent({
      type: 'command',
      action: 'ALLOWED',
      command: validation.command,
      timestamp: Date.now()
    });
    
    return result;
  } catch (error) {
    console.error('Sentinel: Command execution error:', error);
    
    await logAuditEvent({
      type: 'command',
      action: 'ERROR',
      command: validation.command,
      error: REDACTED(error.message),
      timestamp: Date.now()
    });
    
    sendResponse(createFailClosedResponse(error.message));
  }
});

/**
 * Handle operator commands
 */
async function handleCommand(command, data, sendResponse) {
  try {
    switch (command) {
      case 'arm':
        state.armed = true;
        state.armedUntil = Date.now() + (data?.duration || 300000); // Default 5 minutes
        await saveState();
        
        sendResponse({
          success: true,
          armed: true,
          armedUntil: state.armedUntil
        });
        break;
        
      case 'disarm':
        state.armed = false;
        state.armedUntil = 0;
        await saveState();
        
        // Abort any in-flight work
        abortInFlightWork();
        
        sendResponse({ success: true, armed: false });
        break;
        
      case 'kill_switch':
        state.killSwitch = true;
        state.armed = false;
        state.armedUntil = 0;
        await saveState();
        
        // Abort all in-flight work
        abortInFlightWork();
        
        await logAuditEvent({
          type: 'kill_switch',
          action: 'ENGAGED',
          timestamp: Date.now()
        });
        
        sendResponse({ success: true, killSwitch: true });
        break;
        
      case 'read_page':
        // Re-verify tab using lastFocusedWindow
        const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (!tab) {
          sendResponse({ error: 'No active tab' });
          return;
        }
        
        state.currentTab = tab.id;
        
        // Inject content script on-demand
        const result = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ['src/content/content_script.js']
        });
        
        if (result && result[0] && result[0].result) {
          const sanitized = sanitizeContent(result[0].result);
          sendResponse({ data: sanitized });
        } else {
          // Fallback: try to read directly
          const directResult = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => document.documentElement.outerHTML
          });
          
          if (directResult && directResult[0] && directResult[0].result) {
            const sanitized = sanitizeContent(directResult[0].result);
            sendResponse({ data: sanitized });
          } else {
            sendResponse({ error: 'Failed to read page' });
          }
        }
        break;
        
      case 'set_directive':
        if (typeof data === 'string') {
          const sanitized = sanitizeText(data);
          if (sanitized.verdict === 'SAFE') {
            state.directives.push({
              text: sanitized.text,
              timestamp: Date.now()
            });
            sendResponse({ success: true, directives: state.directives });
          } else {
            sendResponse({ 
              error: 'Directive contains unsafe content', 
              findings: sanitized.findings 
            });
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
        const [activeTab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
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
        sendResponse(createFailClosedResponse(`Unknown command: ${command}`));
    }
    return true; // Keep message channel open for async response
  } catch (error) {
    console.error('Command execution error:', error);
    throw error;
  }
}

// Initialize
console.log('Sentinel Operator Bridge service worker loaded');

// Hydrate state on startup
hydrateState().catch(err => {
  console.error('Sentinel: Initial hydration error:', err);
});
