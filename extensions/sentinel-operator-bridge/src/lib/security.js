// Sentinel Operator Bridge - Security Module
// Strict sender validation and command allowlisting

/**
 * Allowed commands from the operator panel only
 * These are the ONLY commands that can be executed
 */
export const ALLOWED_COMMANDS = new Set([
  'read_page',
  'set_directive',
  'start_capture',
  'stop_capture',
  'get_capture',
  'screenshot',
  'sanitize_content',
  'sanitize_network',
  'ping',
  'arm',
  'disarm',
  'kill_switch'
]);

/**
 * State keys that need persistence
 */
export const STATE_KEYS = {
  ARMED: 'sentinel_armed',
  ARMED_UNTIL: 'sentinel_armedUntil',
  KILL_SWITCH: 'sentinel_killSwitch'
};

/**
 * Get the canonical panel URL
 * @returns {string}
 */
function getCanonicalPanelUrl() {
  return chrome.runtime.getURL('src/panel/panel.html');
}

/**
 * Strict sender validation: only messages from our own extension UI are trusted
 * @param {Object} sender - Message sender object
 * @returns {boolean}
 */
export function isOperatorSender(sender) {
  if (!sender || !sender.id || !sender.url) {
    return false;
  }
  
  // Must be from our extension
  if (sender.id !== chrome.runtime.id) {
    return false;
  }
  
  // Must be from the canonical panel URL
  const canonicalUrl = getCanonicalPanelUrl();
  
  // Handle URL comparison with query parameters
  // The panel URL might have query params, but the base must match
  const senderUrlObj = new URL(sender.url);
  const canonicalUrlObj = new URL(canonicalUrl);
  
  // Must have same protocol, host, and pathname
  if (senderUrlObj.protocol !== canonicalUrlObj.protocol ||
      senderUrlObj.host !== canonicalUrlObj.host ||
      senderUrlObj.pathname !== canonicalUrlObj.pathname) {
    return false;
  }
  
  return true;
}

/**
 * Validate a command message
 * @param {Object} message - The message to validate
 * @returns {Object} - { valid: boolean, error?: string, command?: string }
 */
export function validateCommandMessage(message) {
  if (!message || typeof message !== 'object') {
    return { valid: false, error: 'Message must be an object' };
  }
  
  // Ping messages don't need a command
  if (message.type === 'ping') {
    return { valid: true, command: 'ping' };
  }
  
  const { command } = message;
  
  if (!command || typeof command !== 'string') {
    return { valid: false, error: 'Message must have a string command field' };
  }
  
  if (!ALLOWED_COMMANDS.has(command)) {
    return { 
      valid: false, 
      error: `Command '${command}' not in allowlist`,
      command 
    };
  }
  
  return { valid: true, command };
}

/**
 * Create a fail-closed response
 * @param {string} error - Error message
 * @returns {Object}
 */
export function createFailClosedResponse(error) {
  return { error, allowed: false };
}

/**
 * Initialize security state from storage
 * @returns {Promise<Object>}
 */
export async function initSecurityState() {
  const result = await chrome.storage.session.get([
    STATE_KEYS.ARMED,
    STATE_KEYS.ARMED_UNTIL,
    STATE_KEYS.KILL_SWITCH
  ]);
  
  return {
    armed: result[STATE_KEYS.ARMED] || false,
    armedUntil: result[STATE_KEYS.ARMED_UNTIL] || 0,
    killSwitch: result[STATE_KEYS.KILL_SWITCH] || false
  };
}

/**
 * Persist security state
 * @param {Object} state - State to persist
 * @returns {Promise<void>}
 */
export async function persistSecurityState(state) {
  await chrome.storage.session.set({
    [STATE_KEYS.ARMED]: state.armed,
    [STATE_KEYS.ARMED_UNTIL]: state.armedUntil,
    [STATE_KEYS.KILL_SWITCH]: state.killSwitch
  });
}

/**
 * Check if extension is currently armed
 * @param {Object} state - Current state
 * @returns {boolean}
 */
export function isArmed(state) {
  if (!state.armed) return false;
  
  // Check if armedUntil has expired
  if (state.armedUntil && Date.now() > state.armedUntil) {
    return false;
  }
  
  return true;
}
