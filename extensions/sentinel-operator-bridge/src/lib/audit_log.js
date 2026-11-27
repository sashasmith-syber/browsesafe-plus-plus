// Sentinel Operator Bridge - Audit Log Module
// Append-only, local, exportable audit logging with secret redaction

import { redactSecretsInText } from './sanitize_content.js';

/**
 * Maximum number of audit log entries
 */
const MAX_ENTRIES = 1000;

/**
 * Storage key for audit log
 */
const STORAGE_KEY = 'sentinel_audit_log';

/**
 * Secret redaction placeholder
 */
export const REDACTED = '[REDACTED]';

/**
 * Recursively redact secrets from an object
 * @param {any} obj - Object to redact
 * @returns {any}
 */
function deepRedact(obj) {
  if (obj === null || obj === undefined) {
    return obj;
  }
  
  if (typeof obj === 'string') {
    return redactSecretsInText(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(deepRedact);
  }
  
  if (typeof obj === 'object') {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      // Redact sensitive keys (exact match or starts with)
      const lowerKey = key.toLowerCase();
      const sensitiveKeywords = ['key', 'token', 'password', 'secret', 'credential', 'auth'];
      const isSensitive = sensitiveKeywords.some(kw => 
        lowerKey === kw || 
        lowerKey.startsWith(kw + '_') || 
        lowerKey.endsWith('_' + kw) ||
        (kw === 'key' && (lowerKey === 'api_key' || lowerKey === 'apikey' || lowerKey === 'api-key'))
      );
      
      if (isSensitive) {
        result[key] = REDACTED;
      } else {
        result[key] = deepRedact(value);
      }
    }
    return result;
  }
  
  return obj;
}

/**
 * Log an audit event
 * @param {Object} event - Event to log
 * @param {string} event.type - Event type
 * @param {string} event.action - Action performed
 * @param {string} [event.command] - Command name
 * @param {string} [event.reason] - Reason for action
 * @param {string} [event.error] - Error message
 * @param {number} [event.timestamp] - Timestamp
 * @param {Object} [event.metadata] - Additional metadata
 * @returns {Promise<void>}
 */
export async function logAuditEvent(event) {
  try {
    // Create safe event with redacted data
    const safeEvent = {
      type: event.type || 'unknown',
      action: event.action || 'unknown',
      command: event.command,
      reason: event.reason,
      error: event.error ? REDACTED : undefined,
      timestamp: event.timestamp || Date.now(),
      metadata: event.metadata
    };
    
    // Deep redact all string values
    const redactedEvent = deepRedact(safeEvent);
    
    // Get existing log
    const result = await chrome.storage.local.get([STORAGE_KEY]);
    const log = result[STORAGE_KEY] || [];
    
    // Add new entry
    log.push(redactedEvent);
    
    // Rotate if over limit
    if (log.length > MAX_ENTRIES) {
      log.shift(); // Remove oldest entry
    }
    
    // Save
    await chrome.storage.local.set({ [STORAGE_KEY]: log });
    
    // Also log to console for debugging
    console.log('Sentinel Audit:', redactedEvent);
  } catch (error) {
    console.error('Sentinel: Audit log error:', error);
  }
}

/**
 * Get all audit log entries
 * @returns {Promise<Array>}
 */
export async function getAuditLog() {
  try {
    const result = await chrome.storage.local.get([STORAGE_KEY]);
    return result[STORAGE_KEY] || [];
  } catch (error) {
    console.error('Sentinel: Error reading audit log:', error);
    return [];
  }
}

/**
 * Get filtered audit log entries
 * @param {Object} filter - Filter criteria
 * @param {string} [filter.type] - Event type
 * @param {string} [filter.action] - Action
 * @param {string} [filter.command] - Command
 * @returns {Promise<Array>}
 */
export async function getFilteredAuditLog(filter = {}) {
  const log = await getAuditLog();
  
  return log.filter(entry => {
    if (filter.type && entry.type !== filter.type) return false;
    if (filter.action && entry.action !== filter.action) return false;
    if (filter.command && entry.command !== filter.command) return false;
    return true;
  });
}

/**
 * Export audit log as JSON
 * @returns {Promise<string>}
 */
export async function exportAuditLog() {
  const log = await getAuditLog();
  return JSON.stringify(log, null, 2);
}

/**
 * Clear audit log
 * @returns {Promise<void>}
 */
export async function clearAuditLog() {
  await chrome.storage.local.set({ [STORAGE_KEY]: [] });
}

/**
 * Get audit log statistics
 * @returns {Promise<Object>}
 */
export async function getAuditStats() {
  const log = await getAuditLog();
  
  const stats = {
    total: log.length,
    byType: {},
    byAction: {},
    recent: []
  };
  
  for (const entry of log) {
    stats.byType[entry.type] = (stats.byType[entry.type] || 0) + 1;
    stats.byAction[entry.action] = (stats.byAction[entry.action] || 0) + 1;
  }
  
  // Get last 10 entries
  stats.recent = log.slice(-10);
  
  return stats;
}
