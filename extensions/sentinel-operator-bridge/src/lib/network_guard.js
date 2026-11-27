// Sentinel Operator Bridge - Network Guard Module
// Data-exfiltration protection via allowlist enforcement

/**
 * Default allowlisted domains for outbound requests
 * Only localhost and 127.0.0.1 are allowed by default
 */
const DEFAULT_ALLOWLIST = [
  'http://localhost:11434',
  'http://127.0.0.1:11434',
  'https://localhost:11434',
  'https://127.0.0.1:11434'
];

/**
 * Storage key for custom allowlist
 */
const ALLOWLIST_KEY = 'sentinel_network_allowlist';

/**
 * Get the current allowlist
 * @returns {Promise<Array>}
 */
async function getAllowlist() {
  try {
    const result = await chrome.storage.local.get([ALLOWLIST_KEY]);
    const custom = result[ALLOWLIST_KEY] || [];
    return [...DEFAULT_ALLOWLIST, ...custom];
  } catch (error) {
    console.error('Sentinel: Error reading network allowlist:', error);
    return DEFAULT_ALLOWLIST;
  }
}

/**
 * Check if a URL is in the allowlist
 * @param {string} url - URL to check
 * @returns {Promise<boolean>}
 */
async function isUrlAllowed(url) {
  try {
    const allowlist = await getAllowlist();
    
    // Check exact matches
    if (allowlist.includes(url)) {
      return true;
    }
    
    // Check if URL starts with any allowlisted entry
    for (const allowed of allowlist) {
      if (url.startsWith(allowed)) {
        return true;
      }
    }
    
    return false;
  } catch (error) {
    console.error('Sentinel: Error checking URL allowlist:', error);
    return false;
  }
}

/**
 * Safe fetch wrapper that enforces allowlist
 * @param {string} url - URL to fetch
 * @param {Object} [options] - Fetch options
 * @returns {Promise<Response>}
 */
export async function safeFetch(url, options = {}) {
  // Parse URL for validation
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    throw new Error(`Invalid URL: ${REDACTED(url)}`);
  }
  
  // Check allowlist
  const isAllowed = await isUrlAllowed(url);
  
  if (!isAllowed) {
    throw new Error(`Request blocked: URL not in allowlist - ${REDACTED(url)}`);
  }
  
  // Validate protocol
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error(`Request blocked: Invalid protocol - ${REDACTED(parsedUrl.protocol)}`);
  }
  
  // Add credentials: 'omit' to prevent sending cookies/auth headers
  const safeOptions = {
    ...options,
    credentials: 'omit'
  };
  
  try {
    const response = await fetch(url, safeOptions);
    
    // Check for network errors
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${REDACTED(response.statusText)}`);
    }
    
    return response;
  } catch (error) {
    // Wrap network errors
    throw new Error(`Network request failed: ${REDACTED(error.message)}`);
  }
}

/**
 * Add a domain to the allowlist
 * @param {string} url - URL or domain to allow
 * @returns {Promise<void>}
 */
export async function addToAllowlist(url) {
  try {
    const result = await chrome.storage.local.get([ALLOWLIST_KEY]);
    const allowlist = result[ALLOWLIST_KEY] || [];
    
    // Normalize URL
    let normalized = url.trim();
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = `https://${normalized}`;
    }
    
    // Remove trailing slash
    normalized = normalized.replace(/\/$/, '');
    
    if (!allowlist.includes(normalized)) {
      allowlist.push(normalized);
      await chrome.storage.local.set({ [ALLOWLIST_KEY]: allowlist });
    }
  } catch (error) {
    console.error('Sentinel: Error adding to allowlist:', error);
    throw error;
  }
}

/**
 * Remove a domain from the allowlist
 * @param {string} url - URL or domain to remove
 * @returns {Promise<void>}
 */
export async function removeFromAllowlist(url) {
  try {
    const result = await chrome.storage.local.get([ALLOWLIST_KEY]);
    let allowlist = result[ALLOWLIST_KEY] || [];
    
    // Normalize URL
    let normalized = url.trim();
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = `https://${normalized}`;
    }
    normalized = normalized.replace(/\/$/, '');
    
    allowlist = allowlist.filter(item => item !== normalized);
    await chrome.storage.local.set({ [ALLOWLIST_KEY]: allowlist });
  } catch (error) {
    console.error('Sentinel: Error removing from allowlist:', error);
    throw error;
  }
}

/**
 * Get the current allowlist
 * @returns {Promise<Array>}
 */
export async function getCurrentAllowlist() {
  return await getAllowlist();
}

/**
 * Secret redaction placeholder
 */
export const REDACTED = '[REDACTED]';
