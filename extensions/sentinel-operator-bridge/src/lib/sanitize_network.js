// Sentinel Operator Bridge - Network Metadata Sanitizer
// Faithful JS port of Python sanitize_network.py

import { NETWORK_ALLOWED_HEADERS } from './patterns.js';

/**
 * Sanitize URL by removing sensitive parts
 * @param {string} url - URL to sanitize
 * @returns {string} Sanitized URL
 */
export function sanitizeUrl(url) {
  try {
    const parsed = new URL(url);
    
    // Remove userinfo (username:password)
    parsed.username = '';
    parsed.password = '';
    
    // Remove fragment
    parsed.hash = '';
    
    // Remove query parameters
    parsed.search = '';
    
    return parsed.toString();
  } catch {
    // If URL parsing fails, return as-is
    return url;
  }
}

/**
 * Sanitize HTTP headers
 * @param {Object} headers - Headers object
 * @returns {Object} Sanitized headers
 */
export function sanitizeHeaders(headers) {
  const sanitized = {};
  
  for (const [name, value] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    
    // Only keep allowed headers
    if (NETWORK_ALLOWED_HEADERS.has(lowerName)) {
      // Remove sensitive values from certain headers
      if (lowerName === 'cookie' || lowerName === 'authorization' || 
          lowerName === 'set-cookie') {
        sanitized[name] = '[REDACTED]';
      } else {
        sanitized[name] = value;
      }
    }
  }
  
  return sanitized;
}

/**
 * Sanitize request metadata
 * @param {Object} request - Request object
 * @returns {Object} Sanitized request metadata
 */
export function sanitizeRequest(request) {
  return {
    method: request.method || '',
    url: request.url ? sanitizeUrl(request.url) : '',
    headers: request.headers ? sanitizeHeaders(request.headers) : {},
    // Drop body entirely
    body: null,
    bodySize: request.body ? request.body.length : 0
  };
}

/**
 * Sanitize response metadata
 * @param {Object} response - Response object
 * @returns {Object} Sanitized response metadata
 */
export function sanitizeResponse(response) {
  return {
    status: response.status || 0,
    statusText: response.statusText || '',
    url: response.url ? sanitizeUrl(response.url) : '',
    headers: response.headers ? sanitizeHeaders(response.headers) : {},
    // Drop body entirely
    body: null,
    bodySize: response.body ? response.body.length : 0
  };
}

/**
 * Sanitize network request/response pair
 * @param {Object} networkData - Network data to sanitize
 * @returns {Object} Sanitized network data
 */
export function sanitizeNetwork(networkData) {
  const {
    request,
    response,
    timing,
    ...rest
  } = networkData;
  
  return {
    request: request ? sanitizeRequest(request) : null,
    response: response ? sanitizeResponse(response) : null,
    timing: timing || null,
    ...rest
  };
}

export default {
  sanitizeUrl,
  sanitizeHeaders,
  sanitizeRequest,
  sanitizeResponse,
  sanitizeNetwork
};
