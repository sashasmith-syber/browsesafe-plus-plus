// Sentinel Operator Bridge - Content Script
// Data-only content script with no action capabilities

/**
 * This content script can only SEND data to the service worker.
 * It has NO ability to:
 * - Click elements
 * - Fill forms
 * - Navigate
 * - Execute scripts
 * - Modify the DOM
 * 
 * It only reads and sanitizes content, then sends it to the service worker.
 */

// Listen for messages from the service worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // This content script does not execute commands
  // It only responds to data requests
  
  if (message.type === 'get_page_content') {
    const html = document.documentElement.outerHTML;
    
    // Send raw HTML to service worker for sanitization
    sendResponse({
      type: 'page_content',
      data: html,
      url: window.location.href
    });
    return;
  }
  
  // Any other message type is ignored
  sendResponse({ error: 'Unknown message type' });
});

// Observe DOM changes and report significant modifications
const observer = new MutationObserver((mutations) => {
  // Only report if there are many mutations (potential injection)
  if (mutations.length > 50) {
    chrome.runtime.sendMessage({
      type: 'dom_mutation',
      count: mutations.length,
      url: window.location.href
    });
  }
});

// Start observing the document body
observer.observe(document.body, {
  childList: true,
  subtree: true,
  attributes: true,
  characterData: true
});

// Report page load
chrome.runtime.sendMessage({
  type: 'page_loaded',
  url: window.location.href,
  title: document.title
});

console.log('Sentinel Operator Bridge content script loaded');
