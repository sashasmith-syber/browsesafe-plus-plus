// Sentinel Operator Bridge - Panel Script
// Only trusted input surface with paste-fencing and textContent-only rendering

import { sanitizeText } from '../lib/sanitize_content.js';

/**
 * DOM elements
 */
const elements = {
  command: document.getElementById('command'),
  dataGroup: document.getElementById('data-group'),
  dataInput: document.getElementById('data-input'),
  pasteBtn: document.getElementById('paste-btn'),
  executeBtn: document.getElementById('execute-btn'),
  output: document.getElementById('output'),
  clearBtn: document.getElementById('clear-btn'),
  swStatus: document.getElementById('sw-status'),
  captureStatus: document.getElementById('capture-status'),
  capturedCount: document.getElementById('captured-count'),
  directivesList: document.getElementById('directives-list')
};

/**
 * State
 */
let state = {
  captureActive: false,
  capturedCount: 0,
  directives: []
};

/**
 * Commands that require data input
 */
const DATA_COMMANDS = new Set(['set_directive', 'sanitize_content', 'sanitize_network']);

/**
 * Initialize the panel
 */
function init() {
  // Check service worker status
  checkServiceWorker();
  
  // Setup event listeners
  setupEventListeners();
  
  // Update UI based on command selection
  updateDataGroupVisibility();
  
  // Load saved state
  loadState();
  
  console.log('Sentinel Operator Bridge panel initialized');
}

/**
 * Check if service worker is running
 */
function checkServiceWorker() {
  // Try to ping the service worker
  chrome.runtime.sendMessage({ type: 'ping' }, (response) => {
    if (chrome.runtime.lastError) {
      elements.swStatus.textContent = 'Not responding';
      elements.swStatus.style.color = '#f44336';
    } else {
      elements.swStatus.textContent = 'Active';
      elements.swStatus.style.color = '#4CAF50';
    }
  });
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  // Command selection change
  elements.command.addEventListener('change', () => {
    updateDataGroupVisibility();
    updateExecuteButton();
  });
  
  // Data input change
  elements.dataInput.addEventListener('input', updateExecuteButton);
  
  // Paste button
  elements.pasteBtn.addEventListener('click', handlePaste);
  
  // Execute button
  elements.executeBtn.addEventListener('click', executeCommand);
  
  // Clear button
  elements.clearBtn.addEventListener('click', () => {
    elements.output.textContent = '';
  });
  
  // Listen for messages from service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Handle state updates
    if (message.type === 'state_update') {
      updateState(message.state);
    }
  });
}

/**
 * Update data group visibility based on selected command
 */
function updateDataGroupVisibility() {
  const selectedCommand = elements.command.value;
  const needsData = DATA_COMMANDS.has(selectedCommand);
  elements.dataGroup.style.display = needsData ? 'block' : 'none';
}

/**
 * Update execute button state
 */
function updateExecuteButton() {
  const selectedCommand = elements.command.value;
  const needsData = DATA_COMMANDS.has(selectedCommand);
  
  if (!selectedCommand) {
    elements.executeBtn.disabled = true;
    return;
  }
  
  if (needsData) {
    elements.executeBtn.disabled = !elements.dataInput.value.trim();
  } else {
    elements.executeBtn.disabled = false;
  }
}

/**
 * Handle paste with sanitization (paste-fencing)
 */
async function handlePaste() {
  try {
    const clipboardText = await navigator.clipboard.readText();
    
    // Sanitize pasted text
    const sanitized = sanitizeText(clipboardText);
    
    if (sanitized.verdict === 'UNSAFE') {
      // Refuse outright if it carries injection findings
      appendOutput(`⚠️ PASTE BLOCKED: Unsafe content detected (${JSON.stringify(sanitized.findings)})`, 'error');
      return;
    }
    
    // Wrap in paste fence markers
    const fencedText = `⟦DATA⟧${sanitized.text}⟦/DATA⟧`;
    
    // Insert at cursor position or replace selection
    const start = elements.dataInput.selectionStart;
    const end = elements.dataInput.selectionEnd;
    const currentValue = elements.dataInput.value;
    
    elements.dataInput.value = currentValue.substring(0, start) + fencedText + currentValue.substring(end);
    elements.dataInput.selectionStart = start + fencedText.length;
    elements.dataInput.selectionEnd = start + fencedText.length;
    
    appendOutput(`✓ Paste sanitized and fenced`, 'success');
    updateExecuteButton();
    
  } catch (error) {
    appendOutput(`✗ Paste failed: ${error.message}`, 'error');
  }
}

/**
 * Execute selected command
 */
async function executeCommand() {
  const command = elements.command.value;
  const data = elements.dataInput.value;
  
  if (!command) {
    appendOutput('⚠️ Please select a command', 'error');
    return;
  }
  
  // Prepare message
  const message = { command };
  
  // Add data if needed
  if (DATA_COMMANDS.has(command)) {
    message.data = data;
  }
  
  // Clear output
  elements.output.textContent = '';
  
  // Show loading state
  appendOutput(`Executing: ${command}...`, 'info');
  
  try {
    // Send message to service worker
    const response = await chrome.runtime.sendMessage(message);
    
    if (chrome.runtime.lastError) {
      throw new Error(chrome.runtime.lastError.message);
    }
    
    if (response.error) {
      appendOutput(`✗ Error: ${response.error}`, 'error');
      return;
    }
    
    // Handle response
    handleResponse(command, response);
    
  } catch (error) {
    appendOutput(`✗ Command failed: ${error.message}`, 'error');
  }
}

/**
 * Handle command response
 */
function handleResponse(command, response) {
  switch (command) {
    case 'read_page':
      appendOutput('✓ Page read successfully', 'success');
      if (response.data) {
        appendOutput(`Verdict: ${response.data.verdict}`, 'info');
        if (response.data.findings.droppedTags.size > 0) {
          appendOutput(`Dropped tags: ${Array.from(response.data.findings.droppedTags).join(', ')}`, 'warning');
        }
        if (response.data.findings.injectionSpans.length > 0) {
          appendOutput(`Injection spans found: ${response.data.findings.injectionSpans.length}`, 'warning');
        }
      }
      break;
      
    case 'set_directive':
      appendOutput('✓ Directive set', 'success');
      if (response.directives) {
        updateDirectives(response.directives);
      }
      break;
      
    case 'start_capture':
      appendOutput('✓ Capture started', 'success');
      state.captureActive = true;
      updateStatus();
      break;
      
    case 'stop_capture':
      appendOutput(`✓ Capture stopped (${response.capturedCount || 0} items)`, 'success');
      state.captureActive = false;
      state.capturedCount = response.capturedCount || 0;
      updateStatus();
      break;
      
    case 'get_capture':
      appendOutput(`✓ Retrieved ${response.content?.length || 0} captured items`, 'success');
      if (response.content && response.content.length > 0) {
        response.content.forEach((item, index) => {
          appendOutput(`--- Item ${index + 1} ---`, 'info');
          appendOutput(`URL: ${item.url}`, 'info');
          appendOutput(`Verdict: ${item.verdict}`, 'info');
        });
      }
      break;
      
    case 'screenshot':
      appendOutput('✓ Screenshot captured', 'success');
      if (response.screenshot) {
        appendOutput('Screenshot data URL available', 'info');
      }
      break;
      
    case 'sanitize_content':
      appendOutput('✓ Content sanitized', 'success');
      if (response.data) {
        appendOutput(`Verdict: ${response.data.verdict}`, 'info');
        if (response.data.findings.droppedTags.size > 0) {
          appendOutput(`Dropped tags: ${Array.from(response.data.findings.droppedTags).join(', ')}`, 'warning');
        }
      }
      break;
      
    case 'sanitize_network':
      appendOutput('✓ Network data sanitized', 'success');
      break;
      
    default:
      appendOutput(`✓ Command executed: ${command}`, 'success');
      if (response.data) {
        appendOutput(JSON.stringify(response.data, null, 2), 'info');
      }
  }
}

/**
 * Append message to output
 */
function appendOutput(message, type = 'info') {
  const div = document.createElement('div');
  div.className = type;
  // Use textContent for security (no innerHTML)
  div.textContent = message;
  elements.output.appendChild(div);
  elements.output.scrollTop = elements.output.scrollHeight;
}

/**
 * Update state from service worker
 */
function updateState(newState) {
  state = { ...state, ...newState };
  updateStatus();
  
  if (newState.directives) {
    updateDirectives(newState.directives);
  }
}

/**
 * Update UI status indicators
 */
function updateStatus() {
  elements.captureStatus.textContent = state.captureActive ? 'Active' : 'Inactive';
  elements.captureStatus.style.color = state.captureActive ? '#4CAF50' : '#f44336';
  elements.capturedCount.textContent = state.capturedCount;
}

/**
 * Update directives list
 */
function updateDirectives(directives) {
  state.directives = directives || [];
  
  elements.directivesList.textContent = '';
  
  if (state.directives.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No active directives';
    li.style.color = 'var(--text-muted)';
    elements.directivesList.appendChild(li);
    return;
  }
  
  state.directives.forEach((directive, index) => {
    const li = document.createElement('li');
    // Use textContent for security
    li.textContent = directive.text;
    elements.directivesList.appendChild(li);
  });
}

/**
 * Load saved state
 */
function loadState() {
  chrome.storage.local.get(['sentinelState'], (result) => {
    if (result.sentinelState) {
      updateState(result.sentinelState);
    }
  });
}

/**
 * Save state
 */
function saveState() {
  chrome.storage.local.set({ sentinelState: state });
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);

// Save state periodically
setInterval(saveState, 5000);
