// Sentinel Operator Bridge - Panel Script
// Pro-Grade Enterprise Minimalism | Dark Theme | Acid Green Accent
// Chatbot Input | Agent Functions | Click Actions | Move Objects | Fill Forms

import { sanitizeContent, sanitizeText, hasInjectionPatterns } from '../lib/sanitize_content.js';
import { isOperatorSender, ALLOWED_COMMANDS, STATE_KEYS, initSecurityState, persistSecurityState, isArmed } from '../lib/security.js';
import { logAuditEvent, getAuditLog, getFilteredAuditLog, exportAuditLog, clearAuditLog } from '../lib/audit_log.js';
import { safeFetch } from '../lib/network_guard.js';

/**
 * State Management
 */
let state = {
  captureActive: false,
  capturedContent: [],
  directives: [],
  currentTab: null,
  armed: false,
  armedUntil: 0,
  killSwitch: false,
  currentTabId: null
};

/**
 * DOM Elements
 */
const elements = {
  // Header
  statusPill: document.getElementById('status-pill'),
  killSwitch: document.getElementById('kill-switch'),
  themeToggle: document.getElementById('theme-toggle'),
  
  // Tabs
  tabButtons: document.querySelectorAll('.tab-btn'),
  tabPanes: document.querySelectorAll('.tab-pane'),
  
  // Command Tab
  armToggle: document.getElementById('arm-toggle'),
  armCountdown: document.getElementById('arm-countdown'),
  armStatus: document.getElementById('arm-status'),
  chatOutput: document.getElementById('chat-output'),
  commandInput: document.getElementById('command-input'),
  pasteBtn: document.getElementById('paste-btn'),
  executeBtn: document.getElementById('execute-btn'),
  agentButtons: document.querySelectorAll('.agent-btn'),
  
  // Scan Tab
  scanBtn: document.getElementById('scan-btn'),
  copyScanBtn: document.getElementById('copy-scan-btn'),
  scanVerdict: document.getElementById('scan-verdict'),
  scanStripped: document.getElementById('scan-stripped'),
  scanInjections: document.getElementById('scan-injections'),
  scanRedactions: document.getElementById('scan-redactions'),
  scanDiff: document.getElementById('scan-diff'),
  
  // Permissions Tab
  activeDomain: document.getElementById('active-domain'),
  permDomRead: document.getElementById('perm-dom-read'),
  permAgent: document.getElementById('perm-agent'),
  permNetwork: document.getElementById('perm-network'),
  
  // Audit Tab
  auditFilter: document.getElementById('audit-filter'),
  exportAuditBtn: document.getElementById('export-audit-btn'),
  clearAuditBtn: document.getElementById('clear-audit-btn'),
  auditLogBody: document.getElementById('audit-log-body'),
  
  // Settings Tab
  backendUrl: document.getElementById('backend-url'),
  modelName: document.getElementById('model-name'),
  autoDisarm: document.getElementById('auto-disarm'),
  stepByStep: document.getElementById('step-by-step'),
  dryRun: document.getElementById('dry-run'),
  verboseLogging: document.getElementById('verbose-logging'),
  auditRotation: document.getElementById('audit-rotation'),
  
  // Modals
  modalBackdrop: document.getElementById('modal-backdrop'),
  modal: document.getElementById('modal'),
  modalTitle: document.getElementById('modal-title'),
  modalBody: document.getElementById('modal-body'),
  modalClose: document.getElementById('modal-close'),
  modalCancel: document.getElementById('modal-cancel'),
  modalConfirm: document.getElementById('modal-confirm'),
  
  // Toast
  toastContainer: document.getElementById('toast-container')
};

/**
 * Commands that require data input
 */
const DATA_COMMANDS = new Set(['set_directive', 'sanitize_content', 'sanitize_network']);

/**
 * Initialize the panel
 */
async function init() {
  // Load saved state
  await loadState();
  
  // Check service worker status
  await checkServiceWorker();
  
  // Setup event listeners
  setupEventListeners();
  
  // Setup tab navigation
  setupTabs();
  
  // Update UI based on state
  updateUI();
  
  // Load audit log
  await loadAuditLog();
  
  console.log('Sentinel Operator Bridge panel initialized');
  
  // Auto-refresh audit log every 5 seconds
  setInterval(() => loadAuditLog(), 5000);
}

/**
 * Check if service worker is running
 */
async function checkServiceWorker() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'ping' });
    if (chrome.runtime.lastError) {
      showToast('Service worker not responding', 'error');
    } else {
      console.log('Service worker active');
    }
  } catch (error) {
    console.error('Ping error:', error);
  }
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  // Header controls
  elements.killSwitch.addEventListener('click', handleKillSwitch);
  elements.themeToggle.addEventListener('click', toggleTheme);
  
  // Command tab
  elements.armToggle.addEventListener('change', handleArmToggle);
  elements.pasteBtn.addEventListener('click', handlePaste);
  elements.executeBtn.addEventListener('click', executeCommand);
  elements.commandInput.addEventListener('input', updateExecuteButton);
  elements.commandInput.addEventListener('keydown', handleInputKeydown);
  
  // Agent buttons
  elements.agentButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const command = btn.dataset.command;
      elements.commandInput.value = command;
      updateExecuteButton();
      elements.commandInput.focus();
    });
  });
  
  // Scan tab
  elements.scanBtn.addEventListener('click', handleScan);
  elements.copyScanBtn.addEventListener('click', copyScanResults);
  
  // Audit tab
  elements.auditFilter.addEventListener('change', loadAuditLog);
  elements.exportAuditBtn.addEventListener('click', exportAudit);
  elements.clearAuditBtn.addEventListener('click', confirmClearAudit);
  
  // Settings tab
  elements.backendUrl.addEventListener('change', saveSettings);
  elements.modelName.addEventListener('change', saveSettings);
  elements.autoDisarm.addEventListener('change', saveSettings);
  elements.stepByStep.addEventListener('change', saveSettings);
  elements.dryRun.addEventListener('change', saveSettings);
  elements.verboseLogging.addEventListener('change', saveSettings);
  elements.auditRotation.addEventListener('change', saveSettings);
  
  // Modal
  elements.modalClose.addEventListener('click', closeModal);
  elements.modalCancel.addEventListener('click', closeModal);
  elements.modalConfirm.addEventListener('click', confirmModalAction);
  elements.modalBackdrop.addEventListener('click', (e) => {
    if (e.target === elements.modalBackdrop) closeModal();
  });
  
  // Keyboard
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
  });
  
  // Listen for messages from service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender, sendResponse);
  });
  
  // Listen for tab changes
  chrome.tabs.onActivated.addListener((activeInfo) => {
    state.currentTabId = activeInfo.tabId;
    updateActiveDomain();
  });
  
  // Listen for tab updates
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (tabId === state.currentTabId && changeInfo.url) {
      updateActiveDomain();
    }
  });
}

/**
 * Setup tab navigation
 */
function setupTabs() {
  elements.tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.dataset.tab;
      
      // Update button states
      elements.tabButtons.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      
      // Update pane states
      elements.tabPanes.forEach(pane => {
        pane.classList.remove('active');
      });
      document.getElementById(`pane-${tabId}`).classList.add('active');
      
      // Update active domain when switching to permissions tab
      if (tabId === 'permissions') {
        updateActiveDomain();
      }
    });
  });
}

/**
 * Update UI based on state
 */
function updateUI() {
  // Update status pill
  updateStatusPill();
  
  // Update arm toggle
  elements.armToggle.checked = state.armed;
  elements.armStatus.textContent = state.armed ? 'Armed' : 'Disarmed';
  
  // Update countdown
  updateCountdown();
  
  // Update execute button
  updateExecuteButton();
  
  // Update command input
  updateCommandInput();
}

/**
 * Update status pill
 */
function updateStatusPill() {
  elements.statusPill.className = 'status-pill';
  
  if (state.killSwitch) {
    elements.statusPill.classList.add('locked');
    elements.statusPill.textContent = 'Locked';
  } else if (state.armed) {
    elements.statusPill.classList.add('armed');
    updateCountdown();
  } else {
    elements.statusPill.classList.add('disarmed');
    elements.statusPill.textContent = 'Disarmed';
  }
}

/**
 * Update arm countdown
 */
function updateCountdown() {
  if (!state.armed || state.armedUntil <= Date.now()) {
    elements.armCountdown.textContent = '';
    return;
  }
  
  const remaining = Math.ceil((state.armedUntil - Date.now()) / 1000);
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  elements.armCountdown.textContent = `(${minutes}:${seconds.toString().padStart(2, '0')})`;
  
  // Update every second
  if (state.armed) {
    setTimeout(updateCountdown, 1000);
  }
}

/**
 * Handle arm toggle
 */
async function handleArmToggle() {
  if (elements.armToggle.checked) {
    // Arm the extension
    const duration = parseInt(elements.autoDisarm.value) * 60 * 1000;
    const result = await sendCommand('arm', { duration });
    
    if (result.error) {
      elements.armToggle.checked = false;
      showToast(result.error, 'error');
    } else {
      state.armed = true;
      state.armedUntil = Date.now() + duration;
      state.killSwitch = false;
      await saveState();
      updateUI();
      showToast('Extension armed', 'success');
    }
  } else {
    // Disarm the extension
    const result = await sendCommand('disarm');
    
    if (result.error) {
      elements.armToggle.checked = true;
      showToast(result.error, 'error');
    } else {
      state.armed = false;
      state.armedUntil = 0;
      await saveState();
      updateUI();
      showToast('Extension disarmed', 'success');
    }
  }
}

/**
 * Handle kill switch
 */
async function handleKillSwitch() {
  const result = await sendCommand('kill_switch');
  
  if (result.error) {
    showToast(result.error, 'error');
  } else {
    state.killSwitch = true;
    state.armed = false;
    state.armedUntil = 0;
    elements.armToggle.checked = false;
    await saveState();
    updateUI();
    showToast('Kill switch engaged! All actions blocked.', 'error');
  }
}

/**
 * Toggle theme
 */
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('sentinel-theme', next);
  showToast(`Theme: ${next}`, 'info');
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
      showToast(`Paste blocked: ${sanitized.findings.hiddenChars} hidden chars, ${sanitized.findings.secretRedactions} secrets`, 'error');
      return;
    }
    
    // Check for injection patterns
    if (hasInjectionPatterns(clipboardText)) {
      showToast('Paste blocked: Injection patterns detected', 'error');
      return;
    }
    
    // Wrap in paste fence markers
    const fencedText = `⟦DATA⟧${sanitized.text}⟦/DATA⟧`;
    
    // Insert at cursor position
    const start = elements.commandInput.selectionStart;
    const end = elements.commandInput.selectionEnd;
    const currentValue = elements.commandInput.value;
    
    elements.commandInput.value = currentValue.substring(0, start) + fencedText + currentValue.substring(end);
    elements.commandInput.selectionStart = start + fencedText.length;
    elements.commandInput.selectionEnd = start + fencedText.length;
    elements.commandInput.focus();
    
    showToast('Paste sanitized and fenced', 'success');
    updateExecuteButton();
    
  } catch (error) {
    showToast(`Paste failed: ${error.message}`, 'error');
  }
}

/**
 * Execute command
 */
async function executeCommand() {
  const command = elements.commandInput.value.trim();
  
  if (!command) {
    showToast('Please enter a command', 'error');
    return;
  }
  
  // Check if armed
  if (!state.armed && !['arm', 'kill_switch'].includes(command)) {
    showToast('Extension not armed. Arm it first.', 'error');
    return;
  }
  
  // Check kill switch
  if (state.killSwitch) {
    showToast('Kill switch engaged. All actions blocked.', 'error');
    return;
  }
  
  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  state.currentTabId = tab?.id;
  
  // Prepare message
  const message = { command };
  
  // Add tabId for verification
  if (state.currentTabId) {
    message.tabId = state.currentTabId;
  }
  
  // Clear output
  clearChatOutput();
  
  // Show loading
  addChatMessage('system', 'Executing command...', { loading: true });
  
  try {
    // Send message to service worker
    const response = await sendCommand(command);
    
    if (response.error) {
      addChatMessage('system', response.error, { type: 'error' });
      showToast(response.error, 'error');
      return;
    }
    
    // Handle response
    handleResponse(command, response);
    
  } catch (error) {
    addChatMessage('system', error.message, { type: 'error' });
    showToast(error.message, 'error');
  } finally {
    elements.commandInput.value = '';
    updateExecuteButton();
  }
}

/**
 * Send command to service worker
 */
async function sendCommand(command, data = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ command, ...data }, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ error: chrome.runtime.lastError.message });
      } else {
        resolve(response || {});
      }
    });
  });
}

/**
 * Handle command response
 */
function handleResponse(command, response) {
  switch (command) {
    case 'arm':
      state.armed = true;
      state.armedUntil = Date.now() + (data?.duration || 300000);
      state.killSwitch = false;
      saveState();
      addChatMessage('system', `Extension armed for ${(data?.duration || 300000) / 60000} minutes`, { type: 'success' });
      updateUI();
      break;
      
    case 'disarm':
      state.armed = false;
      state.armedUntil = 0;
      saveState();
      addChatMessage('system', 'Extension disarmed', { type: 'success' });
      updateUI();
      break;
      
    case 'kill_switch':
      state.killSwitch = true;
      state.armed = false;
      state.armedUntil = 0;
      elements.armToggle.checked = false;
      saveState();
      addChatMessage('system', 'Kill switch engaged! All actions blocked.', { type: 'error' });
      updateUI();
      break;
      
    case 'read_page':
      if (response.data) {
        addChatMessage('assistant', `Page read: ${response.data.verdict}`, { findings: response.data.findings });
        addChatMessage('assistant', `Text length: ${response.data.text?.length || 0} chars`, { type: 'info' });
      }
      break;
      
    case 'set_directive':
      if (response.directives) {
        state.directives = response.directives;
        addChatMessage('system', `Directive set (${response.directives.length} active)`, { type: 'success' });
      }
      break;
      
    case 'start_capture':
      state.captureActive = true;
      addChatMessage('system', 'Capture started', { type: 'success' });
      break;
      
    case 'stop_capture':
      state.captureActive = false;
      state.capturedCount = response.capturedCount || 0;
      addChatMessage('system', `Capture stopped (${response.capturedCount || 0} items)`, { type: 'success' });
      break;
      
    case 'get_capture':
      if (response.content && response.content.length > 0) {
        addChatMessage('assistant', `Captured ${response.content.length} items`, { type: 'info' });
        response.content.forEach((item, index) => {
          addChatMessage('assistant', `Item ${index + 1}: ${item.url || 'Unknown URL'}`, { type: 'info' });
        });
      } else {
        addChatMessage('system', 'No captured content', { type: 'info' });
      }
      break;
      
    case 'screenshot':
      if (response.screenshot) {
        addChatMessage('system', 'Screenshot captured', { type: 'success' });
        // Could display the screenshot here
      }
      break;
      
    case 'sanitize_content':
    case 'sanitize_network':
      if (response.data) {
        addChatMessage('assistant', `Sanitized: ${response.data.verdict}`, { findings: response.data.findings });
      }
      break;
      
    default:
      addChatMessage('assistant', `Command executed: ${command}`, { type: 'success' });
      if (response.data) {
        addChatMessage('assistant', JSON.stringify(response.data, null, 2), { type: 'info' });
      }
  }
}

/**
 * Handle input keydown
 */
function handleInputKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    executeCommand();
  }
}

/**
 * Update execute button state
 */
function updateExecuteButton() {
  const hasCommand = elements.commandInput.value.trim().length > 0;
  elements.executeBtn.disabled = !hasCommand || (state.killSwitch && !elements.commandInput.value.includes('kill_switch'));
}

/**
 * Update command input based on state
 */
function updateCommandInput() {
  // Disable input if kill switch is engaged (except for kill_switch command)
  if (state.killSwitch) {
    elements.commandInput.placeholder = 'Kill switch engaged. Type "kill_switch" to reset...';
  } else if (!state.armed) {
    elements.commandInput.placeholder = 'Arm extension first or use arm/disarm commands';
  } else {
    elements.commandInput.placeholder = 'Type a command or select from agent functions...';
  }
}

/**
 * Handle scan
 */
async function handleScan() {
  if (!state.armed) {
    showToast('Arm extension first', 'error');
    return;
  }
  
  // Clear previous results
  elements.scanVerdict.textContent = 'Scanning...';
  elements.scanStripped.textContent = '0';
  elements.scanInjections.textContent = '0';
  elements.scanRedactions.textContent = '0';
  elements.scanDiff.textContent = '';
  
  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  state.currentTabId = tab?.id;
  
  if (!state.currentTabId) {
    showToast('No active tab', 'error');
    return;
  }
  
  try {
    // Execute read_page command
    const response = await sendCommand('read_page');
    
    if (response.error) {
      showToast(response.error, 'error');
      elements.scanVerdict.textContent = 'ERROR';
      return;
    }
    
    if (response.data) {
      // Update scan results
      elements.scanVerdict.textContent = response.data.verdict;
      elements.scanVerdict.className = `value ${response.data.verdict.toLowerCase()}`;
      
      elements.scanStripped.textContent = response.data.findings.droppedTags.size || 0;
      elements.scanInjections.textContent = response.data.findings.injectionSpans.length || 0;
      elements.scanRedactions.textContent = response.data.findings.secretRedactions || 0;
      
      // Display diff
      if (response.data.text) {
        // Simple diff display
        const preview = response.data.text.substring(0, 500);
        elements.scanDiff.textContent = preview + (response.data.text.length > 500 ? '...' : '');
      }
      
      showToast('Page scan complete', 'success');
    }
  } catch (error) {
    showToast(error.message, 'error');
    elements.scanVerdict.textContent = 'ERROR';
  }
}

/**
 * Copy scan results
 */
async function copyScanResults() {
  try {
    const response = await sendCommand('read_page');
    
    if (response.data && response.data.text) {
      await navigator.clipboard.writeText(response.data.text);
      showToast('Scan results copied to clipboard', 'success');
    } else {
      showToast('No scan results to copy', 'error');
    }
  } catch (error) {
    showToast(`Copy failed: ${error.message}`, 'error');
  }
}

/**
 * Update active domain
 */
async function updateActiveDomain() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    
    if (tab && tab.url) {
      try {
        const url = new URL(tab.url);
        elements.activeDomain.textContent = url.hostname;
        state.currentTabId = tab.id;
      } catch {
        elements.activeDomain.textContent = tab.url;
      }
    } else {
      elements.activeDomain.textContent = 'No active site';
    }
  } catch (error) {
    console.error('Error updating domain:', error);
    elements.activeDomain.textContent = 'Error';
  }
}

/**
 * Load audit log
 */
async function loadAuditLog() {
  try {
    const filter = elements.auditFilter.value;
    let log;
    
    if (filter === 'all') {
      log = await getAuditLog();
    } else {
      const filterMap = {
        'allowed': { action: 'ALLOWED' },
        'denied': { action: 'BLOCKED' },
        'kill': { type: 'kill_switch' }
      };
      log = await getFilteredAuditLog(filterMap[filter] || {});
    }
    
    renderAuditLog(log);
  } catch (error) {
    console.error('Error loading audit log:', error);
  }
}

/**
 * Render audit log
 */
function renderAuditLog(log) {
  if (log.length === 0) {
    elements.auditLogBody.innerHTML = `
      <tr>
        <td colspan="4">
          <div class="empty-state">
            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/>
            </svg>
            <h3>No audit entries yet</h3>
            <p>Commands and events will appear here</p>
          </div>
        </td>
      </tr>
    `;
    return;
  }
  
  let html = '';
  for (const entry of log) {
    const timestamp = new Date(entry.timestamp).toLocaleTimeString();
    const type = entry.type || 'unknown';
    const action = entry.action || 'unknown';
    const command = entry.command || '';
    
    html += `
      <tr>
        <td class="timestamp">${timestamp}</td>
        <td class="type">${type}</td>
        <td class="action ${action.toLowerCase()}">${action}</td>
        <td>${command}</td>
      </tr>
    `;
  }
  
  elements.auditLogBody.innerHTML = html;
}

/**
 * Export audit log
 */
async function exportAudit() {
  try {
    const json = await exportAuditLog();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-audit-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Audit log exported', 'success');
  } catch (error) {
    showToast(`Export failed: ${error.message}`, 'error');
  }
}

/**
 * Confirm clear audit log
 */
function confirmClearAudit() {
  showModal(
    'Clear Audit Log',
    'Are you sure you want to clear the audit log? This action cannot be undone.',
    async () => {
      await clearAuditLog();
      await loadAuditLog();
      showToast('Audit log cleared', 'success');
    }
  );
}

/**
 * Save settings
 */
async function saveSettings() {
  const settings = {
    backendUrl: elements.backendUrl.value,
    modelName: elements.modelName.value,
    autoDisarm: elements.autoDisarm.value,
    stepByStep: elements.stepByStep.checked,
    dryRun: elements.dryRun.checked,
    verboseLogging: elements.verboseLogging.checked,
    auditRotation: elements.auditRotation.checked
  };
  
  await chrome.storage.local.set({ sentinelSettings: settings });
  showToast('Settings saved', 'success');
}

/**
 * Load state
 */
async function loadState() {
  try {
    // Load security state
    const stored = await initSecurityState();
    state.armed = stored.armed || false;
    state.armedUntil = stored.armedUntil || 0;
    state.killSwitch = stored.killSwitch || false;
    
    // Load settings
    const result = await chrome.storage.local.get('sentinelSettings');
    if (result.sentinelSettings) {
      const settings = result.sentinelSettings;
      elements.backendUrl.value = settings.backendUrl || 'http://localhost:11434';
      elements.modelName.value = settings.modelName || 'mistral';
      elements.autoDisarm.value = settings.autoDisarm || '5';
      elements.stepByStep.checked = settings.stepByStep !== false;
      elements.dryRun.checked = settings.dryRun || false;
      elements.verboseLogging.checked = settings.verboseLogging || false;
      elements.auditRotation.checked = settings.auditRotation !== false;
    }
    
    // Load theme preference
    const theme = localStorage.getItem('sentinel-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    
    await saveState();
  } catch (error) {
    console.error('Error loading state:', error);
  }
}

/**
 * Save state
 */
async function saveState() {
  try {
    await persistSecurityState({
      armed: state.armed,
      armedUntil: state.armedUntil,
      killSwitch: state.killSwitch
    });
  } catch (error) {
    console.error('Error saving state:', error);
  }
}

/**
 * Handle messages from service worker
 */
function handleMessage(message, sender, sendResponse) {
  // Handle state updates
  if (message.type === 'state_update') {
    state = { ...state, ...message.state };
    updateUI();
    return;
  }
  
  // Handle audit events
  if (message.type === 'audit_event') {
    loadAuditLog();
    return;
  }
  
  // Handle command responses
  if (message.command && message.command !== 'ping') {
    // Will be handled by executeCommand
    return;
  }
}

/**
 * Chat Message System
 */

/**
 * Add chat message
 */
function addChatMessage(role, content, options = {}) {
  const { type = 'text', loading = false, findings = null } = options;
  
  const messageDiv = document.createElement('div');
  messageDiv.className = `chat-message ${role}`;
  
  // Add badge
  const badgeSpan = document.createElement('span');
  badgeSpan.className = 'badge';
  
  const badgeText = role === 'user' ? 'USER' : 
                    role === 'assistant' ? 'ASSISTANT' : 
                    role === 'system' ? 'SYSTEM' : role;
  badgeSpan.textContent = badgeText;
  messageDiv.appendChild(badgeSpan);
  
  // Add content
  const contentSpan = document.createElement('span');
  contentSpan.textContent = content;
  messageDiv.appendChild(contentSpan);
  
  // Add findings if present
  if (findings) {
    const findingsDiv = document.createElement('div');
    findingsDiv.className = 'findings';
    findingsDiv.style.fontSize = '11px';
    findingsDiv.style.marginTop = '4px';
    findingsDiv.style.color = 'var(--color-text-muted)';
    
    if (findings.droppedTags && findings.droppedTags.size > 0) {
      findingsDiv.innerHTML += `<span>Dropped tags: ${Array.from(findings.droppedTags).join(', ')}</span><br/>`;
    }
    if (findings.injectionSpans && findings.injectionSpans.length > 0) {
      findingsDiv.innerHTML += `<span>Injections: ${findings.injectionSpans.length}</span><br/>`;
    }
    if (findings.secretRedactions && findings.secretRedactions > 0) {
      findingsDiv.innerHTML += `<span>Secrets redacted: ${findings.secretRedactions}</span><br/>`;
    }
    if (findings.hiddenElements && findings.hiddenElements > 0) {
      findingsDiv.innerHTML += `<span>Hidden elements: ${findings.hiddenElements}</span>`;
    }
    
    messageDiv.appendChild(findingsDiv);
  }
  
  // Add to chat output
  elements.chatOutput.appendChild(messageDiv);
  
  // Scroll to bottom
  elements.chatOutput.scrollTop = elements.chatOutput.scrollHeight;
  
  // Remove loading state if present
  if (loading) {
    const loadingMessage = elements.chatOutput.querySelector('.chat-message[loading]');
    if (loadingMessage) {
      elements.chatOutput.removeChild(loadingMessage);
    }
  }
}

/**
 * Clear chat output
 */
function clearChatOutput() {
  elements.chatOutput.innerHTML = '';
}

/**
 * Modal System
 */

let modalCallback = null;

/**
 * Show modal
 */
function showModal(title, content, callback) {
  modalCallback = callback;
  elements.modalTitle.textContent = title;
  elements.modalBody.textContent = content;
  elements.modalBackdrop.classList.remove('hidden');
  elements.modalClose.focus();
}

/**
 * Close modal
 */
function closeModal() {
  elements.modalBackdrop.classList.add('hidden');
  modalCallback = null;
}

/**
 * Confirm modal action
 */
function confirmModalAction() {
  if (modalCallback) {
    modalCallback();
    closeModal();
  }
}

/**
 * Toast System
 */

/**
 * Show toast
 */
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  // Add icon
  const icon = document.createElement('svg');
  icon.className = 'icon';
  icon.setAttribute('viewBox', '0 0 24 24');
  icon.setAttribute('aria-hidden', 'true');
  
  let iconPath;
  switch (type) {
    case 'success':
      iconPath = 'M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z';
      break;
    case 'error':
      iconPath = 'M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z';
      break;
    case 'warning':
      iconPath = 'M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z';
      break;
    default:
      iconPath = 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z';
  }
  
  icon.innerHTML = `<path d="${iconPath}"/>`;
  toast.appendChild(icon);
  
  // Add message
  const messageSpan = document.createElement('span');
  messageSpan.className = 'message';
  messageSpan.textContent = message;
  toast.appendChild(messageSpan);
  
  // Add to container
  elements.toastContainer.appendChild(toast);
  
  // Auto-remove after 3 seconds
  setTimeout(() => {
    toast.style.animation = 'slideIn 0.2s ease reverse';
    setTimeout(() => {
      toast.remove();
    }, 200);
  }, 3000);
}

/**
 * Initialize when DOM is ready
 */
document.addEventListener('DOMContentLoaded', init);

// Auto-save state periodically
setInterval(saveState, 5000);
