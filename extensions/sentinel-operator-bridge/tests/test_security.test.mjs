// Sentinel Operator Bridge - Security Module Tests
import { assert, describe, it, beforeEach, afterEach } from 'node:test';

// Mock chrome.runtime
const mockChrome = {
  runtime: {
    id: 'test-extension-id',
    getURL: (path) => `chrome-extension://test-extension-id/${path}`
  },
  storage: {
    session: {
      get: async (keys) => {
        const result = {};
        for (const key of keys) {
          result[key] = mockStorage[key];
        }
        return result;
      },
      set: async (data) => {
        for (const [key, value] of Object.entries(data)) {
          mockStorage[key] = value;
        }
      }
    }
  }
};

// Set up global chrome
global.chrome = mockChrome;

// Storage for testing
const mockStorage = {};

// Import the security module
import {
  ALLOWED_COMMANDS,
  isOperatorSender,
  validateCommandMessage,
  createFailClosedResponse,
  initSecurityState,
  persistSecurityState,
  isArmed,
  STATE_KEYS
} from '../src/lib/security.js';

describe('Security Module', () => {
  beforeEach(() => {
    // Reset storage
    Object.keys(mockStorage).forEach(key => delete mockStorage[key]);
  });

  describe('ALLOWED_COMMANDS', () => {
    it('should contain all expected commands', () => {
      const expectedCommands = [
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
      ];
      
      for (const cmd of expectedCommands) {
        assert.ok(ALLOWED_COMMANDS.has(cmd), `Command ${cmd} should be in allowlist`);
      }
    });

    it('should not contain dangerous commands', () => {
      const dangerousCommands = ['click', 'fill', 'navigate', 'execute_script'];
      
      for (const cmd of dangerousCommands) {
        assert.ok(!ALLOWED_COMMANDS.has(cmd), `Dangerous command ${cmd} should not be in allowlist`);
      }
    });
  });

  describe('isOperatorSender()', () => {
    it('should accept sender from canonical panel URL', () => {
      const sender = {
        id: 'test-extension-id',
        url: 'chrome-extension://test-extension-id/src/panel/panel.html'
      };
      
      assert.ok(isOperatorSender(sender), 'Should accept canonical panel sender');
    });

    it('should accept sender from panel URL with query params', () => {
      const sender = {
        id: 'test-extension-id',
        url: 'chrome-extension://test-extension-id/src/panel/panel.html?tab=123'
      };
      
      assert.ok(isOperatorSender(sender), 'Should accept panel sender with query params');
    });

    it('should reject sender with wrong extension ID', () => {
      const sender = {
        id: 'different-extension-id',
        url: 'chrome-extension://test-extension-id/src/panel/panel.html'
      };
      
      assert.ok(!isOperatorSender(sender), 'Should reject sender with wrong ID');
    });

    it('should reject sender with wrong path', () => {
      const sender = {
        id: 'test-extension-id',
        url: 'chrome-extension://test-extension-id/src/other/other.html'
      };
      
      assert.ok(!isOperatorSender(sender), 'Should reject sender with wrong path');
    });

    it('should reject sender without id', () => {
      const sender = {
        url: 'chrome-extension://test-extension-id/src/panel/panel.html'
      };
      
      assert.ok(!isOperatorSender(sender), 'Should reject sender without id');
    });

    it('should reject sender without url', () => {
      const sender = {
        id: 'test-extension-id'
      };
      
      assert.ok(!isOperatorSender(sender), 'Should reject sender without url');
    });

    it('should reject sender from page context', () => {
      const sender = {
        id: 'test-extension-id',
        url: 'https://example.com/page.html',
        tab: { id: 123 }
      };
      
      assert.ok(!isOperatorSender(sender), 'Should reject page context sender');
    });

    it('should reject null sender', () => {
      assert.ok(!isOperatorSender(null), 'Should reject null sender');
    });

    it('should reject undefined sender', () => {
      assert.ok(!isOperatorSender(undefined), 'Should reject undefined sender');
    });
  });

  describe('validateCommandMessage()', () => {
    it('should accept valid ping message', () => {
      const result = validateCommandMessage({ type: 'ping' });
      assert.ok(result.valid, 'Ping message should be valid');
      assert.equal(result.command, 'ping');
    });

    it('should accept valid command message', () => {
      const result = validateCommandMessage({ command: 'read_page' });
      assert.ok(result.valid, 'Valid command should be accepted');
      assert.equal(result.command, 'read_page');
    });

    it('should reject non-object message', () => {
      const result = validateCommandMessage('invalid');
      assert.ok(!result.valid, 'Non-object should be rejected');
      assert.ok(result.error, 'Should have error message');
    });

    it('should reject null message', () => {
      const result = validateCommandMessage(null);
      assert.ok(!result.valid, 'Null should be rejected');
    });

    it('should reject message without command', () => {
      const result = validateCommandMessage({});
      assert.ok(!result.valid, 'Message without command should be rejected');
      assert.ok(result.error, 'Should have error message');
    });

    it('should reject message with non-string command', () => {
      const result = validateCommandMessage({ command: 123 });
      assert.ok(!result.valid, 'Non-string command should be rejected');
    });

    it('should reject unknown command', () => {
      const result = validateCommandMessage({ command: 'unknown_command' });
      assert.ok(!result.valid, 'Unknown command should be rejected');
      assert.ok(result.error, 'Should have error message');
      assert.equal(result.command, 'unknown_command');
    });

    it('should accept all allowed commands', () => {
      for (const cmd of ALLOWED_COMMANDS) {
        const result = validateCommandMessage({ command: cmd });
        assert.ok(result.valid, `Command ${cmd} should be valid`);
        assert.equal(result.command, cmd);
      }
    });
  });

  describe('createFailClosedResponse()', () => {
    it('should create proper fail-closed response', () => {
      const response = createFailClosedResponse('Test error');
      assert.equal(response.error, 'Test error');
      assert.equal(response.allowed, false);
    });

    it('should include the error message', () => {
      const errorMsg = 'Unauthorized access attempt';
      const response = createFailClosedResponse(errorMsg);
      assert.equal(response.error, errorMsg);
    });
  });

  describe('State Management', () => {
    it('should initialize with default values', async () => {
      const state = await initSecurityState();
      assert.equal(state.armed, false);
      assert.equal(state.armedUntil, 0);
      assert.equal(state.killSwitch, false);
    });

    it('should persist and retrieve state', async () => {
      const testState = {
        armed: true,
        armedUntil: Date.now() + 10000,
        killSwitch: false
      };
      
      await persistSecurityState(testState);
      const retrieved = await initSecurityState();
      
      assert.equal(retrieved.armed, true);
      assert.ok(retrieved.armedUntil > 0);
      assert.equal(retrieved.killSwitch, false);
    });

    it('should handle expired armed state', async () => {
      const testState = {
        armed: true,
        armedUntil: Date.now() - 1000, // Expired
        killSwitch: false
      };
      
      await persistSecurityState(testState);
      const retrieved = await initSecurityState();
      
      // Expired armed state should be cleared
      assert.equal(retrieved.armed, false);
      assert.equal(retrieved.armedUntil, 0);
    });
  });

  describe('isArmed()', () => {
    it('should return false when not armed', () => {
      const state = { armed: false, armedUntil: 0, killSwitch: false };
      assert.ok(!isArmed(state), 'Should not be armed');
    });

    it('should return true when armed with future timestamp', () => {
      const state = { 
        armed: true, 
        armedUntil: Date.now() + 10000, 
        killSwitch: false 
      };
      assert.ok(isArmed(state), 'Should be armed');
    });

    it('should return false when armed but expired', () => {
      const state = { 
        armed: true, 
        armedUntil: Date.now() - 1000, 
        killSwitch: false 
      };
      assert.ok(!isArmed(state), 'Should not be armed when expired');
    });

    it('should return false when kill switch is engaged', () => {
      const state = { 
        armed: true, 
        armedUntil: Date.now() + 10000, 
        killSwitch: true 
      };
      assert.ok(!isArmed(state), 'Should not be armed when kill switch is on');
    });
  });
});

describe('Security Edge Cases', () => {
  it('should handle malformed sender objects', () => {
    const senders = [
      {},
      { id: null, url: null },
      { id: '', url: '' },
      { id: 'test-extension-id', url: '' },
      { id: '', url: 'chrome-extension://test-extension-id/src/panel/panel.html' }
    ];
    
    for (const sender of senders) {
      assert.ok(!isOperatorSender(sender), `Should reject malformed sender: ${JSON.stringify(sender)}`);
    }
  });

  it('should handle edge case URLs', () => {
    const edgeCases = [
      // Different protocols
      { id: 'test-extension-id', url: 'https://test-extension-id/src/panel/panel.html' },
      { id: 'test-extension-id', url: 'http://test-extension-id/src/panel/panel.html' },
      // Different hosts
      { id: 'test-extension-id', url: 'chrome-extension://other-id/src/panel/panel.html' },
      // Different paths
      { id: 'test-extension-id', url: 'chrome-extension://test-extension-id/panel/panel.html' },
      { id: 'test-extension-id', url: 'chrome-extension://test-extension-id/src/panel/' },
      // With fragments
      { id: 'test-extension-id', url: 'chrome-extension://test-extension-id/src/panel/panel.html#section' }
    ];
    
    for (const sender of edgeCases) {
      assert.ok(!isOperatorSender(sender), `Should reject edge case URL: ${sender.url}`);
    }
  });
});
