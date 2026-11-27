// Sentinel Operator Bridge - Audit Log Tests
import { assert, describe, it, beforeEach, afterEach } from 'node:test';

// Mock chrome.storage
const mockStorage = {};
const mockChrome = {
  storage: {
    local: {
      get: async (keys) => {
        const result = {};
        for (const key of keys) {
          result[key] = mockStorage[key] || [];
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

global.chrome = mockChrome;

// Import audit log module
import {
  logAuditEvent,
  getAuditLog,
  getFilteredAuditLog,
  exportAuditLog,
  clearAuditLog,
  getAuditStats,
  REDACTED
} from '../src/lib/audit_log.js';

describe('Audit Log Module', () => {
  beforeEach(async () => {
    // Clear storage
    await clearAuditLog();
  });

  describe('logAuditEvent()', () => {
    it('should log a basic event', async () => {
      await logAuditEvent({
        type: 'command',
        action: 'ALLOWED',
        command: 'read_page',
        timestamp: Date.now()
      });
      
      const log = await getAuditLog();
      assert.equal(log.length, 1);
      assert.equal(log[0].type, 'command');
      assert.equal(log[0].action, 'ALLOWED');
      assert.equal(log[0].command, 'read_page');
    });

    it('should redact secrets in event data', async () => {
      await logAuditEvent({
        type: 'message',
        action: 'REJECTED',
        reason: 'Secret detected',
        secretData: 'password=mysecret123',
        timestamp: Date.now()
      });
      
      const log = await getAuditLog();
      assert.equal(log.length, 1);
      
      // The secret should be redacted
      const entry = log[0];
      assert.ok(!entry.secretData || !entry.secretData.includes('mysecret123'));
    });

    it('should redact secrets in error messages', async () => {
      await logAuditEvent({
        type: 'command',
        action: 'ERROR',
        command: 'read_page',
        error: 'Failed with token=abc123',
        timestamp: Date.now()
      });
      
      const log = await getAuditLog();
      const entry = log[0];
      
      // Error should be redacted
      assert.ok(!entry.error || entry.error === REDACTED);
    });

    it('should redact API keys in metadata', async () => {
      await logAuditEvent({
        type: 'network',
        action: 'BLOCKED',
        url: 'https://api.example.com?key=sk-abc123def456',
        timestamp: Date.now()
      });
      
      const log = await getAuditLog();
      const entry = log[0];
      
      // URL should be redacted
      assert.ok(!entry.url || !entry.url.includes('sk-abc123def456'));
    });

    it('should handle multiple events', async () => {
      for (let i = 0; i < 5; i++) {
        await logAuditEvent({
          type: 'command',
          action: 'ALLOWED',
          command: `command_${i}`,
          timestamp: Date.now()
        });
      }
      
      const log = await getAuditLog();
      assert.equal(log.length, 5);
    });

    it('should rotate when exceeding 1000 entries', async () => {
      // Log 1001 events
      for (let i = 0; i < 1001; i++) {
        await logAuditEvent({
          type: 'test',
          action: 'test',
          index: i,
          timestamp: Date.now()
        });
      }
      
      const log = await getAuditLog();
      assert.equal(log.length, 1000);
      
      // First event should be rotated out
      assert.equal(log[0].index, 1);
    });

    it('should use current timestamp if not provided', async () => {
      const before = Date.now();
      await logAuditEvent({
        type: 'command',
        action: 'ALLOWED'
      });
      const after = Date.now();
      
      const log = await getAuditLog();
      assert.ok(log[0].timestamp >= before);
      assert.ok(log[0].timestamp <= after);
    });
  });

  describe('getAuditLog()', () => {
    it('should return empty array when no logs exist', async () => {
      const log = await getAuditLog();
      assert.equal(log.length, 0);
    });

    it('should return all logged events', async () => {
      await logAuditEvent({ type: 'test1', action: 'test' });
      await logAuditEvent({ type: 'test2', action: 'test' });
      
      const log = await getAuditLog();
      assert.equal(log.length, 2);
    });
  });

  describe('getFilteredAuditLog()', () => {
    beforeEach(async () => {
      await logAuditEvent({ type: 'command', action: 'ALLOWED', command: 'read_page' });
      await logAuditEvent({ type: 'command', action: 'BLOCKED', command: 'click' });
      await logAuditEvent({ type: 'message', action: 'REJECTED' });
      await logAuditEvent({ type: 'command', action: 'ALLOWED', command: 'screenshot' });
    });

    it('should filter by type', async () => {
      const filtered = await getFilteredAuditLog({ type: 'command' });
      assert.equal(filtered.length, 3);
      assert.ok(filtered.every(e => e.type === 'command'));
    });

    it('should filter by action', async () => {
      const filtered = await getFilteredAuditLog({ action: 'ALLOWED' });
      assert.equal(filtered.length, 2);
      assert.ok(filtered.every(e => e.action === 'ALLOWED'));
    });

    it('should filter by command', async () => {
      const filtered = await getFilteredAuditLog({ command: 'read_page' });
      assert.equal(filtered.length, 1);
      assert.equal(filtered[0].command, 'read_page');
    });

    it('should filter by multiple criteria', async () => {
      const filtered = await getFilteredAuditLog({ 
        type: 'command', 
        action: 'ALLOWED' 
      });
      assert.equal(filtered.length, 2);
      assert.ok(filtered.every(e => e.type === 'command' && e.action === 'ALLOWED'));
    });

    it('should return empty array for no matches', async () => {
      const filtered = await getFilteredAuditLog({ type: 'nonexistent' });
      assert.equal(filtered.length, 0);
    });
  });

  describe('exportAuditLog()', () => {
    it('should export log as JSON string', async () => {
      await logAuditEvent({ type: 'test', action: 'test' });
      
      const json = await exportAuditLog();
      assert.ok(typeof json === 'string');
      
      const parsed = JSON.parse(json);
      assert.equal(parsed.length, 1);
      assert.equal(parsed[0].type, 'test');
    });

    it('should export empty array when no logs', async () => {
      const json = await exportAuditLog();
      const parsed = JSON.parse(json);
      assert.equal(parsed.length, 0);
    });
  });

  describe('clearAuditLog()', () => {
    it('should clear all log entries', async () => {
      await logAuditEvent({ type: 'test', action: 'test' });
      await logAuditEvent({ type: 'test2', action: 'test' });
      
      await clearAuditLog();
      
      const log = await getAuditLog();
      assert.equal(log.length, 0);
    });
  });

  describe('getAuditStats()', () => {
    beforeEach(async () => {
      await logAuditEvent({ type: 'command', action: 'ALLOWED', command: 'read_page' });
      await logAuditEvent({ type: 'command', action: 'ALLOWED', command: 'screenshot' });
      await logAuditEvent({ type: 'command', action: 'BLOCKED', command: 'click' });
      await logAuditEvent({ type: 'message', action: 'REJECTED' });
    });

    it('should return correct statistics', async () => {
      const stats = await getAuditStats();
      
      assert.equal(stats.total, 4);
      assert.equal(stats.byType.command, 3);
      assert.equal(stats.byType.message, 1);
      assert.equal(stats.byAction.ALLOWED, 2);
      assert.equal(stats.byAction.BLOCKED, 1);
      assert.equal(stats.byAction.REJECTED, 1);
      assert.equal(stats.recent.length, 4);
    });

    it('should return empty stats when no logs', async () => {
      await clearAuditLog();
      
      const stats = await getAuditStats();
      
      assert.equal(stats.total, 0);
      assert.equal(Object.keys(stats.byType).length, 0);
      assert.equal(Object.keys(stats.byAction).length, 0);
      assert.equal(stats.recent.length, 0);
    });
  });
});

describe('Secret Redaction', () => {
  it('should redact API keys', async () => {
    await logAuditEvent({
      type: 'test',
      action: 'test',
      apiKey: 'sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234'
    });
    
    const log = await getAuditLog();
    assert.ok(!log[0].apiKey || !log[0].apiKey.includes('abc123'));
  });

  it('should redact passwords', async () => {
    await logAuditEvent({
      type: 'test',
      action: 'test',
      password: 'mysecretpassword123'
    });
    
    const log = await getAuditLog();
    assert.ok(!log[0].password || !log[0].password.includes('mysecretpassword'));
  });

  it('should redact tokens', async () => {
    await logAuditEvent({
      type: 'test',
      action: 'test',
      token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test'
    });
    
    const log = await getAuditLog();
    assert.ok(!log[0].token || !log[0].token.includes('eyJhbGci'));
  });

  it('should redact nested secrets in objects', async () => {
    await logAuditEvent({
      type: 'test',
      action: 'test',
      metadata: {
        config: {
          apiKey: 'secret123',
          endpoint: 'https://api.example.com'
        }
      }
    });
    
    const log = await getAuditLog();
    const metadata = log[0].metadata;
    assert.ok(!metadata.config.apiKey || !metadata.config.apiKey.includes('secret'));
  });

  it('should redact secrets in arrays', async () => {
    await logAuditEvent({
      type: 'test',
      action: 'test',
      secrets: ['key1=value1', 'key2=value2']
    });
    
    const log = await getAuditLog();
    assert.ok(!log[0].secrets || !log[0].secrets[0].includes('value1'));
  });
});
