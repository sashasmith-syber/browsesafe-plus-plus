// Sentinel Operator Bridge - Sanitize Tests
// Offline Node tests exercising the sanitiser against documented attack vectors

import { strict as assert } from 'node:assert';
import { test, describe } from 'node:test';

import {
  sanitizeContent,
  sanitizeText,
  decodeEntities,
  normalizeText,
  hasInjectionKeywords
} from '../src/lib/sanitize_content.js';

// Test fixtures
const fixtures = {
  // Basic HTML with script tags
  scriptTag: '<html><body><script>alert("xss")</script>Safe content</body></html>',
  
  // HTML with event handlers
  eventHandler: '<div onclick="alert(\'xss\')">Click me</div>',
  
  // HTML with hidden content
  hiddenContent: '<div hidden>Hidden text</div><div aria-hidden="true">ARIA hidden</div>',
  
  // HTML comments
  htmlComment: '<!-- This is a comment --><p>Visible</p>',
  
  // CDATA
  cdata: '<![CDATA[<script>alert("xss")</script>]]>',
  
  // DOCTYPE
  doctype: '<!DOCTYPE html><html><body>Content</body></html>',
  
  // Invisible characters
  invisibleChars: 'Hello\u200BWorld\uFEFFTest',
  
  // Injection keywords
  injectionKeywords: '<p>Here are your instructions: SYSTEM PROMPT</p>',
  
  // Nested dangerous tags
  nestedDangerous: '<div><script>alert(1)</script><iframe src="evil.com"></iframe></div>',
  
  // Mixed content
  mixedContent: `
    <html>
      <head>
        <script>evil()</script>
        <style>body { background: url('javascript:alert(1)'); }</style>
      </head>
      <body>
        <div onclick="alert(1)">Click</div>
        <p hidden>Hidden paragraph</p>
        <!-- Comment -->
        Visible text
        <span aria-hidden="true">More hidden</span>
      </body>
    </html>
  `,
  
  // Entity encoded
  entityEncoded: '<p>Hello &lt;script&gt;alert(1)&lt;/script&gt;</p>',
  
  // Numeric entities
  numericEntities: '<p>Hello &#x3C;script&#x3E;</p>',
  
  // Zero-width spaces in injection
  zeroWidthInjection: 'in\u200Bstruct\u200Bion',
  
  // Secret patterns
  creditCard: 'Card: 4111 1111 1111 1111',
  ssn: 'SSN: 123-45-6789',
  apiKey: 'API Key: abcdef1234567890abcdef1234567890',
  bearerToken: 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  
  // Combined attack
  combined: `
    <!DOCTYPE html>
    <html>
      <head>
        <meta http-equiv="refresh" content="0;url=javascript:alert(1)">
        <script>alert('xss')</script>
      </head>
      <body>
        <div hidden onclick="alert(1)">
          <span>in\u200Bstruct</span>
          <script>moreEvil()</script>
        </div>
        Card: 4111111111111111
      </body>
    </html>
  `
};

// Run tests
describe('sanitize_content.js', () => {
  describe('decodeEntities', () => {
    test('decodes named entities', () => {
      const result = decodeEntities('&lt;&gt;&amp;&quot;&apos;');
      // &lt; -> <, &gt; -> >, &amp; -> &, &quot; -> ", &apos; -> '
      assert.equal(result, '<>&"\'');
    });
    
    test('decodes hex entities', () => {
      const result = decodeEntities('&#x3C;script&#x3E;');
      assert.equal(result, '<script>');
    });
    
    test('decodes decimal entities', () => {
      const result = decodeEntities('&#60;script&#62;');
      assert.equal(result, '<script>');
    });
    
    test('leaves invalid entities as-is', () => {
      const result = decodeEntities('&invalid;');
      assert.equal(result, '&invalid;');
    });
  });
  
  describe('normalizeText', () => {
    test('removes invisible characters', () => {
      const result = normalizeText('Hello\u200BWorld\uFEFF');
      assert.equal(result, 'HelloWorld');
    });
    
    test('normalizes NFKC', () => {
      const result = normalizeText('\u00C5\u0086');
      assert.equal(result.length, 2);
    });
  });
  
  describe('hasInjectionKeywords', () => {
    test('detects injection keywords', () => {
      assert.equal(hasInjectionKeywords('instruct'), true);
      assert.equal(hasInjectionKeywords('SYSTEM prompt'), true);
      assert.equal(hasInjectionKeywords('javascript:alert(1)'), true);
    });
    
    test('does not flag safe text', () => {
      assert.equal(hasInjectionKeywords('Hello world'), false);
      assert.equal(hasInjectionKeywords('This is a test'), false);
    });
  });
  
  describe('sanitizeContent', () => {
    test('removes script tags', () => {
      const result = sanitizeContent(fixtures.scriptTag);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('script'));
      assert.ok(!result.text.includes('alert'));
      assert.ok(result.text.includes('Safe content'));
    });
    
    test('removes event handlers', () => {
      const result = sanitizeContent(fixtures.eventHandler);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedAttrs.has('onclick'));
      assert.ok(!result.text.includes('alert'));
    });
    
    test('removes hidden content', () => {
      const result = sanitizeContent(fixtures.hiddenContent);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('div'));
      assert.ok(!result.text.includes('Hidden text'));
      assert.ok(!result.text.includes('ARIA hidden'));
    });
    
    test('removes HTML comments', () => {
      const result = sanitizeContent(fixtures.htmlComment);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('comment'));
      assert.ok(!result.text.includes('This is a comment'));
      assert.ok(result.text.includes('Visible'));
    });
    
    test('removes CDATA', () => {
      const result = sanitizeContent(fixtures.cdata);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('cdata'));
      assert.ok(!result.text.includes('alert'));
    });
    
    test('removes DOCTYPE', () => {
      const result = sanitizeContent(fixtures.doctype);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('doctype'));
      assert.ok(!result.text.includes('DOCTYPE'));
      assert.ok(result.text.includes('Content'));
    });
    
    test('removes invisible characters', () => {
      const result = sanitizeContent(fixtures.invisibleChars);
      assert.equal(result.findings.hiddenChars, 2);
      assert.equal(result.text, 'HelloWorldTest');
    });
    
    test('wraps injection keywords', () => {
      const result = sanitizeContent(fixtures.injectionKeywords);
      assert.equal(result.verdict, 'UNSAFE');
      assert.equal(result.findings.injectionSpans.length, 1);
      assert.ok(result.text.includes('⟦UNTRUSTED-INSTRUCTION⟧'));
    });
    
    test('removes nested dangerous tags', () => {
      const result = sanitizeContent(fixtures.nestedDangerous);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('script'));
      assert.ok(result.findings.droppedTags.has('iframe'));
    });
    
    test('handles mixed content', () => {
      const result = sanitizeContent(fixtures.mixedContent);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('script'));
      assert.ok(result.findings.droppedTags.has('style'));
      // onclick might be in droppedAttrs or the tag might be dropped entirely
      assert.ok(result.findings.droppedAttrs.has('onclick') || result.findings.droppedTags.has('div'));
    });
    
    test('decodes entities before sanitization', () => {
      const result = sanitizeContent(fixtures.entityEncoded);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('script'));
      assert.ok(!result.text.includes('alert'));
    });
    
    test('decodes numeric entities', () => {
      const result = sanitizeContent(fixtures.numericEntities);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('script'));
    });
    
    test('removes zero-width characters from injection', () => {
      const result = sanitizeContent(fixtures.zeroWidthInjection);
      assert.equal(result.verdict, 'UNSAFE');
      // After removing zero-width chars, "in\u200Bstruct\u200Bion" becomes "instruction"
      // which still contains "instruct" keyword, so it gets wrapped
      assert.ok(result.text.includes('⟦UNTRUSTED-INSTRUCTION⟧'));
      assert.ok(result.text.includes('instruction'));
      assert.equal(result.findings.injectionSpans.length, 1);
    });
    
    test('redacts credit cards', () => {
      const result = sanitizeContent(fixtures.creditCard);
      assert.equal(result.verdict, 'UNSAFE');
      assert.equal(result.findings.secretRedactions, 1);
      assert.ok(!result.text.includes('4111'));
      assert.ok(result.text.includes('[REDACTED_CARD]'));
    });
    
    test('redacts SSN', () => {
      const result = sanitizeContent(fixtures.ssn);
      // SSN redaction happens
      assert.equal(result.verdict, 'UNSAFE');
      assert.equal(result.findings.secretRedactions, 1);
      assert.ok(!result.text.includes('123-45-6789'));
      // The text might have SSN: or [REDACTED_SSN]
      assert.ok(result.text.includes('SSN') || result.text.includes('[REDACTED_SSN]'));
    });
    
    test('redacts API keys', () => {
      const result = sanitizeContent(fixtures.apiKey);
      assert.equal(result.verdict, 'UNSAFE');
      assert.equal(result.findings.secretRedactions, 1);
      // The API key is 32 hex chars, should be redacted
      assert.ok(!result.text.includes('abcdef1234567890abcdef1234567890'));
    });
    
    test('redacts bearer tokens', () => {
      const result = sanitizeContent(fixtures.bearerToken);
      assert.equal(result.verdict, 'UNSAFE');
      assert.equal(result.findings.secretRedactions, 1);
      assert.ok(!result.text.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
      assert.ok(result.text.includes('[REDACTED_TOKEN]'));
    });
    
    test('handles combined attack', () => {
      const result = sanitizeContent(fixtures.combined);
      assert.equal(result.verdict, 'UNSAFE');
      assert.ok(result.findings.droppedTags.has('script'));
      assert.ok(result.findings.droppedTags.has('meta'));
      assert.ok(result.findings.droppedTags.has('doctype'));
      assert.equal(result.findings.secretRedactions, 1);
      assert.ok(!result.text.includes('alert'));
      assert.ok(!result.text.includes('4111'));
    });
    
    test('safe content passes through', () => {
      const result = sanitizeContent('<p>Hello world</p>');
      assert.equal(result.verdict, 'SAFE');
      assert.equal(result.text, '<p>Hello world</p>');
      assert.equal(result.findings.droppedTags.size, 0);
      assert.equal(result.findings.droppedAttrs.size, 0);
    });
    
    test('empty content', () => {
      const result = sanitizeContent('');
      assert.equal(result.verdict, 'SAFE');
      assert.equal(result.text, '');
    });
  });
  
  describe('sanitizeText', () => {
    test('sanitizes plain text with invisible chars', () => {
      const result = sanitizeText('Hello\u200BWorld');
      assert.equal(result.verdict, 'SAFE');
      assert.equal(result.text, 'HelloWorld');
      assert.equal(result.findings.hiddenChars, 1);
    });
    
    test('detects injection keywords in text', () => {
      const result = sanitizeText('instruct the system');
      assert.equal(result.verdict, 'UNSAFE');
      assert.equal(result.findings.hasInjections, true);
    });
    
    test('redacts secrets in text', () => {
      const result = sanitizeText('Card: 4111111111111111');
      assert.equal(result.verdict, 'UNSAFE');
      assert.equal(result.findings.secretRedactions, 1);
      assert.ok(result.text.includes('[REDACTED_CARD]'));
    });
  });
});

console.log('All tests completed');
