// Sentinel Operator Bridge - Content Sanitizer
// Faithful JS port of Python sanitize_content.py
// Tolerant HTML tokenizer mirroring html.parser semantics

import {
  INVISIBLE,
  ZERO_WIDTH,
  INJECTION_KEYWORDS,
  SCRIPT_TAGS,
  DANGEROUS_ATTRS,
  HIDDEN_ATTRS,
  ENTITY_PATTERN,
  HTML_COMMENT,
  CSS_COMMENT,
  CDATA,
  DOCTYPE
} from './patterns.js';

/**
 * Decode HTML entities (numeric and named)
 * @param {string} text - Text to decode
 * @returns {string} Decoded text
 */
export function decodeEntities(text) {
  return text.replace(ENTITY_PATTERN, (match, hex, dec, named) => {
    if (hex) {
      const code = parseInt(hex, 16);
      if (code >= 0 && code <= 0x10FFFF && !isNaN(code)) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return match;
        }
      }
    } else if (dec) {
      const code = parseInt(dec, 10);
      if (code >= 0 && code <= 0x10FFFF && !isNaN(code)) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return match;
        }
      }
    } else if (named) {
      // Basic named entity support
      const entities = {
        'amp': '&',
        'lt': '<',
        'gt': '>',
        'quot': '"',
        'apos': "'",
        'nbsp': '\u00A0',
        'copy': '\u00A9',
        'reg': '\u00AE',
        'trade': '\u2122'
      };
      const lower = named.toLowerCase();
      if (entities[lower]) {
        return entities[lower];
      }
    }
    return match;
  });
}

/**
 * Normalize text (NFKC normalization + invisible char stripping)
 * @param {string} text - Text to normalize
 * @returns {string} Normalized text
 */
export function normalizeText(text) {
  // NFKC normalization
  let normalized = text.normalize('NFKC');
  
  // Remove invisible characters
  normalized = normalized.replace(INVISIBLE, '');
  
  // Remove zero-width characters
  normalized = normalized.replace(ZERO_WIDTH, '');
  
  return normalized;
}

/**
 * Check if text contains injection keywords
 * @param {string} text - Text to check
 * @returns {boolean} True if injection keywords found
 */
export function hasInjectionKeywords(text) {
  const lowerText = text.toLowerCase();
  for (const keyword of INJECTION_KEYWORDS) {
    if (lowerText.includes(keyword)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if tag is a script/dangerous tag
 * @param {string} tag - Tag name
 * @returns {boolean} True if dangerous
 */
function isDangerousTag(tag) {
  return SCRIPT_TAGS.has(tag.toLowerCase());
}

/**
 * Check if attribute is dangerous
 * @param {string} attr - Attribute name
 * @returns {boolean} True if dangerous
 */
function isDangerousAttr(attr) {
  const lowerAttr = attr.toLowerCase();
  for (const dangerous of DANGEROUS_ATTRS) {
    if (lowerAttr.includes(dangerous.toLowerCase())) {
      return true;
    }
  }
  return false;
}

/**
 * Check if attribute indicates hidden content
 * @param {string} attr - Attribute name
 * @returns {boolean} True if hidden
 */
function isHiddenAttrName(attr) {
  const lowerAttr = attr.toLowerCase();
  // Check exact matches
  if (HIDDEN_ATTRS.has(lowerAttr)) {
    return true;
  }
  // Check data-* prefix (HIDDEN_ATTRS contains 'data-')
  for (const hidden of HIDDEN_ATTRS) {
    if (hidden === 'data-' && lowerAttr.startsWith('data-')) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a style attribute value indicates hidden content
 * @param {string} value - Style value
 * @returns {boolean} True if hidden
 */
function isHiddenStyle(value) {
  const lowerValue = value.toLowerCase();
  return lowerValue.includes('display:none') ||
         lowerValue.includes('visibility:hidden') ||
         lowerValue.includes('opacity:0') ||
         lowerValue.includes('hidden');
}

/**
 * Simple HTML tokenizer (mirrors html.parser semantics)
 * @param {string} html - HTML to tokenize
 * @returns {Array} Array of tokens
 */
function tokenizeHTML(html) {
  const tokens = [];
  let i = 0;
  
  while (i < html.length) {
    if (html[i] === '<') {
      // Tag or comment
      if (html[i + 1] === '!') {
        // Comment or CDATA or DOCTYPE
        if (html.substr(i, 4) === '<!--') {
          const end = html.indexOf('-->', i + 4);
          if (end !== -1) {
            tokens.push({ type: 'comment', value: html.slice(i, end + 3), start: i, end: end + 3 });
            i = end + 3;
            continue;
          }
        } else if (html.substr(i, 9).toLowerCase() === '<![cdata[') {
          const end = html.indexOf(']]>', i + 9);
          if (end !== -1) {
            tokens.push({ type: 'cdata', value: html.slice(i, end + 3), start: i, end: end + 3 });
            i = end + 3;
            continue;
          }
        } else if (html.substr(i, 9).toLowerCase().startsWith('<!doctype')) {
          const end = html.indexOf('>', i + 9);
          if (end !== -1) {
            tokens.push({ type: 'doctype', value: html.slice(i, end + 1), start: i, end: end + 1 });
            i = end + 1;
            continue;
          }
        }
      }
      
      // Opening or closing tag
      const end = html.indexOf('>', i + 1);
      if (end !== -1) {
        const tagContent = html.slice(i + 1, end);
        const spaceIndex = tagContent.indexOf(' ');
        let tagName, attrs = {};
        
        if (spaceIndex === -1) {
          tagName = tagContent;
        } else {
          tagName = tagContent.slice(0, spaceIndex);
          // Parse attributes
          const attrStr = tagContent.slice(spaceIndex + 1);
          // Use a simple state machine to parse attributes
          let i = 0;
          while (i < attrStr.length) {
            // Skip whitespace
            while (i < attrStr.length && attrStr[i].match(/\s/)) i++;
            if (i >= attrStr.length) break;
            
            // Read attribute name
            let attrStart = i;
            while (i < attrStr.length && !attrStr[i].match(/\s|=/)) i++;
            const attrName = attrStr.slice(attrStart, i);
            
            // Skip whitespace
            while (i < attrStr.length && attrStr[i].match(/\s/)) i++;
            
            // Check for = sign
            if (i < attrStr.length && attrStr[i] === '=') {
              i++; // Skip =
              // Skip whitespace
              while (i < attrStr.length && attrStr[i].match(/\s/)) i++;
              
              // Read value
              if (i < attrStr.length) {
                if (attrStr[i] === '"' || attrStr[i] === "'") {
                  const quote = attrStr[i];
                  i++;
                  attrStart = i;
                  while (i < attrStr.length && attrStr[i] !== quote) i++;
                  attrs[attrName] = attrStr.slice(attrStart, i);
                  i++; // Skip closing quote
                } else {
                  attrStart = i;
                  while (i < attrStr.length && !attrStr[i].match(/\s/)) i++;
                  attrs[attrName] = attrStr.slice(attrStart, i);
                }
              }
            } else {
              // Boolean attribute
              attrs[attrName] = '';
            }
          }
        }
        
        const isClosing = tagName.startsWith('/');
        if (isClosing) {
          tagName = tagName.slice(1);
        }
        
        tokens.push({
          type: isClosing ? 'endTag' : 'startTag',
          tag: tagName.toLowerCase(),
          attrs,
          start: i,
          end: end + 1
        });
        
        i = end + 1;
        continue;
      }
    }
    
    // Text node
    const nextTag = html.indexOf('<', i);
    if (nextTag === -1) {
      tokens.push({ type: 'text', value: html.slice(i), start: i, end: html.length });
      break;
    }
    
    tokens.push({ type: 'text', value: html.slice(i, nextTag), start: i, end: nextTag });
    i = nextTag;
  }
  
  return tokens;
}

/**
 * Sanitize HTML content
 * @param {string} html - HTML content to sanitize
 * @param {Object} options - Sanitization options
 * @returns {Object} Sanitized content and metadata
 */
export function sanitizeContent(html, options = {}) {
  const {
    wrapInjections = true,
    redactSecrets = true,
    removeHidden = true,
    removeScripts = true
  } = options;
  
  // Decode entities first
  let text = decodeEntities(html);
  
  // Normalize text
  text = normalizeText(text);
  
  // Tokenize HTML
  const tokens = tokenizeHTML(text);
  
  let result = '';
  let inDangerousTag = false;
  let inHiddenTag = false;
  const findings = {
    droppedTags: new Set(),
    droppedAttrs: new Set(),
    hiddenChars: 0,
    injectionSpans: [],
    secretRedactions: 0
  };
  
  // First pass: count invisible chars in original
  const invisibleMatches = html.match(INVISIBLE) || [];
  findings.hiddenChars = invisibleMatches.length;
  
  // Second pass: process tokens
  for (const token of tokens) {
    switch (token.type) {
      case 'comment':
      case 'cdata':
      case 'doctype':
        findings.droppedTags.add(token.type);
        break;
        
      case 'startTag':
        if (isDangerousTag(token.tag)) {
          findings.droppedTags.add(token.tag);
          inDangerousTag = true;
        } else {
          // Check for dangerous attributes
          let hasDangerous = false;
          let isHidden = false;
          
          for (const [attr, value] of Object.entries(token.attrs)) {
            if (isDangerousAttr(attr)) {
              findings.droppedAttrs.add(attr);
              hasDangerous = true;
            }
            if (isHiddenAttrName(attr)) {
              // Check if it's a boolean hidden attribute or has hidden value
              if (attr.toLowerCase() === 'hidden' || 
                  attr.toLowerCase() === 'aria-hidden' ||
                  (attr.toLowerCase() === 'style' && isHiddenStyle(value))) {
                isHidden = true;
              }
            }
          }
          
          if (hasDangerous) {
            // Drop the entire tag
            findings.droppedTags.add(token.tag);
            inDangerousTag = true;
          } else if (isHidden && removeHidden) {
            // Drop hidden tags and their content
            findings.droppedTags.add(token.tag);
            inHiddenTag = true;
          } else {
            // Keep the tag but sanitize attributes
            result += `<${token.tag}`;
            for (const [attr, value] of Object.entries(token.attrs)) {
              if (!isDangerousAttr(attr) && !isHiddenAttrName(attr)) {
                result += ` ${attr}="${value.replace(/["&<>]/g, c => 
                  c === '"' ? '&quot;' : 
                  c === '&' ? '&amp;' : 
                  c === '<' ? '&lt;' : 
                  '&gt;')}"`;
              } else if (isHiddenAttrName(attr)) {
                // Still track that we found hidden attributes
                findings.droppedAttrs.add(attr);
              }
            }
            result += '>';
          }
        }
        break;
        
      case 'endTag':
        if (inDangerousTag && isDangerousTag(token.tag)) {
          inDangerousTag = false;
        } else if (inHiddenTag && token.tag === 'div') {
          // End of hidden div
          inHiddenTag = false;
        } else if (inHiddenTag) {
          // End of any hidden tag
          inHiddenTag = false;
        } else {
          result += `</${token.tag}>`;
        }
        break;
        
      case 'text':
        if (inDangerousTag || inHiddenTag) {
          // Drop text inside dangerous tags or hidden content
          break;
        }
        
        let textContent = token.value;
        
        // Check for injection keywords BEFORE normalization
        const hasInjections = hasInjectionKeywords(textContent);
        
        // Normalize text content
        textContent = normalizeText(textContent);
        
        // Check again after normalization
        const stillHasInjections = hasInjections || hasInjectionKeywords(textContent);
        
        // Wrap injection keywords
        if (stillHasInjections && wrapInjections) {
          findings.injectionSpans.push({
            start: result.length,
            end: result.length + textContent.length,
            text: textContent
          });
          textContent = `⟦UNTRUSTED-INSTRUCTION⟧${textContent}⟦/UNTRUSTED-INSTRUCTION⟧`;
        }
        
        // Redact secrets
        if (redactSecrets) {
          const originalText = textContent;
          textContent = redactSecretsInText(textContent);
          if (textContent !== originalText) {
            findings.secretRedactions++;
          }
        }
        
        result += textContent;
        break;
    }
  }
  
  return {
    text: result,
    html: result,
    findings,
    verdict: findings.droppedTags.size > 0 || findings.droppedAttrs.size > 0 || 
             findings.injectionSpans.length > 0 || findings.secretRedactions > 0 ? 
             'UNSAFE' : 'SAFE'
  };
}

/**
 * Redact secrets from text
 * @param {string} text - Text to redact
 * @returns {string} Text with secrets redacted
 */
function redactSecretsInText(text) {
  // SSN
  text = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');
  
  // Credit card numbers (Luhn check)
  text = text.replace(/\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b/g, (match) => {
    const clean = match.replace(/[\s-]/g, '');
    if (clean.length >= 13 && clean.length <= 19) {
      let sum = 0;
      let shouldDouble = false;
      for (let i = clean.length - 1; i >= 0; i--) {
        let digit = parseInt(clean[i], 10);
        if (shouldDouble) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
      }
      if (sum % 10 === 0) {
        return '[REDACTED_CARD]';
      }
    }
    return match;
  });
  
  // Bearer tokens
  text = text.replace(/Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi, '[REDACTED_TOKEN]');
  
  // AWS keys
  text = text.replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]');
  
  // Generic secret patterns
  text = text.replace(/(?:secret|password|token|key|api[_-]?key)\s*[:=]\s*['"]?[^\s'"]+['"]?/gi, '$1=[REDACTED]');
  
  // API keys (32+ hex chars)
  text = text.replace(/\b[A-Fa-f0-9]{32,}\b/g, '[REDACTED_API_KEY]');
  
  return text;
}

/**
 * Quick sanitize for plain text (no HTML)
 * @param {string} text - Text to sanitize
 * @returns {Object} Sanitized text and findings
 */
export function sanitizeText(text) {
  const normalized = normalizeText(text);
  const hasInjections = hasInjectionKeywords(normalized);
  const redacted = redactSecretsInText(normalized);
  
  return {
    text: redacted,
    findings: {
      hiddenChars: (text.match(INVISIBLE) || []).length,
      hasInjections,
      secretRedactions: redacted !== normalized ? 1 : 0
    },
    verdict: hasInjections || redacted !== normalized ? 'UNSAFE' : 'SAFE'
  };
}

export default {
  sanitizeContent,
  sanitizeText,
  decodeEntities,
  normalizeText,
  hasInjectionKeywords
};
