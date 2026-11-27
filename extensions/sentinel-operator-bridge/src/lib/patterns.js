// Sentinel Operator Bridge - Pattern Library
// Faithful JS port of Python regex tables with JS-compatible flag handling

/**
 * Regex patterns for detecting and sanitizing untrusted content
 * All patterns use JS-compatible flags (g, i, m, s, u, y)
 */

export const INVISIBLE = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3000\uFEFF\uFFA0\u{1D173}-\u{1D17A}\u{E0000}-\u{E007F}]/gu;

export const ZERO_WIDTH = /[\u200B-\u200D\u2060-\u2064\uFEFF\u{1D173}-\u{1D17A}\u{E0000}-\u{E007F}]/gu;

export const HOMOGLYPHS = {
  'a': /[\u0430\u03B1\u00E0-\u00E5]/gi,
  'b': /[\u0431\u03B2]/gi,
  'c': /[\u0441\u03C3]/gi,
  'd': /[\u0434]/gi,
  'e': /[\u0435\u03B5\u00E8-\u00EB]/gi,
  'f': /[\u0444]/gi,
  'g': /[\u0433]/gi,
  'h': /[\u0445]/gi,
  'i': /[\u0438\u0439\u03B9\u03B7\u00EC-\u00EF]/gi,
  'j': /[\u043A]/gi,
  'k': /[\u043A\u03BA]/gi,
  'l': /[\u043B\u043C\u00A1]/gi,
  'm': /[\u043C]/gi,
  'n': /[\u043D]/gi,
  'o': /[\u043E\u03BF\u00F2-\u00F6\u00F8-\u00FA]/gi,
  'p': /[\u043F]/gi,
  'q': /[\u0440]/gi,
  'r': /[\u0440]/gi,
  's': /[\u0441\u03C2\u03C3]/gi,
  't': /[\u0442]/gi,
  'u': /[\u0443\u03C5\u00F9-\u00FC]/gi,
  'v': /[\u0432\u03BD]/gi,
  'w': /[\u0432\u03C9]/gi,
  'x': /[\u0445\u03C7]/gi,
  'y': /[\u0443\u03B3\u00FD\u00FF]/gi,
  'z': /[\u0437\u03B6]/gi
};

export const INJECTION_KEYWORDS = [
  'instruct',
  'instruction',
  'system',
  'prompt',
  'command',
  'execute',
  'run',
  'script',
  'eval',
  'function',
  'javascript',
  'jscript',
  'vbscript',
  'onerror',
  'onload',
  'onclick',
  'href',
  'src',
  'data:',
  'blob:',
  'fetch',
  'xmlhttprequest',
  'iframe',
  'object',
  'embed',
  'ignore previous',
  'forget previous',
  'disregard previous',
  'ignore all previous',
  'ignore above',
  'tool_call',
  'im_start',
  'inst'
];

/**
 * Prompt injection regex patterns for detecting system override attempts
 */
export const INJECTION_PATTERNS = [
  /ignore\s+previous/i,
  /ignore\s+all\s+previous/i,
  /ignore\s+above/i,
  /forget\s+previous/i,
  /disregard\s+previous/i,
  /disregard\s+all\s+previous/i,
  /system\s*:/i,
  /<\|im_start\|>/i,
  /<\[im_start\]>/i,
  /\[inst\]/i,
  /<inst>/i,
  /<\/inst>/i,
  /tool_call/i,
  /<tool_call>/i,
  /\[tool_call\]/i,
  /<function\s+calls>/i,
  /<function\s+call>/i,
  /<invoke>/i,
  /role\s*=\s*["']?system["']?/i,
  /role\s*=\s*["']?assistant["']?/i,
  /role\s*=\s*["']?user["']?/i
];

export const SCRIPT_TAGS = new Set([
  'script',
  'iframe',
  'object',
  'embed',
  'applet',
  'meta',
  'link',
  'style',
  'svg',
  'math',
  'form',
  'input',
  'button',
  'select',
  'textarea'
]);

export const DANGEROUS_ATTRS = new Set([
  'onclick',
  'ondblclick',
  'onmouseover',
  'onmouseout',
  'onmousemove',
  'onmousedown',
  'onmouseup',
  'onkeydown',
  'onkeypress',
  'onkeyup',
  'onload',
  'onunload',
  'onerror',
  'onabort',
  'onsubmit',
  'onreset',
  'onfocus',
  'onblur',
  'onchange',
  'onselect',
  'javascript:',
  'data:',
  'vbscript:',
  'on',
  'href',
  'src',
  'action',
  'formaction',
  'background',
  'dynsrc',
  'lowsrc'
]);

export const HIDDEN_ATTRS = new Set([
  'hidden',
  'aria-hidden',
  'style',
  'class',
  'id',
  'data-'
]);

export const NETWORK_ALLOWED_HEADERS = new Set([
  'accept',
  'accept-encoding',
  'accept-language',
  'cache-control',
  'connection',
  'content-length',
  'content-type',
  'date',
  'host',
  'origin',
  'referer',
  'user-agent',
  'x-requested-with'
]);

export const REDACTION_PATTERNS = {
  // Credit card numbers (Luhn-validated)
  creditCard: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
  // Social Security Numbers
  ssn: /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/g,
  // API keys (generic pattern)
  apiKey: /\b[A-Za-z0-9]{32,}\b/g,
  // Bearer tokens
  bearerToken: /Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi,
  // AWS access keys
  awsKey: /AKIA[0-9A-Z]{16}/g,
  // Generic secrets
  secret: /(?:secret|password|token|key|api[_-]?key)\s*[:=]\s*['"]?[^\s'"]+['"]?/gi
};

export const ENTITY_PATTERN = /&(?:#x([0-9a-f]+)|#([0-9]+)|([a-z]+));/gi;

export const HTML_COMMENT = /<!--[\s\S]*?-->/g;

export const CSS_COMMENT = /\/\*[\s\S]*?\*\//g;

export const CDATA = /<!\[CDATA\[[\s\S]*?\]\]>/gi;

export const DOCTYPE = /<!DOCTYPE[^>]*>/gi;
