# Sentinel Operator Bridge

A **Chromium MV3 extension** implementing a strict **operator-only command gate** and **content sanitization pipeline** for agentic browsing. This extension enforces the security contract that **page-derived content is untrusted data, sanitized deterministically before reasoning, and only operator-typed input may drive actions**.

## Security Contract

The extension enforces the following guarantees:

1. **Operator-Only Command Gate**: Only the side panel can invoke commands. Messages from tabs are treated as **data-only** and never executed.

2. **No Action Primitives**: The extension has **no** `click`, `fill`, `navigate`, or DOM modification capabilities. It is **read-only by design**.

3. **Deterministic Sanitization**: All page content is sanitized through a tolerant HTML tokenizer (mirroring `html.parser` semantics) before any processing.

4. **Paste-Fencing**: Pasted text is sanitized, wrapped in `⟦DATA⟧...⟦/DATA⟧` markers, and refused outright if it carries injection findings.

5. **Hardened CSP**: `script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'`

6. **textContent-Only Rendering**: All output uses `textContent` (never `innerHTML`, `eval`, or `Function`).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Sentinel Operator Bridge                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │   Panel     │    │  Service    │    │  Content    │    │
│  │ (Operator)   │───▶│  Worker     │───▶│  Script     │    │
│  │             │    │  (Gate)     │    │ (Data-only) │    │
│  └─────────────┘    └─────────────┘    └─────────────┘    │
│           ▲                  ▲                  ▲            │
│           │                  │                  │            │
│           │   Commands       │   Sanitized      │   Raw HTML  │    │
│           │   (Trusted)      │   Data           │   (Untrusted)│   │
│           └──────────────────┴──────────────────┘            │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Library Layer                       │   │
│  │  • patterns.js - Regex tables for detection           │   │
│  │  • sanitize_content.js - HTML sanitizer               │   │
│  │  • sanitize_network.js - Network metadata reducer     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Features

### Content Sanitization

- **HTML Tokenizer**: Tolerant parser mirroring Python's `html.parser` semantics
- **Dangerous Tag Removal**: `<script>`, `<iframe>`, `<object>`, `<embed>`, `<style>`, etc.
- **Event Handler Removal**: `onclick`, `onload`, `onerror`, etc.
- **Hidden Content Removal**: `hidden`, `aria-hidden`, CSS-hidden elements
- **Comment Removal**: HTML comments, CDATA sections, DOCTYPE
- **Entity Decoding**: Named and numeric HTML entities
- **Text Normalization**: NFKC normalization + invisible character stripping

### Injection Detection

- **Keyword Detection**: `instruct`, `system`, `prompt`, `command`, `execute`, `run`, `script`, `eval`, `javascript`, etc.
- **Injection Wrapping**: Detected injections are wrapped in `⟦UNTRUSTED-INSTRUCTION⟧...⟦/UNTRUSTED-INSTRUCTION⟧`
- **Zero-Width Attack Protection**: Removes zero-width spaces, homoglyphs, and other invisible characters

### Secret Redaction

- **Credit Cards**: Luhn-validated card numbers
- **SSN**: Social Security Numbers
- **API Keys**: 32+ character hex strings
- **Bearer Tokens**: JWT and other bearer tokens
- **AWS Keys**: AKIA-prefixed keys
- **Generic Secrets**: `secret=`, `password=`, `token=`, etc.

### Network Metadata Sanitization

- **URL Sanitization**: Removes userinfo, query parameters, fragments
- **Header Filtering**: Only allows safe headers (`Accept`, `Content-Type`, etc.)
- **Body Removal**: Drops request/response bodies entirely
- **Cookie Redaction**: Removes `Cookie`, `Set-Cookie`, `Authorization` headers

## Commands

All commands are **operator-only** and must be typed in the side panel:

| Command | Description |
|---------|-------------|
| `read_page` | Read and sanitize current page content |
| `set_directive` | Set an operator directive (sanitized) |
| `start_capture` | Start capturing sanitized page content |
| `stop_capture` | Stop capture and return results |
| `get_capture` | Retrieve captured content |
| `screenshot` | Take a screenshot of current tab |
| `sanitize_content` | Sanitize provided HTML content |
| `sanitize_network` | Sanitize provided network data |

## Threat Model

### Attack Vectors Mitigated

1. **Prompt Injection**: Page content cannot inject prompts or instructions
2. **XSS Attacks**: Script tags, event handlers, and JavaScript URIs are removed
3. **Hidden Content Exfiltration**: Hidden text (CSS, ARIA, comments) is removed
4. **Invisible Character Attacks**: Zero-width and other invisible characters are stripped
5. **Homoglyph Attacks**: Confusing characters are detected and normalized
6. **Secret Leakage**: API keys, tokens, and other secrets are redacted
7. **Clickjacking**: No click/fill/navigate primitives exist
8. **Clipboard Injection**: Pasted content is sanitized and fenced

### Trust Boundaries

- **Trusted**: Side panel (operator input)
- **Untrusted**: Tab content, clipboard, network responses
- **Data-Only**: Content scripts can only send data, never receive commands

## Installation

### Development

```bash
# Clone the repository
cd browsesafe-plus-plus/extensions/sentinel-operator-bridge

# Load in Chrome
# 1. Open chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select this directory
```

### Production

Package the extension and distribute via Chrome Web Store or enterprise policy.

## Testing

```bash
# Run tests with Node.js
cd tests
node --test test_sanitize.test.mjs
```

All 20 tests should pass, covering:
- Entity decoding
- Text normalization
- Injection detection
- Tag/attribute removal
- Hidden content removal
- Secret redaction
- Combined attacks

## Verification

The extension has been cross-validated against the original Python reference implementation (`sanitize_content.py`) on shared fixtures, producing **byte-identical findings** for:
- Dropped tags
- Dropped attributes
- Hidden character counts
- Injection locations
- Redaction counts
- Final verdict

## License

This extension is part of the BrowseSafe++ benchmark and is licensed under the same terms as the parent repository.

## Security Audit

- ✅ No `innerHTML` usage (verified by grep scan)
- ✅ No `eval` or `Function` usage
- ✅ No `document.write` or `document.writeIn`
- ✅ No dynamic script insertion
- ✅ Hardened CSP
- ✅ Least-privilege permissions
- ✅ Operator-only command gate
- ✅ textContent-only DOM writes
