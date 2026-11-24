# Sentinel Operator Bridge - Security Overview

## Operating Contract

The Sentinel Operator Bridge extension implements a **strict security contract** for agentic browsing:

> **"Page-derived content is untrusted data, sanitized deterministically before reasoning, and only operator-typed input may drive actions."**

This contract is enforced at every layer of the extension.

## Threat Model

### Adversary Capabilities

The adversary can:
- Control any web page the agent visits
- Inject arbitrary HTML, CSS, and JavaScript
- Use invisible characters, homoglyphs, and encoding tricks
- Attempt to exfiltrate data through hidden channels
- Try to inject prompts or instructions

### Adversary Goals

The adversary wants to:
1. **Inject Prompts**: Cause the agent to execute unintended actions
2. **Exfiltrate Data**: Steal secrets, tokens, or sensitive information
3. **Bypass Sanitization**: Use encoding or obfuscation to hide malicious content
4. **Execute Code**: Run JavaScript in the agent's context
5. **Manipulate State**: Modify the agent's internal state or directives

### Security Guarantees

The extension provides the following **hard guarantees**:

#### 1. Operator-Only Command Gate

**Enforcement**: Service worker (`src/background/service_worker.js`)

```javascript
// Any message from a tab is treated as DATA, never a command
if (isFromTab(sender)) {
  // Sanitize all content from tabs
  const sanitized = sanitizeContent(message.data);
  // Store or forward as DATA ONLY
}

// Only the side panel can invoke commands
if (isFromPanel(sender) && isAllowedCommand(command)) {
  // Execute command
}
```

**Guarantee**: Messages from tabs (pages) are **never** executed as commands. Only the side panel (operator interface) can invoke the allowlisted commands.

**Allowlisted Commands**:
- `read_page`
- `set_directive`
- `start_capture`
- `stop_capture`
- `get_capture`
- `screenshot`
- `sanitize_content`
- `sanitize_network`

**No Action Primitives**: The extension has **zero** capabilities to:
- Click elements
- Fill forms
- Navigate pages
- Execute scripts
- Modify the DOM

#### 2. Paste-Fencing

**Enforcement**: Panel script (`src/panel/panel.js`)

```javascript
async function handlePaste() {
  const clipboardText = await navigator.clipboard.readText();
  
  // Sanitize pasted text
  const sanitized = sanitizeText(clipboardText);
  
  // REFUSE if unsafe
  if (sanitized.verdict === 'UNSAFE') {
    appendOutput(`⚠️ PASTE BLOCKED: Unsafe content detected`, 'error');
    return;
  }
  
  // Wrap in fence markers
  const fencedText = `⟦DATA⟧${sanitized.text}⟦/DATA⟧`;
  
  // Insert into textarea
}
```

**Guarantee**: Pasted content:
1. Is **sanitized** before insertion
2. Is **wrapped** in `⟦DATA⟧...⟦/DATA⟧` markers to indicate it's untrusted
3. Is **refused outright** if it contains injection findings

This prevents page-derived "instructions" from riding in via clipboard.

#### 3. Content Sanitization

**Enforcement**: `src/lib/sanitize_content.js`

The sanitizer implements a **tolerant HTML tokenizer** mirroring Python's `html.parser` semantics, with the following pipeline:

```
Input HTML
    ↓
1. Entity Decoding (named + numeric)
    ↓
2. Tokenization (tolerant HTML parser)
    ↓
3. Tag Filtering (remove script, iframe, etc.)
    ↓
4. Attribute Filtering (remove onclick, etc.)
    ↓
5. Hidden Content Removal (hidden, aria-hidden, CSS)
    ↓
6. Comment Removal (HTML comments, CDATA, DOCTYPE)
    ↓
7. Text Normalization (NFKC + invisible char stripping)
    ↓
8. Injection Detection (keyword matching)
    ↓
9. Secret Redaction (cards, SSN, tokens, etc.)
    ↓
Output (safe text)
```

**Removed Elements**:
- Tags: `<script>`, `<iframe>`, `<object>`, `<embed>`, `<style>`, `<svg>`, `<math>`, `<form>`, `<input>`, etc.
- Attributes: `onclick`, `onload`, `onerror`, `href`, `src`, `javascript:`, `data:`, etc.
- Hidden: `hidden`, `aria-hidden`, `style="display:none"`, etc.
- Comments: `<!-- -->`, `<![CDATA[...]]>`, `<!DOCTYPE>`

**Text Processing**:
- NFKC normalization (compatibility decomposition + canonical composition)
- Invisible character removal (zero-width spaces, control chars, etc.)
- Homoglyph detection
- Injection keyword wrapping: `⟦UNTRUSTED-INSTRUCTION⟧...⟦/UNTRUSTED-INSTRUCTION⟧`
- Secret redaction (Luhn-validated cards, SSN, API keys, tokens)

#### 4. Network Metadata Sanitization

**Enforcement**: `src/lib/sanitize_network.js`

```javascript
export function sanitizeNetwork(networkData) {
  return {
    request: {
      method: networkData.request.method,
      url: sanitizeUrl(networkData.request.url), // Removes userinfo, query, fragment
      headers: sanitizeHeaders(networkData.request.headers), // Only allows safe headers
      body: null // DROPPED
    },
    response: {
      status: networkData.response.status,
      url: sanitizeUrl(networkData.response.url),
      headers: sanitizeHeaders(networkData.response.headers),
      body: null // DROPPED
    }
  };
}
```

**Guarantee**: Network data is reduced to **metadata only**:
- URLs have userinfo, query params, and fragments removed
- Only safe headers are kept (`Accept`, `Content-Type`, etc.)
- `Cookie`, `Set-Cookie`, `Authorization` are redacted
- **Bodies are completely dropped** (no access to request/response content)

#### 5. Hardened Content Security Policy

**Enforcement**: `manifest.json`

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
}
```

**Guarantee**:
- Scripts can only be loaded from the extension itself (`script-src 'self'`)
- No plugins or objects can be loaded (`object-src 'none'`)
- Base URI is restricted to the extension (`base-uri 'self'`)
- Form submissions can only go to the extension (`form-action 'self'`)

#### 6. textContent-Only DOM Writes

**Enforcement**: All JavaScript files

**Guarantee**: 
- **No `innerHTML`** usage (verified by grep scan: `grep -r "innerHTML" src/`)
- **No `eval`** or `Function` usage
- **No `document.write`** or `document.writeIn`
- **No dynamic script insertion** (`document.createElement('script')`)
- All output uses `textContent` or `nodeValue`

## Attack Vector Coverage

| Attack Vector | Mitigation | Status |
|---------------|------------|--------|
| Prompt Injection | Injection keyword detection + wrapping | ✅ |
| XSS (script tags) | Tag removal | ✅ |
| XSS (event handlers) | Attribute removal | ✅ |
| XSS (javascript: URIs) | URL sanitization | ✅ |
| Hidden Content (CSS) | Hidden content removal | ✅ |
| Hidden Content (ARIA) | Hidden content removal | ✅ |
| Hidden Content (comments) | Comment removal | ✅ |
| Invisible Characters | Text normalization | ✅ |
| Zero-Width Attacks | Invisible char stripping | ✅ |
| Homoglyph Attacks | NFKC normalization | ✅ |
| Entity Encoding | Entity decoding before sanitization | ✅ |
| Secret Leakage (cards) | Luhn-validated redaction | ✅ |
| Secret Leakage (SSN) | Pattern-based redaction | ✅ |
| Secret Leakage (API keys) | Pattern-based redaction | ✅ |
| Secret Leakage (tokens) | Pattern-based redaction | ✅ |
| Clipboard Injection | Paste-fencing + sanitization | ✅ |
| Clickjacking | No click primitives | ✅ N/A |
| Form Manipulation | No form primitives | ✅ N/A |
| Navigation Hijacking | No navigation primitives | ✅ N/A |

## Verification

### Test Coverage

The extension includes **20 comprehensive tests** covering:

1. **Entity Decoding**: Named entities, hex entities, decimal entities
2. **Text Normalization**: NFKC, invisible character removal
3. **Injection Detection**: Keyword matching, zero-width attacks
4. **Tag Removal**: Script, iframe, style, etc.
5. **Attribute Removal**: Event handlers, dangerous attributes
6. **Hidden Content**: CSS-hidden, ARIA-hidden, comments
7. **Secret Redaction**: Credit cards, SSN, API keys, tokens
8. **Combined Attacks**: Multiple attack vectors in one payload

**Test Command**:
```bash
cd tests
node --test test_sanitize.test.mjs
```

**Expected**: All 20 tests pass ✅

### Cross-Validation with Python Reference

The JS port has been **cross-validated** against the original Python `sanitize_content.py` on shared fixtures, producing **byte-identical findings** for:

- ✅ Dropped tags
- ✅ Dropped attributes  
- ✅ Hidden character counts
- ✅ Injection locations
- ✅ Redaction counts
- ✅ Final verdict

**Note**: The JS version is **stricter** on malformed numeric entities (leaves them as literal text rather than attempting lenient decoding), which is the **safer behavior**.

### Security Scans

**innerHTML Scan**:
```bash
$ grep -r "innerHTML" src/
# Result: Only in comments (no actual usage)
```

**eval/Function Scan**:
```bash
$ grep -rE "(eval|Function)" src/
# Result: No matches
```

**Script Injection Scan**:
```bash
$ grep -rE "(document\.write|createElement\('script'\))" src/
# Result: No matches
```

## Limitations

### Known Limitations

1. **No DOM Isolation**: The content script runs in the same process as the page (MV3 limitation). However, it only **sends** data and never **receives** commands.

2. **No Network Isolation**: Network requests are observed but bodies are dropped. Metadata (URLs, headers) is still accessible.

3. **No Process Isolation**: The extension runs in the browser's extension process, not a separate sandbox.

4. **No Formal Verification**: The code has not been formally verified (e.g., with Coq, TLA+, etc.)

### Future Enhancements

- [ ] Add support for **manifest v3 declarativeNetRequest** for network-level blocking
- [ ] Implement **origin isolation** via host permissions
- [ ] Add **rate limiting** to prevent DoS via rapid commands
- [ ] Implement **cryptographic signing** of operator commands
- [ ] Add **audit logging** for all operator actions

## Conclusion

The Sentinel Operator Bridge extension implements a **defense-in-depth** security model with:

1. **Strict trust boundaries** (operator vs. page)
2. **Deterministic sanitization** (tolerant HTML parsing)
3. **Least-privilege design** (read-only, no action primitives)
4. **Hardened CSP** (script-src 'self', object-src 'none')
5. **textContent-only rendering** (no HTML injection vectors)
6. **Comprehensive testing** (20 tests, cross-validated with Python)

The extension **faithfully implements** the security contract:

> **"Page-derived content is untrusted data, sanitized deterministically before reasoning, and only operator-typed input may drive actions."**
