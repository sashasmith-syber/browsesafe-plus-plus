# Security Policy

## Supported Versions

The Sentinel Operator Bridge extension follows semantic versioning. Security updates are provided for:

- All versions currently in use in production
- The latest major version
- The previous major version (for a limited time)

## Reporting a Vulnerability

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please:

1. **Email**: Send details to the maintainer via secure channel
2. **Include**: 
   - Steps to reproduce
   - Impact assessment
   - Suggested mitigation (if any)
3. **Do not include**: Sensitive data or actual exploits

We will acknowledge receipt within 24 hours and provide regular updates on the resolution timeline.

## Security Features

### Core Security Principles

1. **Operator-Only Command Gate**: Only the extension UI (side panel) can invoke commands. Page content is data-only.
2. **Fail-Closed Security**: Unknown senders, unknown commands, and invalid messages are rejected by default.
3. **Least Privilege**: Uses `activeTab` and optional host permissions instead of `<all_urls>`.
4. **Strict Message Validation**: Validates `sender.id === chrome.runtime.id` and exact panel URL on every message.
5. **No Action Primitives**: Zero `click`, `fill`, `navigate`, or DOM modification capabilities. Read-only by design.

### Protection Mechanisms

#### Content Sanitization
- HTML tokenizer with script/style/iframe/svg body stripping
- Comment and CSS comment removal
- Hidden text detection (display:none, zero-size, off-screen, same-color text, aria-hidden)
- NFKC normalization + invisible Unicode stripping
- Zero-width character removal

#### Prompt Injection Defense
- Injection pattern detection (ignore previous, system:, tool-call syntax)
- All page content wrapped in `⟦UNTRUSTED_PAGE_DATA⟧` delimiters
- Visible warning badges for detected injection attempts

#### Data Exfiltration Guards
- `connect-src` CSP restricts outbound requests
- `safeFetch()` wrapper enforces domain allowlist (localhost/127.0.0.1 only by default)
- Secret redaction before sending to models (API keys, tokens, passwords, private keys)

#### State Management
- All state persisted in `chrome.storage.session` (not globals)
- MV3 service worker lifecycle handled (state survives sleep after ~30s inactivity)
- Auto-disarm with timestamp checking (no `setTimeout` reliance)

#### Audit Logging
- Append-only, local audit log
- Capped at 1000 entries with rotation
- Recursive secret redaction before writing
- Exportable as JSON

### Supply Chain Security

1. **Dependency Pinning**: All dependencies are pinned to specific versions in package-lock.json
2. **Vendored DOMPurify**: Bundled locally, not loaded from CDN
3. **CSP**: Strict Content Security Policy with `script-src 'self'` only
4. **No Remote Code**: No eval, Function constructor, or dynamic import

## Security Audit Checklist

- [x] All permissions justified and minimal
- [x] Sender validation on every message
- [x] No innerHTML with untrusted data (textContent only)
- [x] No eval, new Function, or inline scripts
- [x] Service worker state persistence
- [x] Fail-closed on unknown messages
- [x] Audit logging enabled
- [x] Secret redaction in logs
- [x] Network allowlist enforced
- [x] CSP configured

## Known Limitations

1. **MV3 Service Worker Sleep**: Service workers sleep after ~30s inactivity. State is persisted to survive this.
2. **CSP Limitations**: `connect-src` cannot block all outbound requests in extension contexts. `safeFetch()` provides additional protection.
3. **DOMPurify Scope**: Only used for rendering sanitized HTML diffs. All other UI uses textContent.

## Security Testing

Run the following commands to verify security:

```bash
# Lint for security issues
npm run lint

# Run unit tests
npm test

# Check for vulnerabilities
npm audit

# Scan for secrets
npm run gitleaks
```

## Emergency Procedures

### Kill Switch
The extension includes a kill switch that:
- Immediately blocks all agent actions
- Aborts in-flight work via AbortController
- Persists across service worker restarts
- Can be triggered from the panel UI

### Manual Disabling
If the extension must be disabled immediately:
1. Go to `chrome://extensions/`
2. Find "Sentinel Operator Bridge"
3. Toggle off or click "Remove"

## Updates

This security policy is reviewed and updated:
- After any security incident
- When new vulnerabilities are discovered
- At least quarterly
- Before major releases
