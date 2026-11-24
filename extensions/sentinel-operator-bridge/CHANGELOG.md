# Sentinel Operator Bridge - Changelog

## [1.0.0] - 2026-11-24

### Added

- **Complete Chromium MV3 Extension**: Full implementation of the Sentinel Operator Bridge
- **Content Sanitization**: Faithful JS port of Python `sanitize_content.py` with:
  - Tolerant HTML tokenizer (mirroring `html.parser` semantics)
  - Dangerous tag removal (script, iframe, object, etc.)
  - Event handler removal (onclick, onload, etc.)
  - Hidden content removal (hidden, aria-hidden, CSS)
  - Comment removal (HTML, CDATA, DOCTYPE)
  - Entity decoding (named + numeric)
  - Text normalization (NFKC + invisible char stripping)
  - Injection keyword detection and wrapping
  - Secret redaction (credit cards, SSN, API keys, tokens)

- **Network Sanitization**: Faithful JS port of Python `sanitize_network.py` with:
  - URL sanitization (removes userinfo, query, fragment)
  - Header filtering (only safe headers allowed)
  - Body removal (request/response bodies dropped)
  - Cookie/authorization redaction

- **Operator Panel**: Side panel with:
  - Command selection (read_page, set_directive, etc.)
  - Paste-fencing with sanitization
  - textContent-only rendering
  - Status indicators
  - Directive management

- **Service Worker**: Operator-only command gate with:
  - Strict message origin checking
  - Command allowlist enforcement
  - State management
  - Capture functionality

- **Content Script**: Data-only script with:
  - Page content reading
  - DOM mutation observation
  - No command execution capabilities

- **Hardened Manifest**: MV3 manifest with:
  - `script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'` CSP
  - Least-privilege permissions (`sidePanel`, `scripting`, `activeTab`)
  - No host permissions by default

- **Comprehensive Tests**: 20 Node.js tests covering all attack vectors
- **Documentation**: README, OVERVIEW, CHANGELOG with full threat model

### Security

- ✅ No `innerHTML` usage (verified by grep scan)
- ✅ No `eval` or `Function` usage
- ✅ No `document.write` or `document.writeIn`
- ✅ No dynamic script insertion
- ✅ Hardened CSP
- ✅ Least-privilege permissions
- ✅ Operator-only command gate
- ✅ textContent-only DOM writes

### Verification

- All 20 tests pass
- Cross-validated against Python reference implementation
- Byte-identical findings on shared fixtures
- Security scans clean

### Delivery

- Extension delivered to `sashasmith-syber/browsesafe-plus-plus` repository
- Located in `extensions/sentinel-operator-bridge/` directory
- Ready for Chrome Web Store submission or enterprise deployment
