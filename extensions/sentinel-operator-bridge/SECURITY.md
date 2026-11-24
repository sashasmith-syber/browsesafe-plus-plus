# Sentinel Operator Bridge — Security Policy

This document describes the security posture, guarantees, and vulnerability
reporting process of the **Sentinel Operator Bridge** Chromium extension
(delivered under `extensions/sentinel-operator-bridge/` in the
[BrowseSafe++](https://github.com/sashasmith-syber/browsesafe-plus-plus) repository).

## Supported Versions

| Version | Released | Supported |
|---------|----------|-----------|
| 1.1.0 | 2026-11-24 | ✅ |
| 1.0.0 | 2026-11-24 | ❌ (superseded by 1.1.0) |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use one of the following channels:

1. **GitHub Security Advisories** (preferred) on this repository — see the
   *Security* tab.
2. **Direct contact**: open a private security advisory or reach the repository
   maintainers via the contact channels listed in the main
   [BrowseSafe++ README](../README.md).

Include the following in reports:

- Type of issue (e.g., sanitizer bypass, command-gate bypass, CSP escape,
  secret leakage, XSS).
- Affected component (`src/lib/`, `src/background/`, `src/content/`,
  `src/panel/`, `manifest.json`).
- Step-by-step reproduction or proof of concept.
- Impact assessment (what an adversary could achieve against an agentic
  browsing session).

We aim to acknowledge reports within 72 hours and will keep reporters informed
of remediation progress. Please avoid public disclosure until a fix is released.

## Threat Model Summary

The full adversarial model is documented in
[OVERVIEW.md](OVERVIEW.md#threat-model). In summary, the adversary can:

- Control any web page the agent visits and inject arbitrary HTML/CSS/JS.
- Use invisible characters, homoglyphs, and encoding tricks.
- Attempt prompt injection, secret exfiltration, or state manipulation.

## Security Guarantees

The extension enforces the following hard guarantees:

1. **Operator-Only Command Gate** — Only messages originating from the side
   panel (operator input) can invoke allowlisted commands. Messages from tabs
   are treated as **data-only** and never executed.
2. **No Action Primitives** — The extension cannot click, fill, navigate, or
   modify the DOM. It is read-only by design.
3. **Deterministic Sanitization** — All untrusted content passes through the
   tolerant HTML tokenizer + sanitizer pipeline before any reasoning or
   storage.
4. **Paste-Fencing** — Pasted content is sanitized and refused when unsafe.
5. **Hardened CSP** — `script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'`.
6. **textContent-Only Rendering** — No `innerHTML`, `eval`, `Function`, or
   `document.write` usage.

## Audit & Verification

- **Tests**: 31/31 passing (`tests/test_sanitize.test.mjs`, Node.js test runner).
- **Cross-validation**: JS sanitizer output cross-validated against the Python
  reference implementation (`sanitize_content.py`) on shared fixtures —
  **byte-identical findings**.
- **Static scans**: no `innerHTML`, `eval`, `Function`, or dynamic script
  insertion detected in shipped source (grep-verified).

See [CHANGELOG.md](CHANGELOG.md) for the delivery record and
[INTEGRATION.md](INTEGRATION.md) for how the behavioral threat/auth engines
extend these guarantees.

## Known Limitations

- MV3 content scripts run in the same process as the page (no isolated DOM).
  The extension mitigates this by being **data-only** (never receives commands,
  only sends data).
- Network-level blocking is not implemented; metadata sanitization drops
  bodies and sensitive headers.
- No formal verification (e.g., Coq/TLA+) of the sanitizer logic yet.

These are tracked in the extension [OVERVIEW.md](OVERVIEW.md#limitations) and
planned hardening items.

## Deployment Best Practices

- Ship with least-privilege permissions only (`sidePanel`, `scripting`,
  `activeTab`).
- Do not add host permissions unless strictly required.
- Prefer Chrome Web Store or enterprise policy distribution.
- Keep `minimum_chrome_version` aligned with supported MV3 browsers.
- Rotate any secrets the operator pastes; sanitized content is redacted before
  use, but the operator is responsible for handling redacted output.

## Scope

In scope: the Sentinel Operator Bridge source under
`extensions/sentinel-operator-bridge/` and its integration with the
BrowseSafe++ SDK.

Out of scope: the upstream BrowseSafe++ benchmark itself, third-party web
content, or the operator's own operational practices.
