# Security and safe use

CyberShield AI is an educational, single-user local prototype. It is not a production SIEM, incident-response system, or tamper-proof evidence store.

## Safe operation

- The development API and Vite server bind to `127.0.0.1` by default. Do not expose them to an untrusted network.
- The API uses a fixed local CORS origin, JSON request size limits, basic security headers, and in-memory rate limits. The browser extension's fixed origin is permitted only for URL-check and blocklist routes. These controls are not authentication and do not make a shared host safe.
- Log analysis is deterministic and defensive. It does not probe remote systems, execute submitted content, or perform containment actions.
- All built-in scenarios are synthetic. No live telemetry integration is included.
- Browser URL checks parse the URL locally and never visit it. URL checks do not save browsing history. The extension sends clicked HTTP(S) URLs only to the local loopback API. The optional OpenPhish community feed is downloaded only after the user checks the terms-acceptance box; accepted snapshots refresh every 12 hours while the server runs. The feed provider receives only the feed download request, not the user's URLs.
- The Manifest V3 browser extension uses all-sites content-script access to check ordinary same-tab link clicks. Review that permission before loading it. Feed-listed domains use browser declarative network rules; heuristic link checks do not block typed URLs or all redirects before their first request.
- Offline mode uses local keyword guidance. Optional Groq mode sends the pasted API key and a connection-test prompt to Groq, then sends assistant questions and matched local knowledge excerpts to Groq. Uploaded logs and incident records are not sent by the assistant integration. Provider requests may incur charges.
- Incident, analysis, investigation, and audit data are written as local JSON. Treat them as sensitive. Do not submit information you are not authorized to process.
- The optional Groq key is accepted only by the local settings endpoint, kept in server memory, never returned, logged, or written to disk, and cleared when the local API server stops. Selecting offline mode clears it. Do not put secrets in source code or the data directory.
- The local JSON audit log can be changed by anyone with local file access and is not forensic-grade evidence.

## Limitations

Loopback binding alone does not protect against local users, malware, browser compromise, or unsafe configuration changes. There is no login system, multi-user access control, encrypted storage, cross-process write lock, or production deployment hardening. Use only synthetic or suitably sanitized data.

## Reporting

Report suspected security issues privately to the project maintainer. Do not include API keys, credentials, or sensitive incident data in reports.
