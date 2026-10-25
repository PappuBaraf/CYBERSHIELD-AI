# Build progress

## Verification (2026-10-26)

- `npm run typecheck`: PASS — client and server TypeScript checks completed with exit code 0 after the analyzer demo changes.
- `npm run build`: PASS — Vite production build completed with exit code 0 after the analyzer demo changes.
- `npm test`: FAIL — latest run: 17 tests total; 10 passed, 7 failed. The 7 API tests fail on `fetch failed` connecting to the test server. A direct PowerShell request to the local health endpoint was also blocked by this environment's socket permissions. Do not treat the API suite as passing.
- `npm run dev`: PASS — the local dashboard is open at `http://127.0.0.1:5173/`; the UI reports API ONLINE.
- Security Log Analyzer demo: PASS — loaded and analyzed all 10 sample JSON records in the running browser; result showed 10 processed, 10 valid, 0 rejected, and all 10 local heuristic rule IDs (AUTH-001, AUTH-002, NET-001, NET-002, DNS-001, WEB-001, IAM-001, FILE-001, API-001, ADMIN-001). No external provider call was made.
- Investigation history: PASS — browser showed 11 history entries. Clicking `Open report` loaded the selected demo report and its evidence, rules, knowledge references, and offline status.
- Threat Intelligence and Knowledge Base: PASS — 10 CISA KEV references appear as a dated local snapshot; CVE search/filter works.
- Alert-to-incident: PASS — clicking `View related incident` opened the linked incident.
- Offline assistant: PASS — offline route displayed local guidance. Live Groq: NOT TESTED in this verification; the backend restart cleared its in-memory key, and no provider request was sent.

## Seeded content

- `npx tsx scripts/seed-soc-demo.ts`: PASS — 10 synthetic incidents, 10 synthetic alerts, 10 demo analyses, 11 investigation reports (10 seeded plus 1 previously created), 10 CISA KEV references, 13 knowledge documents (10 threat references plus 3 built-in docs), 20 audit entries, and 12 scenarios.
- Threat references are sourced from public CISA KEV advisories/catalog entries and are a local snapshot, not live intel. SOC alerts, incidents, analyses, scenarios, investigation reports, and the analyzer's ten demo records are synthetic training data, not telemetry from this machine or organization.

## Detection methodology update (2026-10-26)

- `npm run typecheck`: PASS after methodology changes.
- `npx tsx --test tests/soc.test.ts`: PASS — 5 tests passed, including coverage for the four labeled local detection paths, the synthetic signature marker, the fixed-threshold anomaly rule, a CISA KEV CVE match, and ATT&CK candidate metadata.
- `npm run build`: PASS after methodology changes.
- Browser demo: PASS — Threat Detection displayed the four methodology descriptions. Loading and running the 10 demo records returned 10 processed, 10 valid, 0 rejected, and displayed behavior-based findings, `SIG-IOC-001`, `ANOM-001`, `INTEL-KEV-001` for CVE-2021-44228 in the local snapshot, and ATT&CK links.
- Full `npm test` status remains FAIL from the prior run: 10 passed, 7 API tests failed with `fetch failed` when connecting to the test server. The focused SOC suite is green; the unrelated loopback test connectivity issue remains unresolved.
- Limitations: signature matching covers one synthetic marker only; anomaly thresholds are fixed teaching values, not a learned organizational baseline; ATT&CK mappings are candidates; CISA KEV data is a dated local snapshot, not a real-time feed. Raw log records and evidence are excluded from LLM prompts; only rule summaries are sent after a user action or explicit opt-in.

## Agent-assisted findings and final verification (2026-10-26)

- Live Protection → Detection methods: PASS — the preview endpoint analyzed the synthetic 10-event set as 10 processed, 10 valid, 0 rejected, and displayed behavior, signature, anomaly, and intelligence-driven findings. The preview is not persisted as an analysis or incident.
- Assistant handoff: PASS — selecting the findings explanation button navigated to AI Assistant and a real response returned from configured Groq (`openai/gpt-oss-20b`). The assistant prompt contained rule IDs, names, severity, and methodology only; raw event records/evidence were excluded. The provider connection can incur paid usage.
- Live feed assistant action: PASS — browser showed “Explain latest findings with Groq” on the live-event feed. It batches/deduplicates the latest local rule summaries and sends them only when clicked. A new opt-in auto-explain toggle batches incoming rule summaries for 1.5 seconds before sending to Groq; it is off by default and requires Groq to be connected.
- Auto-explain runtime: PASS — enabled the toggle for one synthetic authentication event; local detection produced `AUTH-001` and `ANOM-001`, then the app automatically opened AI Assistant and received a Groq response with only those rule summaries in the prompt. The toggle is off by default; no raw event or evidence was included.
- Log Analyzer runtime: PASS — loaded and analyzed the 10 built-in synthetic records; result showed 10 processed, 10 valid, 0 rejected, all expected local finding types, and the “Explain findings with Groq” action. No additional provider call was made from this page.
- `npm run typecheck`: PASS — client and server TypeScript checks exited 0 after the assistant actions were added.
- `npm run build`: PASS — Vite production build exited 0 after the assistant actions were added.
- `npm test`: PASS — 22 tests passed, 0 failed when run with permission for the test's temporary 127.0.0.1 HTTP server. In the restricted sandbox, seven existing API tests fail to connect to that temporary loopback listener; the test code itself passed when local socket access was available.
- `npx tsx --test tests/soc.test.ts tests/urlProtection.test.ts`: PASS — 9 tests passed, 0 failed.
- Running app: PASS — browser remained open at `http://127.0.0.1:5173/`; UI health reported API ONLINE, live SSE CONNECTED, and Groq configured.
- Boundaries: live detection processes events submitted to the local receiver; it does not install an endpoint agent or automatically read Windows logs/SIEM telemetry. Detection rules remain educational heuristics and the KEV catalog remains a saved snapshot.

## Local real-time monitor update (2026-10-26)

- `npm run typecheck`: PASS — completed after the live receiver and dashboard changes.
- `npm run build`: PASS — Vite production build completed after the live monitor changes.
- `npx tsx --test tests/soc.test.ts`: PASS — 5 passed, 0 failed, including all four detection paths.
- `npm test`: FAIL — 18 total; 11 passed, 7 failed. All 7 failures are legacy API tests that cannot connect to their temporary loopback test server (`fetch failed`). The live app itself accepted events through the Vite proxy and local API.
- Browser live-monitor check: PASS — EventSource showed `connected`; the ten-event demo was sent one event at a time through `POST /api/live/events`; all 10 appeared in the feed with immediate findings. Verified signature (`SIG-IOC-001`), threshold anomaly (`ANOM-001`), and CISA KEV snapshot match (`INTEL-KEV-001`) in the live result.
- The app processes submitted/forwarded events in real time, but does not automatically read Windows logs, install an endpoint agent, or connect to a SIEM. A local source must POST to `http://127.0.0.1:3001/api/live/events`. The rule set and local intelligence snapshot are not production threat-detection coverage.

## Browser protection and simplified navigation update (2026-10-26)

- Main navigation reduced to 9 sections; Live Monitor, URL checks/extension, and methodology details are grouped under Live Protection. Alerts were consolidated into Incidents; audit history is consolidated under Reports.
- `npm run typecheck`: PASS after UI, URL protection, API CORS, feed refresh, and extension changes.
- `npm run build`: PASS after UI and URL protection changes.
- `npm test`: FAIL — 22 tests total; 15 passed, 7 failed. The same 7 existing ContractScan API tests fail because their temporary localhost server cannot be reached (`fetch failed`). All SOC and URL protection tests passed.
- Focused SOC + URL protection tests: PASS — 9 passed, 0 failed. Coverage includes deceptive links, exact feed matches, shared-hosting false-positive protection, unsupported schemes, and all four log detection methods.
- Extension validation: PASS — all three JavaScript files passed `node --check`; manifest JSON parsed; its stable extension ID matches the narrow CORS allowlist.
- Browser URL-check flow: PASS — a deceptive brand-login test URL was labeled SUSPICIOUS / HIGH (55/100) with the reason shown. The URL was not visited.
- Feed refresh: NOT TESTED — it requires the user to review and accept OpenPhish's community feed terms in the app. The feed page reports a 12-hour cadence; this is not instant threat intelligence.
- Extension runtime/install in Edge or Chrome: NOT TESTED — the unpacked extension is provided in `extension/`; load it manually in the browser's extension developer page. Feed-block rules require a successful feed download and extension sync.
- Scope: browser click checks and feed-listed pre-request blocks are implemented. Typed URLs and redirects can make their first request before heuristic warning. No automatic Windows event capture or endpoint-level process protection is included.
