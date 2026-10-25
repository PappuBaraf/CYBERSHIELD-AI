# CyberShield AI

CyberShield AI is a local educational security operations dashboard. It analyzes submitted security events with deterministic rules, displays live findings, and offers optional Groq explanations. Findings are review signals, not proof of compromise; this project is not a production SIEM or endpoint antivirus.

## Technologies

- React and Vite frontend
- Node.js, TypeScript, and Express API
- JSON files for local persistence
- Server-Sent Events for the live event dashboard
- Optional Groq API integration; offline mode is available

## Dataset

The built-in training dataset contains fictional scenarios and reserved documentation-only IP addresses in [`data/scenarios.json`](https://github.com/PappuBaraf/-CYBERSHIELD-AI/blob/main/data/scenarios.json). The local vulnerability reference snapshot is in [`data/threat-intelligence.json`](https://github.com/PappuBaraf/-CYBERSHIELD-AI/blob/main/data/threat-intelligence.json) and references the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). These files are training/reference data, not telemetry from a real organization; the CISA data is a dated snapshot.

## Run on Windows

Requirements: Node.js 20.19 or later, npm, and Windows PowerShell.

```powershell
npm install
npm install --prefix client
npm run dev
```

Open <http://127.0.0.1:5173/>. The local API listens at <http://127.0.0.1:3001/>. `RUN_CYBERSHIELD_AI.bat` starts the development app. To load the synthetic incidents and alerts, run `npx tsx scripts/seed-soc-demo.ts` from the project root.

## Detection and assistant

Live Protection analyzes JSON events submitted to its loopback event receiver and displays results over SSE. It does not automatically read Windows Event Logs or connect to an endpoint agent or SIEM. The Log Analyzer accepts JSON, JSONL, and simple CSV. Local methods include a synthetic signature marker, deterministic behavior rules, fixed educational anomaly thresholds, and CISA KEV snapshot matching with selected MITRE ATT&CK candidate mappings.

Groq is optional. Connect it from the app's setup or Settings screen; the API key stays in backend memory and clears when the server stops. Assistant explanations send rule IDs, names, severity, and methodology, not raw event records or evidence. Live Protection's automatic explanation toggle is opt-in and may consume paid API usage. Never commit API keys or submit logs you are not authorized to process.

## Verify

```powershell
npm test
npm run typecheck
npm run build
```

There are no Python dependencies; see `package.json` and `client/package.json` for Node dependencies. Review [SECURITY.md](SECURITY.md) for privacy and prototype limitations.