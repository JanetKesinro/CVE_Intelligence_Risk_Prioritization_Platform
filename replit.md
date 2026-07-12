# AI CVE Risk Prioritizer

A cybersecurity triage tool: an analyst enters a CVE ID, answers four context questions, and gets a local, rule-based risk score, risk level, plain-language explanation, and a recommended remediation priority.

## Run & Operate

- The app runs as the `artifacts/cve-risk-prioritizer: web` workflow (`streamlit run app.py`).
- No database, no external/paid APIs — all scoring logic is local and deterministic.

## Stack

- Python 3.12 + Streamlit
- pnpm workspaces, Node.js 24, TypeScript 5.9 (used by the other artifacts in this project)
- API: Express 5 (shared `api-server` artifact, unused by this tool so far)
- DB: PostgreSQL + Drizzle ORM (provisioned, unused by this tool)

## Where things live

- `artifacts/cve-risk-prioritizer/app.py` — Streamlit UI and page flow
- `artifacts/cve-risk-prioritizer/risk_engine.py` — scoring weights, thresholds, and explanation text
- `artifacts/cve-risk-prioritizer/cve_lookup.py` — CVE ID format validation
- `artifacts/cve-risk-prioritizer/.streamlit/config.toml` — server + dark cybersecurity theme

## Architecture decisions

- Built as a `react-vite`-scaffolded artifact whose service command was then swapped to run Streamlit directly, because this project's artifact system doesn't have a native Streamlit/Python artifact type. This keeps proxy routing and workflow management working normally. See `.agents/memory/streamlit-in-artifact-workspace.md`.
- Risk scoring is a simple additive weighted model (internet-facing +30, actively exploited +40, business-critical +20, no patch +10; thresholds at 30/55/80) — intentionally transparent and explainable to a security analyst, no ML/AI or external threat intel feeds.

## Product

- Single-page tool: enter a CVE ID, answer 4 yes/no questions about exposure, exploitation, criticality, and patch availability.
- Output: Risk level (Low/Medium/High/Critical), numeric score with a breakdown of point contributions, and a recommended remediation priority with timeframe.

## User preferences

- Explicitly requested: Python + Streamlit, professional/simple/cybersecurity-themed UI, no paid APIs.

## Gotchas

- This artifact's `dev`/production commands run `streamlit`, not `vite` — don't run `pnpm run build` on it expecting a static bundle.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details (applies to the other artifacts, not this Streamlit one).
