# CVE Intelligence & Risk Prioritizer

A cybersecurity triage/vulnerability-management tool: an analyst enters a CVE ID, sees live technical + threat intelligence (NVD, CISA KEV, FIRST EPSS), answers four business context questions, and gets a local, rule-based risk score, risk level, plain-language explanation, and a recommended remediation priority.

## Run & Operate

- The app runs as the `artifacts/cve-risk-prioritizer: web` workflow (`streamlit run app.py`).
- No database, no paid APIs. NVD, CISA KEV, and FIRST EPSS are free public data sources called live over HTTP — the 100-point risk score itself stays local/deterministic.

## Stack

- Python 3.12 + Streamlit
- pnpm workspaces, Node.js 24, TypeScript 5.9 (used by the other artifacts in this project)
- API: Express 5 (shared `api-server` artifact, unused by this tool so far)
- DB: PostgreSQL + Drizzle ORM (provisioned, unused by this tool)

## Where things live

- `artifacts/cve-risk-prioritizer/app.py` — Streamlit UI and page flow, including the valid-CVE gate that hides context questions/Analyze button until NVD confirms the CVE exists
- `artifacts/cve-risk-prioritizer/risk_engine.py` — scoring weights, thresholds, and explanation text
- `artifacts/cve-risk-prioritizer/cve_lookup.py` — CVE ID format validation
- `artifacts/cve-risk-prioritizer/nvd_client.py` — NVD API v2.0 client (description, CVSS, CWE, vendor/product)
- `artifacts/cve-risk-prioritizer/cisa_kev_client.py` — CISA KEV catalog client (fetches full catalog, looks up by CVE)
- `artifacts/cve-risk-prioritizer/epss_client.py` — FIRST EPSS API client (probability, percentile, label)
- `artifacts/cve-risk-prioritizer/.streamlit/config.toml` — server + dark cybersecurity theme

## Architecture decisions

- Built as a `react-vite`-scaffolded artifact whose service command was then swapped to run Streamlit directly, because this project's artifact system doesn't have a native Streamlit/Python artifact type. This keeps proxy routing and workflow management working normally. See `.agents/memory/streamlit-in-artifact-workspace.md`.
- Risk scoring is a simple additive weighted model (internet-facing +30, actively exploited +35, business-critical +25, no patch +10; thresholds at 30/55/80) — intentionally transparent and explainable to a security analyst, no ML/AI feeds.
- CISA KEV listing is the one piece of enrichment that feeds back into the score: if a CVE is KEV-listed, the "actively exploited" question is force-set to Yes and locked (read-only), since KEV is an authoritative exploitation signal. EPSS is displayed as supporting intel only and is NOT added to the 100-point score.
- NVD lookup success/failure is the gate for the whole workflow: if the CVE isn't found in NVD (or the lookup errors), context questions and the Analyze button are hidden entirely and a clear error is shown, so no assessment can be generated for an unverified/invalid CVE.
- CISA KEV catalog is fetched in full (no per-CVE endpoint exists) and cached 6h; EPSS and NVD lookups are cached 30min per CVE — all via `st.cache_data`.

## Product

- Single-page tool: enter a CVE ID, review live technical/threat intelligence (NVD description/CVSS/CWE/vendor, CISA KEV status, FIRST EPSS score), answer 4 yes/no business-context questions, and get a final risk assessment.
- Output: Risk level (Low/Medium/High/Critical), numeric score with a breakdown of point contributions, and a recommended remediation priority with timeframe.

## User preferences

- Explicitly requested: Python + Streamlit, professional/simple/cybersecurity-themed UI, no paid APIs (free public sources like NVD/CISA KEV/FIRST EPSS are fine).

## Gotchas

- This artifact's `dev`/production commands run `streamlit`, not `vite` — don't run `pnpm run build` on it expecting a static bundle.
- CISA KEV has no per-CVE query endpoint — the client downloads the entire catalog JSON and indexes it locally; don't try to add a `?cve=` param to that URL.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details (applies to the other artifacts, not this Streamlit one).
