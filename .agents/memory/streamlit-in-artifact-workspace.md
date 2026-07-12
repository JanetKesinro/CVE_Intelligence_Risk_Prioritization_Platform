---
name: Streamlit/Python apps in artifact workspace
description: How to get a Streamlit (or other non-JS) app previewable in a PNPM_WORKSPACE-stack project, where the artifact system has no matching artifact type.
---

This project's artifact router only serves content registered as an artifact
(`REPLIT_ARTIFACT_ROUTER`). A plain `configureWorkflow` process on its own port
returns 404 on both the dev domain and deployed domain — "no previewable
artifacts" — even if the workflow itself runs fine. There is no "python" or
"streamlit" `artifactType` in `createArtifact`.

**Why:** the proxy/router only knows about paths declared in some
`artifacts/<slug>/.replit-artifact/artifact.toml`; workflows outside that
system aren't wired into routing at all, regardless of `outputType: webview`.

**How to apply:** to ship a Python/Streamlit (or other non-supported-stack) app
with working preview + deploy routing:
1. `createArtifact({ artifactType: "react-vite", slug, previewPath, title })` to get a
   real `artifact.toml` + managed workflow + proxy registration.
2. Delete the scaffolded JS/React files (`src/`, `vite.config.ts`, `tsconfig.json`,
   `index.html`, `components.json`) and drop in the real app files.
3. Replace `package.json` with a minimal one (no node deps needed).
4. Edit `.replit-artifact/artifact.toml` via `verifyAndReplaceArtifactToml` — set
   `services.development.run` to the actual run command (e.g.
   `streamlit run app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true`),
   keep `services.env` with `PORT`/`BASE_PATH` matching `localPort`, and drop
   `services.production` entirely if there's no static build step (validation
   rejects the react-vite-style production schema for a non-static app).
5. Restart with `WorkflowsRestart` using the exact managed workflow name
   (`artifacts/<slug>: web`), not a hand-configured workflow.
