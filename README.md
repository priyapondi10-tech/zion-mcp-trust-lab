# MCP Trust Lab

A complete dependency-free browser utility for static review of MCP configurations and tools-list manifests. It complements Zion's Prompt Shield and Secrets Sentinel by reviewing the **capability boundary**, not model output or a running server.

Live: https://priyapondi10-tech.github.io/zion-mcp-trust-lab/

## Run and test

```sh
python3 -m http.server 8080
# open http://localhost:8080/
node --test test.mjs
# or npm test if npm is available
```

Requires a modern ES-module browser; tests use Node 20+. No build step or third-party dependencies. GitHub Pages serves `main` / root; `.nojekyll` disables Jekyll processing. All assets and links work at a project-site subpath.

## Inputs and outputs

Paste JSON containing `mcpServers`, VS Code `servers`, or `tools` / `result.tools`. Import a local JSON file up to 1 MiB. Inspect findings, filter severity, and download a JSON report or Markdown review checklist. Clear removes in-memory input/output. No input persistence, analytics, upload, fetch, server invocation, eval or shell execution exists. A restrictive CSP blocks network connections and form submissions.

Reports omit environment/header values and full endpoint/argument strings. Server and tool names are retained; review reports before sharing. Never paste real production secrets merely to test detection.

Rules cover literal credential-like fields, shell launchers, unpinned package launchers, auto-install flags, filesystem roots, wildcard permissions, HTTP remote endpoints, credential-bearing URLs, potentially destructive tools, open input schemas and a few suspicious metadata phrases. The score starts at 100 and deducts critical=35, high=20, medium=8, low=2. It is **not a security certification**. False positives and negatives are expected; annotations are untrusted hints. Review provenance and source, use OS-level sandboxing, enforce server-side authorization and test least privilege separately.

## Network and domain staging

The page links to all four working utilities and the staging homepage. `mcp-trust.ziontechgroup.com` is a planned custom domain, not bound to this Pages site while the connected Cloudflare zone is pending. No CNAME file is committed: this keeps the HTTPS github.io URL usable. DNS preparation is not public routing. Do not activate a prepared zone without verifying domain ownership, claiming each hostname in Pages, and checking TLS; dangling/unclaimed custom-domain records can enable takeover. Production Zion repositories and existing DNS are not modified.
