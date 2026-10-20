# Contract Auditor v5.1

**AI-powered Solidity smart contract security auditor with Porcelain-X decompilation and pattern-based pre-analysis.**

v5.1 integrates the `evolution_orchestrator.py` from the `learner/` subsystem so that when a chain ID + contract address is supplied:

- **Verified source** → fetched from Etherscan V2, then passed to the orchestrator for pattern-based pre-analysis. The structured findings are injected into the LLM prompt as **additional context** (trust but verify — automated hypotheses, not conclusions).
- **Unverified source** → the orchestrator falls back to bytecode extraction + **Porcelain-X** Rust decompiler, producing pseudocode + semantic findings. The LLM audits the decompiled code with a clear "decompiled" disclaimer and the fast-parse results as guidance.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Key Features](#key-features)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [API Reference](#api-reference)
8. [Environment Variables](#environment-variables)
9. [How the Orchestrator Integration Works](#how-the-orchestrator-integration-works)
10. [Deployment](#deployment)
  - [Render.com](#rendercom)
  - [Docker](#docker)
  - [Manual (Linux/macOS)](#manual-linuxmacos)
11. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

<img src="architecture-diagram.png" alt="Architecture diagram" width="100%" />

Or in ASCII-art form:

```
                    Contract Auditor v5.1
                              |
            +-----------------+-----------------+
            |                                   |
   ┌──────────────────┐             ┌──────────────────┐
   |  Frontend (SPA)  |             |  REST API Server  |
   |  public/index.html|             |  server.js        |
   └────────┬─────────┘             └────────┬─────────┘
            |                                |
            |   Paste Chain ID + CA          |
            v                                v
   ┌──────────────────┐             ┌──────────────────┐
   |  Etherscan V2    |             |  /api/* routes   |
   |  getsourcecode    |             |  audit, batch,   |
   └────────┬─────────┘             |  reaudit, evolve |
            |                       └────────┬─────────┘
   ┌────────▼────────┐                       |
   | Source Verified? |                       |
   |     ┌─────┬────┐|                       |
   |   YES       NO |                       |
   └──────┬──────┬──┘                       |
           | YES  | NO                     |
           v        v                        |
   ┌────────────┐ ┌──────────────────┐      |
   | Return     | | Evolution        |      |
   | verified   | | Orchestrator     |      |
   | source +   | │ (Python)         |      |
   | run        | │ • Etherscan fetch│      |
   | pattern    | │ • Porcelain-X    |      |
   | analysis   | │   decompiler     |      |
   └────┬───────┘ │ • TS analyzer    |      |
        |         │ • Pattern libs   |      |
        |         └──┬───────┬───────┘      |
        |            │       │              |
        |            v       v              |
        |    ┌────────────┐ ┌───────┐        |
        |    │ additional │ │source │        |
        |    │ Context    │ │code   │        |
        |    └─────┬──────┘ └───┬───┘        |
        |          |              |          |
        └──────────┴──────────────┘          |
                      | combined             |
                      v output               |
           ┌─────────────────────┐           |
           |    runLLMAudit()     |           |
           │ OpenAI-compatible    │           |
           │ HTTP/1.1 (undici)   │           |
           │ + additionalContext  │           |
           │ + isDecompiled flag  │           |
           └──────────┬────────┘           |
                      |                      |
                      v                      |
          ┌─────────────────────┐            |
          |  MongoDB (Atlas)    |            |
          │ single_audit_jobs   │            |
          │ batch_items         │            |
          │ batches             │            |
          │ reaudits            │            |
          └─────────────────────┘            |
                                             |
                    ┌────────────────────────┘
                    |
                    v
          ┌─────────────────────┐
          |  LLM Provider       |
          |  (OpenAI-compatible)|
          └─────────────────────┘
```

**The core flow**: The orchestrator acts as a pre-processing layer between Etherscan/source fetching and the final LLM audit. It enriches the prompt with structured findings, and when source isn't available, it decompiles bytecode into pseudocode the LLM can still auditee.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Dual-path source resolution** | Verified source → pattern analysis. Unverified → Porcelain-X bytecode decompilation. |
| **Pattern-based pre-audit** | Uses a 411-pattern library (17 vulnerability categories) to generate structured findings fed as `additionalContext` to the LLM. |
| **Trust-but-verify LLM integration** | Fast-parse objects provide hypotheses; the LLM uses them as guidance, not authoritative conclusions. |
| **Batch processing** | Submit multiple contracts with persistent MongoDB state; resumes after server restarts. |
| **Reaudit system** | UNRATED contracts (black-box escalation) get a one-shot human-assisted reaudit flow following the same orchestrator integration. |
| **COM dual-auditor mode** | Two LLMs perform initial + cross-review audits for higher confidence. |
| **Adaptive LLM rate learning** | Per-key/provider/model interval learning persisted in MongoDB. |
| **HTTP/1.1 enforcement** | Prevents HTTP/2 negotiation crashes from LLM providers. |
| **Debug logging** | `ORCHESTRATOR_DEBUG=1` saves full orchestrator output to `/tmp/orchestrator_debug_*.md`. |
| **Render-ready** | Pre-configured for one-click deployment. |

---

## Prerequisites

- **Node.js** v18+ (v22+ recommended; `package.json` declares engine v22.x)
- **Python 3.8+** (with the `learner/` subsystem installed — see [Learner Setup](#learner-subsystem-setup))
- **MongoDB Atlas** account (or self-hosted MongoDB instance)
- **Etherscan API key** (V2 unified API)
- **OpenAI-compatible LLM API key** (OpenAI, Groq, Together, Pollinations, etc.)

### Learner Subsystem (Bundled)

v5.1 **bundles the full learner subsystem** (orchestrator + TypeScript analyzer) in the `learner/` directory. No separate clone or installation is needed.

The bundled learner provides:

- **Etherscan V2 source fetching** (chain ID based, with local caching)
- **Porcelain-X Rust decompiler** (bytecode → pseudocode) via the `porosity-analyzer` binary
- **TypeScript analyzer** subprocess (`npx tsx src/analyzer/index.ts`) for pattern-based vulnerability detection
- **Pattern library** (`data/vuln_pattern_library.json`): 411 patterns across 17 vulnerability categories
- **Zero-shot vulnerability reasoning** via knowledge graph → attacker hypotheses → precondition evaluation
- **Label inference** from `vuln_contracts.jsonl` and `vuln_labels.json`

The orchestrator automatically resolves paths relative to its own location (`learner/evolution_orchestrator.py`), so it works from the bundled directory without configuration.

**Porcelain-X decompiler**: The orchestrator calls the `porosity-analyzer` Rust binary. If `PORTOXITY_X_BINARY` is not set in your environment, it will look for `../porosity-x/target/debug/porosity-analyzer` relative to the project root (i.e., `/home/ghost/projects/porosity-x/target/debug/porosity-analyzer`). You can also set `PORTOXITY_X_BINARY` to an absolute path to the compiled Rust binary.

---

## Installation

```bash
# Clone
git clone https://github.com/your-org/contract-auditor-v5.1.git
cd contract-auditor-v5.1

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env with your credentials (see Configuration section)
# Then:
node server.js  # or npm start
```

---

## Configuration

### 1. Environment Variables (`.env`)

Copy `.env.example` to `.env` and fill in values:

```env
# MongoDB Atlas connection string (REQUIRED)
MONGODB_URI=mongodb+srv://USER:PASS@cluster0.example.mongodb.net/dbname?retryWrites=true&w=primary

# Python binary (default: python3)
PYTHON_BIN=python3

# Path to evolution_orchestrator.py (OPTIONAL — defaults to ./learner/evolution_orchestrator.py)
EVOLUTION_ORCHESTRATOR_PATH=

# Path to Porcelain-X Rust binary (OPTIONAL — defaults to ../porosity-x/target/debug/porosity-analyzer)
PORTOXITY_X_BINARY=

# Enable orchestrator debug logging to /tmp/orchestrator_debug_*.md
ORCHESTRATOR_DEBUG=1
```

> **Important:** The orchestrator runs as a subprocess via `child_process.spawn`. It inherits the main process's environment. The orchestrator's `npx tsx` subprocess resolves TypeScript files relative to its own `REPO_ROOT` (the `learner/` directory), so all analyzer source files are included in the bundle. The orchestrator uses Python's standard library + `requests` — no additional pip packages are required for the core flow.

### 2. Frontend Configuration

### 2. Frontend Configuration

API keys and LLM endpoint are provided at **runtime** via HTTP headers:

| Header | Purpose | Example |
|--------|---------|---------|
| `x-etherscan-key` | Etherscan V2 API key | `0123456789abcdef...` |
| `x-openai-key` | OpenAI-compatible LLM API key | `sk-...` |
| `x-openai-keys` | Multiple keys (batch mode, comma-separated) | `sk-...,sk-...` |

The LLM URL and model are submitted per-batch via the frontend UI.

---

## Usage

### Single Audit

1. Open `http://localhost:3000` in your browser.
2. Switch to the **"Single Audit"** tab.
3. Enter a **contract address** and **chain ID** (e.g., chain 1 = Ethereum mainnet).
4. Provide your **Etherscan API key** (`x-etherscan-key` header via the UI).
5. Provide your **LLM API key** and **model** (e.g., `gpt-4o-mini`).
6. Optionally provide an **LLM endpoint URL** (default: `https://api.openai.com/v1/chat/completions`).
7. Submit. The system will:
   - Check Etherscan for verified source.
   - If found → run orchestrator pattern analysis → LLM audit.
   - If not found → run Porcelain-X decompilation → LLM audit with decompiled code + fast-parse context.

### Batch Audit

1. Switch to the **"Batch Audit"** tab.
2. Enter contracts as a list of `address,chainId` pairs (one per line).
3. Provide Etherscan key, LLM endpoint, model(s), and API key(s).
4. Submit. Results are persisted to MongoDB and auto-resume on restart.

### Reaudit (UNRATED resolution)

When an audit returns an **UNRATED** verdict (black-box escalation), a reaudit record is created:

1. Go to the **"Reaudits"** tab.
2. Click on the pending reaudit.
3. Add external contract addresses — the system fetches their source/decompiles via the orchestrator.
4. Click **RUN REAUDIT** — the system re-runs the LLM audit with the additional external contract evidence + fast-parse context.

---

## API Reference

### `POST /api/audit`

Start a single audit job. Returns a `jobId` immediately.

**Headers:**
- `x-openai-key` — LLM API key (required)
- `x-etherscan-key` — Etherscan API key (required when no source provided)

**Body:**
```json
{
  "address": "0xf5A1a95024c454AbaD291EF1cE1765B01DFDaA22",
  "chainId": "1",
  "label": "unknown",
  "systemPrompt": "...",
  "model": "gpt-4o-mini",
  "llmUrl": "https://api.openai.com/v1/chat/completions"
}
```

> If `source` is omitted, the system auto-fetches via the orchestrator (verified → source; unverified → decompiled pseudocode).

### `GET /api/audit/:jobId`

Poll for audit status/result.

### `POST /api/evolve`

Manual orchestrator test endpoint.

**Body:**
```json
{
  "address": "0x...",
  "chain": "1",
  "label": "unknown"
}
```

Returns the full orchestrator result including `source`/`decompiledSource`, `score`, `status`, `patterns_matched`, and `porcelainx_findings`.

### `POST /api/batch`

Start a batch audit.

**Headers:**
- `x-etherscan-key` — Etherscan API key
- `x-openai-key` (Normal mode) or `x-openai-keys` (COM mode, comma-separated) — LLM API keys

**Body:**
```json
{
  "items": [
    { "address": "0x...", "chainId": "1" },
    { "address": "0x...", "chainId": "1" }
  ],
  "systemPrompt": "...",
  "model": "gpt-4o-mini",
  "llmUrl": "https://api.openai.com/v1/chat/completions",
  "mode": "normal",
  "com": {
    "enabled": true,
    "llmA": { "url": "...", "model": "gpt-4o", "apiKeys": ["sk-..."] },
    "llmB": { "url": "...", "model": "gpt-4-turbo", "apiKeys": ["sk-..."] }
  }
}
```

### `GET /api/etherscan?address=0x...&chainId=1`

Fetch source for a single contract (with orchestrator fallback). Headers: `x-etherscan-key`.

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MONGODB_URI` | ✅ | — | MongoDB connection string |
| `PYTHON_BIN` | ❌ | `python3` | Python executable for orchestrator subprocess |
| `EVOLUTION_ORCHESTRATOR_PATH` | ❌ | `./learner/evolution_orchestrator.py` | Path to orchestrator script (bundled in v5.1) |
| `PORTOXITY_X_BINARY` | ❌ | `../porosity-x/target/debug/porosity-analyzer` | Path to Porcelain-X Rust binary |
| `ORCHESTRATOR_DEBUG` | ❌ | `0` | Save debug logs to `/tmp/orchestrator_debug_*.md` |
| `LOG_LEVEL` | ❌ | `info` | Logging verbosity |
| `PORT` | ❌ | `3000` | Server port (Render sets this automatically) |

---

## How the Orchestrator Integration Works

### Verified Source Path

```
1. User pastes address + chainId → frontend
2. /api/audit POST → server.js
3. No source provided → runEvolutionOrchestrator(address, chainId, label)
4. Orchestrator:
   a. Etherscan V2 fetch → verified source found ✅
   b. Runs TypeScript analyzer (npx tsx src/analyzer/index.ts)
   c. Pattern-matches against 411-pattern vulnerability library
   d. Returns { source, score, status, patterns_matched, ... }
5. Server extracts: source (for LLM) + fastParseResult (for additionalContext)
6. runLLMAudit({ source, additionalContext, isDecompiled: false })
7. LLM prompt includes: source code + "TRUST BUT VERIFY" pattern findings
8. Result persisted to MongoDB → returned to frontend
```

### Unverified Source Path

```
1. User pastes address + chainId → frontend
2. /api/audit POST → server.js
3. No source provided → runEvolutionOrchestrator(address, chainId, label)
4. Orchestrator:
   a. Etherscan V2 fetch → no verified source ❌
   b. Fetches bytecode via Etherscan
   c. Runs Porcelain-X Rust decompiler → pseudocode + semantic findings
   d. Returns { decompiledSource, score, status, patterns_matched, porcelainx_findings, ... }
5. Server extracts: decompiledSource (for LLM) + fastParseResult (for additionalContext)
6. runLLMAudit({ source: decompiledSource, additionalContext, isDecompiled: true })
7. LLM prompt includes: decompiled pseudocode + "DECOMPILED CODE NOTICE" disclaimer
   + "TRUST BUT VERIFY" pattern findings
8. Result persisted to MongoDB → returned to frontend
```

### Rescan / Reaudit Flow

The reaudit system for UNRATED contracts follows the same integration:
- External contract sources are fetched via the same `fetchExternalContract()` → `runEvolutionOrchestrator()` pipeline
- Both verified and decompiled external contracts contribute `fastParseResult` to the reaudit LLM context
- The `verifiedEvidence()` function includes decompiled external contracts alongside verified ones

### Frontend Indicators

- **DECOMPILED badge** (yellow): Shown next to contract names when `isDecompiled: true`
- **Collapsible Fast Parse Results**: Shows score, status, patterns matched, Porcelain-X findings, predicted vs. actual label

---

## Deployment

### Render.com (Recommended)

**One-click deploy:**

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/your-org/contract-auditor-v5.1)

**Manual setup on Render:**

1. **Create a new Web Service** on Render.
2. Connect your GitHub repo.
3. Set the build command:
   ```bash
   npm install
   # Install learner dependencies (for npx tsx TypeScript analyzer)
   npm install --prefix learner
   ```
4. Set the start command:
   ```bash
   node server.js
   ```
5. Add environment variables in the Render dashboard:
   ```
   MONGODB_URI=<your-mongodb-atlas-connection-string>
   PYTHON_BIN=python3
   ORCHESTRATOR_DEBUG=0
   ```
   > `EVOLUTION_ORCHESTRATOR_PATH` and `PORTOXITY_X_BINARY` are optional — sensible defaults are bundled. Only override them if you're using an external orchestrator or custom Porcelain-X build.
6. **Porcelain-X**: If deployed on Render, you'll need to include the `porosity-analyzer` Rust binary. Options:
   - **Build a custom Docker image** that compiles Porcelain-X and copies it alongside the project
   - **Set `PORTOXITY_X_BINARY`** to point to wherever you deploy the binary
   - Without Porcelain-X, unverified contracts will fail decompilation (the system will log a warning and return the pattern-only analysis if source was fetched)

**Render `render.yaml` (optional, for infra-as-code):**
```yaml
services:
  - type: web
    name: contract-auditor-v51
    runtime: node
    buildCommand: npm install
    startCommand: node server.js
    envVars:
      - key: MONGODB_URI
        fromSecret: mongodb-uri
      - key: PYTHON_BIN
        value: python3
      - key: EVOLUTION_ORCHESTRATOR_PATH
        value: /opt/learner/evolution_orchestrator.py
      - key: ORCHESTRATOR_DEBUG
        value: "0"
    healthCheck:
      path: /health
```

### Docker

```dockerfile
FROM node:22-alpine

# Install Python 3 and build tools (for orchestrator subprocess + Porcelain-X)
RUN apk add --no-cache python3 curl

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Install learner dependencies (for npx tsx TypeScript analyzer)
COPY learner/package*.json ./learner/
RUN npm ci --prefix learner

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
```

```bash
# Build
docker build -t contract-auditor-v5.1 .

# Run (Porcelain-X binary optional — set PORTOXITY_X_BINARY if you have it)
docker run -p 3000:3000 \
  -e MONGODB_URI="mongodb+srv://..." \
  -e PYTHON_BIN="python3" \
  -e PORTOXITY_X_BINARY="/opt/porosity-x/porosity-analyzer" \
  contract-auditor-v5.1
```

### Manual (Linux/macOS)

```bash
git clone https://github.com/your-org/contract-auditor-v5.1.git
cd contract-auditor-v5.1
npm install
cp .env.example .env
# Edit .env...
node server.js
# Open http://localhost:3000
```

---

## Troubleshooting

### Orchestrator fails to start

- ✅ Verify `EVOLUTION_ORCHESTRATOR_PATH` points to a valid `evolution_orchestrator.py` (default: `./learner/evolution_orchestrator.py`)
- ✅ Verify `PYTHON_BIN` can execute the script: `python3 /path/to/evolution_orchestrator.py --help`
- ✅ Verify the orchestrator's own dependencies are installed — `npx tsx` must work from the learner directory
- ✅ Check debug output if `ORCHESTRATOR_DEBUG=1` is enabled (`/tmp/orchestrator_debug_*.md`)

### "Orchestrator could not retrieve or decompile source"

- ✅ Verify your Etherscan API key is valid and has V2 access
- ✅ The contract may not exist on the specified chain — verify chain ID
- ✅ If the contract is unverified and Porcelain-X fails, ensure the `porosity-analyzer` binary exists at `./porosity-x/target/debug/porosity-analyzer`
- ✅ Verify the binary is executable: `chmod +x ./porosity-x/target/debug/porosity-analyzer`
- ✅ Alternatively, set `PORTOXITY_X_BINARY` env var to an absolute path

### Porcelain-X decompilation not working (empty `decompiledSource`)

- ✅ The pre-compiled binary is bundled at `porosity-x/target/debug/porosity-analyzer`
- ✅ Make sure it's executable: `chmod +x porosity-x/target/debug/porosity-analyzer`
- ✅ For x86_64 Linux: the bundled binary should work out of the box
- ✅ For other architectures: rebuild with `cargo build --release` from the `porosity-x/` directory
- ✅ Without Porcelain-X, unverified contracts will still get pattern analysis but no decompiled pseudocode

### HTTP 503/502 from LLM provider

- ✅ The system already forces HTTP/1.1 via undici's `alpnProtocols: ['http/1.1']` to prevent HTTP/2 negotiation crashes
- ✅ Try a different LLM provider or endpoint URL
- ✅ Check your API key has sufficient quota

### MongoDB connection errors

- ✅ Verify `MONGODB_URI` is correct and the IP is whitelisted in Atlas
- ✅ Check the database name in the URI — it should match your Atlas database

### 401 Unauthorized from LLM

- ✅ Your API key is invalid or expired
- ✅ The key doesn't have access to the specified model
- ✅ Check the provider's dashboard for key status

### Batch items stuck on "pending"

- ✅ Check the server logs for errors
- ✅ Ensure MongoDB is reachable and indexes are created
- ✅ Verify all API keys in the batch request are valid

### Empty or truncated decompiled output

- ✅ Porcelain-X decompilation works best on simpler contracts. Complex proxy patterns may produce incomplete pseudocode
- ✅ The orchestrator may fall back to pattern-only analysis without decompilation for certain contract types

---

## File Structure

```
contract-auditor-v5.1/
├── server.js                      # Express server entry point
├── package.json                   # Server dependencies + start script
├── .env.example                   # Environment variable template
├── .gitignore
├── .github/
│   └── workflows/
│       └── keepalive.yml          # GitHub Actions keep-alive
├── README.md                      # This file
├── INTEGRATION_SUMMARY.md         # Architectural summary of orchestrator integration
├── api/
│   ├── audit.js                   # Single audit endpoint (orchestrator integration)
│   ├── batch.js                   # Batch processing engine
│   ├── batch-config.js            # Batch configuration helpers
│   ├── com.js                     # COM dual-auditor mode
│   ├── contract-skip-list.js      # Skip list for contracts
│   ├── db.js                      # MongoDB connection helpers
│   ├── etherscan.js               # Etherscan V2 source fetching + orchestrator fallback
│   ├── evolve.js                  # Manual orchestrator test endpoint
│   ├── llm.js                     # LLM API client (HTTP/1.1 enforced)
│   └── reaudit.js                 # Reaudit queue for UNRATED contracts
├── public/
│   └── index.html                 # SPA frontend with DECOMPILED badges + Fast Parse sections
├── learner/                       # === BUNDLED Learner Subsystem ===
│   ├── evolution_orchestrator.py  # Main orchestrator (Python)
│   ├── package.json               # Learner deps (tsx for analyzer)
│   ├── package-lock.json
│   ├── vuln_contracts.jsonl       # Contract dataset for label inference
│   ├── data/
│   │   ├── vuln_pattern_library.json  # 411 patterns × 17 categories
│   │   ├── vuln_labels.json           # Label mappings
│   │   └── vuln_patterns.json         # Pattern definitions
│   └── src/
│       ├── index.ts              # Learner entry point
│       ├── api/                  # API server (not used by v5.1)
│       ├── lib/                  # Utility modules (logger, etherscan)
│       ├── training/             # Training pipeline (not used by v5.1)
│       └── analyzer/             # === TypeScript Static Analyzer ===
│           ├── index.ts          # CLI entry: npx tsx src/analyzer/index.ts --target <file> --json
│           ├── extractor.ts      # Feature extraction
│           ├── reasoner.ts       # Zero-shot vulnerability reasoner
│           ├── ast/              # Solidity AST parser + tokenizer
│           │   ├── parser.ts
│           │   ├── tokenizer.ts
│           │   └── types.ts
│           ├── cfg/              # Control-flow graph builder
│           ├── features/          # Feature extractors
│           ├── knowledge/         # Docs processor
│           ├── models/            # Architecture + bug database
│           ├── taint/             # Taint analysis graph
│           └── zero_shot/         # Zero-shot predictor + KB + patterns
├── learner/node_modules/          # TSX + TypeScript (gitignored)
├── porosity-x/                     # === Bundled Porcelain-X Rust Decompiler ===
│   ├── Cargo.toml                  # Rust crate manifest
│   ├── Cargo.lock                  # Pinned dependencies
│   ├── src/                        # Rust source files
│   │   ├── main.rs
│   │   ├── lib.rs
│   │   ├── analyzer.rs
│   │   ├── blocks.rs
│   │   ├── disasm.rs
│   │   ├── semantics.rs
│   │   ├── solkb.rs
│   │   └── taint.rs
│   ├── examples/
│   │   └── test_debug.rs
│   └── target/
│       └── debug/
│           └── porosity-analyzer    # Pre-compiled binary (make executable)
└── porosity-x/                     # (same as above — bundled Rust decompiler)
```

---

## Credits

Built on the foundation of:
- **Etherscan V2** unified API
- **Porcelain-X** (porosity-x) Rust decompiler
- **TypeScript analyzer** pattern-matching engine
- **MongoDB** for persistence
- **Undici** for HTTP/1.1-compliant LLM requests

Co-authored by Claude Code.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
