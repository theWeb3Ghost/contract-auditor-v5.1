# Evolution Orchestrator → v4 Integration: Architectural Summary

## Executive Summary

The core problem is simple: **v4 has four hard "source required" blockers** that prevent bytecode-only audits. The `evolution_orchestrator.py` already does everything needed — Etherscan V2 fetch, Porcelain-X decompilation, pattern-library short-circuit, fast-parse output — it just doesn't return the **code** to the caller and v4 doesn't call it. The integration is a bridge: v4 calls the orchestrator, gets back (objects + code), and injects both into the LLM prompt with an explicit "trust but verify" instruction on the fast-parse findings.

The existing `additionalContext` parameter in `llm.js` (line 301, used at line 465) is the injection point. The existing `ADDITIONAL AUDIT CONTEXT` template block (lines 465, 368–369) is the surface-level hook. No new prompt field is needed — just populate `additionalContext` with the orchestrator's JSON and prefix appropriately.

---

## 1. Current State Map

### What v4 does now (single audit flow)
1. **Frontend** (`public/index.html`): User enters address + chain, selects mode (Normal or COM). `startBtn.onclick` (line 1998) sends a `POST /api/batch` with `rawInput` (the address), `chainId`, `model`, `systemPrompt`, `llmUrl`, keys, and `mode`.
2. **Batch processor** (`api/batch.js`): `processBatchItem()` (line 2434) calls `fetchContractSource()` (line 2142) which hits Etherscan V2. If `!base.SourceCode`, returns `verified: false` (line 2244). Then at line 2545–2575, **unverified contracts are hard-skipped** — marked `'skipped'` in MongoDB and the worker moves on. No LLM is ever invoked.
3. **Single audit flow** (`api/audit.js`): `POST /api/audit` (line 600) hard-rejects missing source at line 616 (`if (!source) return res.status(400)`). It then calls `runAudit()` (line 78) which sends the source to the LLM via `runLLMAudit()`. `runAudit()` does NOT pass `additionalContext` — it builds its own `userMessage` inline (lines 151–168).
4. **LLM** (`api/llm.js`): `runLLMAudit()` (line 293) already accepts `additionalContext = ''` (line 301) and injects it into the user message at line 465: `${additionalContext ? '\nADDITIONAL AUDIT CONTEXT:\n${String(additionalContext)}\n' : ''}`.

### What the reaudit flow does now (`api/reaudit.js`)
1. `fetchExternalContract()` (line 157) hard-blocks at line 160: `if (!base || !base.SourceCode)` returns `sourceStatus: 'unverified'`, `source: null`.
2. `runReaudit()` (line 461) checks at line 469 that at least one external contract has `sourceStatus === 'verified'` before proceeding.
3. `runNormalReaudit()` (line 391) calls `runLLMAudit` with `additionalContext: buildNormalReauditContext(record, evidence)` (line 413).
4. COM reaudit calls `runAudit = async (side, additionalContext) =>` (line 513) with `additionalContext` passed through.

### What the orchestrator does now (`evolution_orchestrator.py`)
- `--address <addr> --chain <id>` (line 1176): Creates a minimal entry dict, sets `contract_name` to the raw address string, empty evidence, empty subset.
- `process_contract()` (line 869): Fetches source from Etherscan V2 (`fetch_source_from_etherscan`, line 344). If no source (line 913), fetches bytecode (`fetch_bytecode_from_etherscan`, line 427), runs Porcelain-X (`run_porosity_x`, line 449), saves decompiled output to disk (`save_decompiled_output`, line 517). Then runs the TypeScript analyzer (`run_analyzer`, line 594) on the temp file.
- **Returns** at six exit points (lines 1011-1021, 1032-1041, 1086-1093, 1120-1129). **CRITICAL GAP**: None of these return `fetched_source` or the decompiled pseudocode. They return `score`, `status`, `patterns_matched`, `porcelainx_findings`, `actual_label`, `predicted`, `attempts`, `pattern`. The code is written to disk (`data/results/target_*.sol` or `data/results/decompiled/*.pseudocode`) but never included in the return object.
- `--address` mode sets `contract_name` to the raw 0x address, so `infer_vuln_label_from_metadata()` (line 642) returns `"unknown"` — no label-specific pattern injection happens.
- Porcelain-X binary path is hardcoded to `/home/ghost/projects/porosity-x/target/debug/porosity-analyzer` (line 457) and silently returns `{}` if missing.

---

## 2. The Six Chokepoints & How to Mend Them

### Chokepoint 1: Orchestrator doesn't return code in its JSON output

**Location**: `evolution_orchestrator.py` lines 1011-1021, 1032-1041, 1086-1093, 1120-1129

**Problem**: All four return dicts include `patterns_matched`, `porcelainx_findings`, `score`, `status`, but **not** `fetched_source` or `decompiled_pseudocode`. v4 has no way to get the code.

**Fix**: Add the code to every return dict. Track `fetched_source` and `porcelainx_output` (and extract pseudocode from it) as variables that are already available in `process_contract` scope. Specifically:
- In the pattern-matched return (line 1011): add `"source": fetched_source` and `"decompiledSource": pseudocode_str` and `"verified": bool(fetched_source)`.
- In the pass return (line 1032): same.
- In the failed return (line 1120): same.
- The `porcelainx_output` variable is set at line 924 for bytecode path, and initialized to `{}` at line 936 for source path. The pseudocode string needs to be extracted from `porcelainx_output.get("semantic_analysis", {}).get("decompiled_pseudocode", "")` or fall back to `porcelainx_output.get("decompiled_pseudocode", "")`.

**Additional fix**: Add a `--json-output <path>` CLI flag. When set, write the final result dict to that path as JSON (in addition to whatever stdout logging happens). This gives v4 a reliable file-based read channel instead of parsing stderr logs.

### Chokepoint 2: `--address` mode doesn't accept a `--label`

**Location**: `evolution_orchestrator.py` line 1138–1141 (argparse), line 1176–1178 (address mode setup)

**Problem**: `--address` mode has `--chain` but no `--label`. So `infer_vuln_label_from_metadata()` gets empty evidence, empty subset, and the raw address as contract_name → always returns `"unknown"`. This means the `VULN_TARGET_LABEL` env var set at line 983 is `"unknown"`, and pattern injection from `vuln_pattern_library.json` won't be targeted.

**Fix**: Add `--label` as an optional argparse argument. In address mode, if `--label` is provided, use it instead of the return of `infer_vuln_label_from_metadata()`. Pass it into the entry dict so it flows to `process_contract()`.

Actually, looking more carefully: `infer_vuln_label_from_metadata` is called at line 898 inside `process_contract`. In address mode, the entry dict's `evidence` is `""`, `contract_name` is the raw address, and `subset` is `""`. The function checks `vuln_labels.json` cache first — if the address happens to be a key, it returns the label. Otherwise it falls through to naming heuristics which won't match a raw 0x address. So `--label` should override this.

### Chokepoint 3: v4 hard-blocks unverified contracts (4 locations)

**Location**: `api/etherscan.js` line 33–35, `api/audit.js` line 616–622, `api/batch.js` line 2545–2575, `api/reaudit.js` line 160

**Problem**: Four independent hard stops. When source isn't verified, v4 returns early or skips the contract entirely.

**Fix**: Replace the hard stop with a **delegation to the orchestrator subprocess**. The pattern is:
1. Try Etherscan source fetch as before.
2. If no verified source: spawn `python3 learner/evolution_orchestrator.py --address <addr> --chain <id> --json-output <tmpfile>` as a subprocess.
3. Read the JSON output file. It contains `{source, decompiledSource, verified, fastParse: {score, status, patterns_matched, porcelainx_findings, ...}, ...}`.
4. Use `source` if verified, `decompiledSource` if not. Pass to `runLLMAudit` with `additionalContext` containing the fast-parse findings.

For `api/audit.js` (POST /api/audit): Instead of `if (!source) return 400`, add optional `chainId` + `address` to the POST body. If `address` and `chainId` are present and `source` is missing, delegate to orchestrator.

For `api/batch.js` (`fetchContractSource` + `processBatchItem`): In `fetchContractSource`, when `!result.SourceCode`, don't return `verified: false`. Instead, mark `verified: false` but `isDecompiled: true` and fetch bytecode through the orchestrator. In `processBatchItem`, replace the skip block (line 2545–2575) with: if not verified, call orchestrator, get decompiled source, set `isDecompiled = true`, and continue to LLM audit instead of skipping.

For `api/etherscan.js`: Keep returning `verified: false` when no source, but also trigger the orchestrator call and return `{verified: false, isDecompiled: true, source: decompiledPseudocode, fastParse: {...}}`.

For `api/reaudit.js`: In `fetchExternalContract` (line 157), when `!base.SourceCode`, call the orchestrator as fallback. Return `sourceStatus: 'decompiled'` instead of `'unverified'`, with the decompiled source populated. Update `runReaudit` line 469 to accept `sourceStatus === 'decompiled'` as a valid trigger for running.

### Chokepoint 4: `audit.js` `runAudit()` doesn't pass `additionalContext`

**Location**: `api/audit.js` lines 78–553 (runAudit), line 293–294 (runLLMAudit call site)

**Problem**: `runAudit()` builds its own `userMessage` inline (lines 151–168) and calls `runLLMAudit()` (line 293) without `additionalContext`. Compare to `batch.js` line 2688–2698 which does pass `additionalContext`.

**Fix**: Add `additionalContext` to the destructured `data` at line 108–116, pass it through to `runLLMAudit` at line 293. Also add `isDecompiled` flag: when true, prefix the `userMessage` with a disclaimer like `"NOTE: This contract's source was not verified on Etherscan. The following code is decompiled pseudocode generated by Peorcelain-X from on-chain bytecode. Semantic analysis may be incomplete; treat variable names and structure with appropriate caution."` Also add `isDecompiled` validation: skip the `if (!source)` check (line 123) or relax it when `isDecompiled` is true.

### Chokepoint 5: LLM `additionalContext` injection needs "trust but verify" framing

**Location**: `api/llm.js` line 465

**Problem**: The template already injects `additionalContext` as `ADDITIONAL AUDIT CONTEXT`, but there's no instruction about how to treat fast-parse results. The LLM could over-trust pattern matches that are actually false positives.

**Fix**: When building `additionalContext` (in whatever module calls the orchestrator), append an explicit instruction:
```
TRUST BUT VERIFY: The following structured analysis was produced by a pattern-matching engine (not human review). Each finding is a hypothesis, not a conclusion. Some may direct attention to non-exploitable paths, false-positive branches, or library code that is safe by construction. Use these findings to guide your attention, not to substitute for your own reasoning. Only cite a finding as exploitable if your independent analysis confirms it.
```

### Chokepoint 6: Frontend doesn't know about decompiled vs verified audits

**Location**: `public/index.html`

**Problem**: The frontend treats all audits the same. There's no visual distinction for bytecode-decompiled audits.

**Fix**: Surface `isDecompiled` and `fastParseResult` in the job result response. In the GET /api/audit/:jobId handler (line 762–831), include `isDecompiled` and `fastParseResult` in the response JSON. In the frontend rendering, when `isDecompiled` is true, show a badge: `"⚠️ Decoded from bytecode (decompiled — no verified source)"` next to the audit result. Show the fast-parse findings (score, patterns matched) in a collapsible section.

---

## 3. Data Flow Diagram (After Integration)

```
Frontend POST /api/audit
  { address, chainId, systemPrompt, model, llmUrl, apiKey }
    │
    ▼
audit.js: POST handler
  │ address + chainId + no source → 
  │   spawn: python3 evolution_orchestrator.py --address 0x... --chain 1 --json-output /tmp/evolve_xxx.json
  │   wait → read /tmp/evolve_xxx.json
  │   extract: result.source (verified) OR result.decompiledSource (unverified)
  │   build additionalContext = JSON.stringify({ score, status, patterns_matched, porcelainx_findings }) + trust-but-verify frame
  │   set isDecompiled = !result.verified
    │
    ▼
runAudit(jobId, { source, isDecompiled, additionalContext, ... })
  │ isDecompiled → prefix userMessage with decompilation disclaimer
  │ 
    ▼
runLLMAudit({ source, additionalContext, ... })
  │ injects: ADDITIONAL AUDIT CONTEXT + fast-parse JSON
    │
    ▼
LLM audit result → MongoDB single_audit_jobs
  │ save: result, isDecompiled, fastParseResult (JSON)
    │
    ▼
Frontend GET /api/audit/:jobId
  │ returns: { status, result, isDecompiled, fastParseResult }
  │ renders: decompiled badge + collapsible fast-parse findings
```

**Batch path** mirrors this but through `processBatchItem` → `fetchContractSource` returns `isDecompiled` → `runLLMAudit` gets `additionalContext`.

**Reaudit path** mirrors this: `fetchExternalContract` falls back to orchestrator when Etherscan returns no source, returns `sourceStatus: 'decompiled'` with the pseudocode and fast-parse JSON.

---

## 4. Implementation Plan (6 Steps, Ordered)

### Step 1: Orchestrator — return code + add `--json-output` + add `--label`

Files: `learner/evolution_orchestrator.py`

- Add `--json-output <path>` to argparse (line 1138 area).
- Add `--label <str>` to argparse.
- In address mode (line 1176–1178), use `args.label` if provided as the entry's `contract_name` fallback (or inject into the entry dict so `infer_vuln_label_from_metadata` can use it).
- In all return dicts from `process_contract()` (lines 1011, 1032, 1086, 1120): add `"source": fetched_source`, `"decompiledSource": <pseudocode_str>`, `"verified": bool(fetched_source)`, `"decompiled": bool(porcelainx_output)`.
- Track the pseudocode string explicitly: after the Porcelain-X block (line 928), capture `pseudocode = porosityx_output.get("semantic_analysis", {}).get("decompiled_pseudocode", "") or porosityx_output.get("decompiled_pseudocode", "")`.
- After all processing, if `args.json_output` is set, write the final result dict to that file as JSON.
- Also, in `main()` after `process_contract()` returns in address mode, if `--json-output` is set, write the result.

### Step 2: v4 — create `POST /api/evolve` endpoint

Files: new `api/evolve.js`, register in `server.js`

- Spawns `python3 learner/evolution_orchestrator.py --address <addr> --chain <chainId> --label <label_opt> --json-output <tmpfile>` as a child process.
- Reads the JSON file, returns it as the HTTP response `{verified, source, decompiledSource, score, status, patterns_matched, porcelainx_findings}`.
- Handles timeout (60s), binary-not-found, and JSON parse errors gracefully.

### Step 3: v4 — remove hard source blockers

Files: `api/etherscan.js`, `api/audit.js`, `api/batch.js`, `api/reaudit.js`

- `etherscan.js` line 33–35: Instead of `return res.json({address, verified: false})`, fall through to orchestrator call and return decompiled source if available.
- `audit.js` line 616–622: Instead of `return res.status(400)`, check for `address` + `chainId` in the POST body. If present, call `/api/evolve` internally or spawn subprocess directly, then use the result.
- `batch.js` line 2545–2575: Instead of skipping, call the orchestrator, get decompiled source, set `isDecompiled = true`, and continue to the LLM audit path.
- `reaudit.js` line 160: Instead of returning `sourceStatus: 'unverified'`, call the orchestrator as fallback. Return `sourceStatus: 'decompiled'` with source populated.

### Step 4: v4 — add `isDecompiled` + `additionalContext` propagation

Files: `api/audit.js`, `api/llm.js`, `api/batch.js`

- `audit.js`: Add `isDecompiled` and `additionalContext` to destructured `data` (line 108). Pass both to `runLLMAudit()`. When `isDecompiled` is true, prefix `userMessage` with the decompilation disclaimer (lines 151–168 area).
- `llm.js`: The `additionalContext` injection at line 465 already works. Add `isDecompiled` parameter, and when true, prepend a similar disclaimer to the Puter and normal user messages.
- `batch.js`: The COM audit path (line 2674–2698) already passes `additionalContext` — just populate it with the orchestrator's fast-parse output. The normal audit path (line 2820–2842) does NOT currently pass `additionalContext` — add it.

### Step 5: v4 — inject fast-parse findings with trust-but-verify framing

Files: wherever the orchestrator result is consumed (likely a shared helper)

- Format the orchestrator's fast-parse output as:
```
=== FAST-PARSE ANALYSIS (Pattern-Based, Pre-Audit) ===
Confidence Score: 85/100
Status: pattern_matched
Patterns Matched:
  - logic.inverted_msg_value_bytecode (90%)
  - external_call.reentrancy_classic (85%)
Porcelain-X Findings (bytecode analysis):
  [JSON dump of semantic_findings]
TRUST BUT VERIFY: This analysis was produced by a pattern-matching engine, not human review. These findings are hypotheses to guide attention, not conclusions. Some may point to non-exploitable paths, false positives, or safe library code. Verify independently before citing in your verdict.
=== END FAST-PARSE ===
```
- Pass this as `additionalContext` to `runLLMAudit`.

### Step 6: Frontend — surface decompiled status + fast-parse results

Files: `public/index.html`

- In the audit result rendering, check for `isDecompiled` and show a warning badge.
- Add a collapsible "Fast-Parse Analysis" section showing score, status, patterns matched, and Porcelain-X findings.
- In single-audit mode, if the user provides only address + chainId (no source), route through `/api/evolve` internally before submitting to `/api/audit`.

---

## 5. Key Design Decisions

1. **Subprocess spawning, not HTTP**: The orchestrator runs as a Python subprocess from the Node.js v4 server (via `child_process.spawn`). This avoids needing a separate Python server process. The `--json-output` flag gives a reliable file-based IPC channel.

2. **Reuse existing `additionalContext`**: v4 already has the plumbing. No new LLM prompt fields needed — just populate `additionalContext` with the orchestrator's findings + trust-but-verify frame.

3. **Dual-path in `process_contract`**: The orchestrator already handles verified (source path) and unverified (bytecode → Porcelain-X path) internally. v4 just needs to call it once and read the output — it doesn't need to duplicate the fetch logic.

4. **Same architecture for reaudit**: `fetchExternalContract` already returns a structured object. Just add the orchestrator fallback when `!base.SourceCode`, and the rest of the reaudit flow (which already uses `additionalContext`) works unchanged.

5. **No changes to the TypeScript analyzer**: The analyzer subprocess (`npx tsx src/analyzer/index.ts`) is already invoked correctly by the orchestrator. v4 doesn't need to call it directly.

6. **Error containment**: If the orchestrator subprocess fails, times out, or the Porcelain-X binary is missing, v4 should gracefully degrade to the current behavior (skip the contract or return an error) rather than crashing the batch.

---

## 6. Risk Points

- **Cross-repo path coupling**: v4 needs to know the absolute path to `evolution_orchestrator.py` (`/home/ghost/projects/learner/`) and the Porcelain-X binary. These should be configurable via environment variables with the current paths as defaults. Environment: WSL2 filesystem paths (`/home/ghost/projects/...`) need to resolve correctly from the Node.js process. The `.env` file in learner already hardcodes these.

- **Subprocess timeout**: The orchestrator can take 30–120s (Etherscan fetch + analyzer + possibly Porcelain-X + possibly Claude Code fix loop). v4's `LLM_TIMEOUT` is 30 minutes, but the orchestrator step needs its own timeout. 120s is the Python analyzer timeout; Porcelain-X has 30s. Total orchestrator time could be ~3 minutes. The endpoint should set a generous timeout (180s+).

- **`MAX_FIX_ATTEMPTS=0` in `.env`**: The orchestrator's `.env` has `MAX_FIX_ATTEMPTS=0`, which means the Claude Code fix loop is already disabled. This is fine for production v4 integration — we don't want v4 to trigger Claude Code patching of the analyzer. The orchestrator will use `fallback_judge()` pattern-based scoring only.

- **MongoDB schema**: `single_audit_jobs` collection needs new fields: `isDecompiled`, `fastParseResult`. `batch_items` needs `isDecompiled`, `fastParseResult`. `reaudits` collection needs `fastParseResult` on external contract entries. These are additive and backward-compatible (existing queries won't break if new fields are absent).

- **Frontend polling**: The single-audit flow polls `GET /api/audit/:jobId` (via `pollTimer`). The GET response needs to include `isDecompiled` and `fastParseResult` in the projection (line 783–793).
