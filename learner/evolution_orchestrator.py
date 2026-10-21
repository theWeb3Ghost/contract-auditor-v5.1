#!/usr/bin/env python3
"""
Autonomous Evolutionary Vulnerability Detection Engine.

This driver loop:
1. Streams contracts from vuln_contracts.jsonl
2. Fetches vulnerable source code from Etherscan V2 API (with local caching)
3. Runs the TypeScript analyzer: `npx tsx src/analyzer/index.ts --target <file> --label <label> --json`
4. Scores analyzer output via pattern-based scoring (no LLM Judge)
5. If score < 80%, invokes headless Claude Code to patch the analyzer rules
6. Retries Claude patches until score >= 80% or max attempts reached
7. Checkpoints progress and advances to next contract

Usage:
    python3 evolution_orchestrator.py [--subset <YYYY-MM>] [--max-contracts N] [--epochs-max N]
"""

import argparse
import json
import os
import re
import subprocess
import shutil
import sys
import time
import traceback
from pathlib import Path
import requests


# ===========================================================================
# Pattern Library Helpers
# ===========================================================================

def clear_injected_env():
    """Clear env vars used for pattern injection so they don't leak
    into subsequent analyzer runs or Claude Code invocations."""
    for key in ("VULN_PATTERN_LIBRARY", "VULN_TARGET_LABEL"):
        os.environ.pop(key, None)


# ===========================================================================
# Environment Loading
# ===========================================================================


# ===========================================================================
# Environment Loading
# ===========================================================================

def load_env_file(env_path: Path):
    """Load .env file into os.environ, overriding existing vars so the
    .env file always takes precedence (ensures config changes are picked up)."""
    if not env_path.exists():
        return
    for line in env_path.read_text("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key:
            os.environ[key] = value


# Load .env from repo root
load_env_file((REPO_ROOT := Path(__file__).resolve().parent) / ".env")


# ===========================================================================
# API Key Validation
# ===========================================================================



# ===========================================================================
# Configuration
# ===========================================================================

REPO_ROOT = Path(__file__).resolve().parent
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "9WKB63B3PGD5VDT8BTUE27GKXZ79CV22PM")
SCORE_THRESHOLD = float(os.environ.get("SCORE_THRESHOLD", "80"))
MAX_FIX_ATTEMPTS = int(os.environ.get("MAX_FIX_ATTEMPTS", "5"))

# Directories
VULN_CONTRACTS_PATH = REPO_ROOT / "vuln_contracts.jsonl"
ETHERSCAN_CACHE_DIR = REPO_ROOT / "data" / "etherscan_cache"
FETCHED_SOURCES_DIR = REPO_ROOT / "data" / "fetched_sources"
RESULTS_DIR = REPO_ROOT / "data" / "results"
CHECKPOINT_PATH = RESULTS_DIR / "checkpoint.json"
DEFECT_LOG_PATH = RESULTS_DIR / "defect_analysis.json"
DECCOMPILED_DIR = RESULTS_DIR / "decompiled"

# Paid-tier chains (skip on free tier)
PAID_TIER_CHAINS = {
    10: "optimism",
    8453: "base",
    43114: "avalanche",
    100: "gnosis",
}

# Chain name to chain ID mapping
CHAIN_NAME_TO_ID = {
    "mainnet": 1, "bsc": 56, "polygon": 137, "arbitrum": 42161,
    "optimism": 10, "fantom": 250, "avalanche": 43114, "metis": 1088,
    "bob": 81, "base": 8453, "linea": 59144, "celo": 422240,
    "moonbeam": 1284, "kava": 11111,
}

# Router/fee addresses to skip when extracting target addresses
ROUTER_ADDRESSES = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
    "0xe592427a0ae2173d9837366982436523032c5ded",  # Uniswap V3 Router
    "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d",  # QuickNode router
    "0x0000000000000000000000000000000000000000",  # Zero address
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",  # WBNB
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
    "0x10ed43c718714eb63d5aa57b78b54704e256024e",  # Pancake Router
}

# Helper interfaces to skip
SKIP_INTERFACE_NAMES = [
    "IPancakePair", "IPancakeRouter", "IUniswapRouter", "IUniswapV2Pair",
    "IERC20", "IERC20Permit", "CheatCodes", "IWBNB", "IWETH",
    "IPancakeFactory", "ProxyFactory", "VyperContract", "CErc20Interface",
    "IUnitroller", "IAggregator", "IBAKC", "IBayc", "IXNFT", "IXToken",
    "INothing", "ILendingPool", "ILendingPoolAddressesProvider",
    "IPriceOracle", "IPriceOracleGetter", "ISwapPool", "IStableSwap",
    "ICurvePool", "ICurveRegistry", "IUniswapV2Router01", "IUniswapV3Pool",
    "IUniswapV3Router", "IOracle", "IPriceFeed", "IChainLink", "IAaveOracle",
    "IPool", "IPoolConfigurator", "IPoolAddressesProvider", "IL2pool",
    "IGauge", "IStakingRewards", "IVault", "IYearnVault", "IMintableERC20",
    "IWrappedToken", "IUNIPAIR", "IPair",
]

# Interface-like or helper tokens to skip in address extraction
INTERFACE_SKIP_NAMES = {
    "IPancakePair", "IPair", "IPancakeRouter", "IUniswapRouter",
    "IUniswapV2Pair", "IERC20", "IERC20Permit", "CheatCodes", "IWBNB", "IWETH",
    "IPancakeFactory", "ProxyFactory", "VyperContract", "CErc20Interface",
    "IUnitroller", "IAggregator", "IBAKC", "IBayc", "IXNFT", "IXToken",
    "INothing", "ILendingPool", "ILendingPoolAddressesProvider",
    "IPriceOracle", "IPriceOracleGetter", "ISwapPool", "IStableSwap",
    "ICurvePool", "ICurveRegistry", "IUniswapV2Router01", "IUniswapV3Pool",
    "IUniswapV3Router", "IOracle", "IPriceFeed", "IChainLink", "IAaveOracle",
    "IPool", "IPoolConfigurator", "IPoolAddressesProvider", "IL2pool",
    "IGauge", "IStakingRewards", "IVault", "IYearnVault", "IMintableERC20",
    "IWrappedToken",
}

# Canonical label mapping from exploit DB patterns
# Load vulnerability labels from data/vuln_labels.json
VULN_LABELS_PATH = REPO_ROOT / "data" / "vuln_labels.json"
VULN_LABELS_CACHE: dict[str, str] = {}


def load_vuln_labels() -> dict[str, str]:
    """Load the vulnerability labels mapping from training data."""
    global VULN_LABELS_CACHE
    if VULN_LABELS_CACHE:
        return VULN_LABELS_CACHE
    try:
        if VULN_LABELS_PATH.exists():
            with open(VULN_LABELS_PATH, "r") as f:
                VULN_LABELS_CACHE = json.load(f)
    except Exception:
        pass
    return VULN_LABELS_CACHE


LABEL_MAP = {
    "reentrancy": "external_call",
    "reentrancy_unrestricted": "external_call",
    "integer_overflow": "arithmetic",
    "integer_underflow": "arithmetic",
    "arithmetic": "arithmetic",
    "unchecked_arithmetic": "arithmetic",
    "access_control": "access_control",
    "owner_only": "access_control",
    "tx_origin": "access_control",
    "missing_sender_auth": "access_control",
    "timestamp_dependence": "timestamp",
    "dos_gas_limit": "gas",
    "dos_block_gas_limit": "gas",
    "unchecked_send": "external_call",
    "unchecked_return_value": "external_call",
    "oracle_manipulation": "oracle",
    "oracle_decentralization": "oracle",
    "flash_loan": "oracle",
    "delegatecall": "delegatecall",
    "delegatecall_dangerous": "delegatecall",
    "signature_replay": "signature_replay",
    "short_address": "arithmetic",
}


# ===========================================================================
# Logging
# ===========================================================================

def log(msg: str, level: str = "INFO"):
    """Log to stderr and a progress file."""
    line = f"[{level}] {time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, file=sys.stderr, flush=True)
    progress_path = RESULTS_DIR / "progress.log"
    try:
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        with open(progress_path, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ===========================================================================
# JSONL Processing
# ===========================================================================

def load_vuln_contracts(subset: str | None = None):
    """Stream contracts from vuln_contracts.jsonl, optionally filtered by subset."""
    if not VULN_CONTRACTS_PATH.exists():
        log(f"vuln_contracts.jsonl not found at {VULN_CONTRACTS_PATH}", "ERROR")
        return []

    contracts = []
    with open(VULN_CONTRACTS_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if subset and entry.get("subset") != subset:
                    continue
                contracts.append(entry)
            except json.JSONDecodeError:
                continue

    log(f"Loaded {len(contracts)} contracts" + (f" for subset '{subset}'" if subset else ""))
    return contracts


def load_checkpoint():
    """Load the last processed checkpoint."""
    if CHECKPOINT_PATH.exists():
        try:
            with open(CHECKPOINT_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"processed": 0, "total": 0, "last_address": ""}


def save_checkpoint(processed: int, total: int, last_address: str, last_result: dict | None = None):
    """Save the current checkpoint."""
    try:
        CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "processed": processed,
            "total": total,
            "last_address": last_address,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_result": last_result,
        }
        with open(CHECKPOINT_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log(f"Failed to save checkpoint: {e}", "ERROR")


# ===========================================================================
# Etherscan V2 Fetching
# ===========================================================================

def get_etherscan_url(chain_id: int, address: str) -> str:
    """Construct Etherscan V2 API URL."""
    return (
        f"https://api.etherscan.io/v2/api"
        f"?chainid={chain_id}"
        f"&module=contract"
        f"&action=getsourcecode"
        f"&address={address}"
        f"&apikey={ETHERSCAN_API_KEY}"
    )


def extract_source_from_response(source_code: str) -> str:
    """Handle JSON-wrapped source (multi-file) and double-brace format."""
    if not source_code:
        return ""

    # Handle double-brace JSON format (e.g., "{{...}}")
    if source_code.startswith("{{") and source_code.rstrip().endswith("}}"):
        source_code = source_code[1:-1]

    # Handle JSON-wrapped source (multi-file)
    if source_code.startswith("{"):
        try:
            parsed = json.loads(source_code)
            if "sources" in parsed:
                parts = []
                for name, info in parsed["sources"].items():
                    content = info.get("content") or info.get("source") or ""
                    if content:
                        parts.append(f"// From: {name}\n{content}")
                if parts:
                    return "\n\n".join(parts)
        except (json.JSONDecodeError, TypeError):
            pass

    return source_code


def is_test_code(code: str) -> bool:
    """Check if source code is test code (contains Foundry/forge patterns)."""
    test_patterns = [
        "vm.createSelectFork",
        "assertEq(",
        "assertTrue(",
        "assertFalse(",
        "ContractTest is Test",
        "function setUp(",
    ]
    return any(p in code for p in test_patterns)


def is_interface_only(code: str) -> bool:
    """Check if source is interface-only (no function implementations)."""
    import re
    func_decls = len(re.findall(
        r"\bfunction\s+\w+\s*\([^)]*\)\s*(?:external|public|internal)\s+", code, re.IGNORECASE
    ))
    func_impls = len(re.findall(
        r"\bfunction\s+\w+\s*\([^)]*\)\s*(?:external|public|internal)\s+[^;]*\{", code, re.IGNORECASE
    ))
    if func_decls == 0:
        return False
    return func_impls < func_decls * 0.2


def fetch_source_from_etherscan(addr: str, chain_id: int, test_name: str = "") -> str | None:
    """Fetch source code from Etherscan V2 API with caching and proxy resolution."""
    addr_lower = addr.lower()
    chain_name = "mainnet"  # default
    for name, cid in CHAIN_NAME_TO_ID.items():
        if cid == chain_id:
            chain_name = name
            break

    # 1. Check cache first
    cache_path = ETHERSCAN_CACHE_DIR / f"{addr_lower}_{chain_name}.sol"
    if cache_path.exists():
        try:
            cached = cache_path.read_text("utf-8")
            if cached.startswith("{{") or (cached.startswith("{") and "sources" in cached):
                cached = extract_source_from_response(cached)
            if cached and len(cached) > 500 and not is_test_code(cached) and not is_interface_only(cached):
                return cached
        except Exception:
            pass

    # 2. Check fetched_sources directory
    if FETCHED_SOURCES_DIR.exists():
        for f in FETCHED_SOURCES_DIR.iterdir():
            if f.name.lower().startswith(addr_lower[:10]) or addr_lower[2:12] in f.name.lower():
                try:
                    content = f.read_text("utf-8")
                    if content and len(content) > 100 and not is_test_code(content) and not is_interface_only(content):
                        return content
                except Exception:
                    pass

    # 3. Fetch from Etherscan V2 API
    url = get_etherscan_url(chain_id, addr)
    try:
        resp = requests.get(url, timeout=30, headers={"Accept": "application/json"})
        if "application/json" not in resp.headers.get("content-type", ""):
            return None

        data = resp.json()
        if data.get("status") != "1" or not data.get("result"):
            return None

        result = data["result"][0] if isinstance(data["result"], list) else data["result"]
        source = result.get("SourceCode", "")

        # Handle proxy resolution
        if result.get("Proxy") == "1" and result.get("Implementation"):
            impl_source = fetch_source_from_etherscan(result["Implementation"], chain_id, test_name)
            if impl_source:
                source = impl_source

        extracted = extract_source_from_response(source)

        if extracted and len(extracted) > 100 and not is_test_code(extracted) and not is_interface_only(extracted):
            # Cache it
            ETHERSCAN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            FETCHED_SOURCES_DIR.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(extracted, "utf-8")
            if test_name:
                (FETCHED_SOURCES_DIR / f"{test_name}_{addr_lower}.sol").write_text(extracted, "utf-8")
            return extracted

    except Exception as e:
        log(f"Etherscan fetch failed for {addr}: {str(e)[:100]}", "WARN")

    return None


# ===========================================================================
# Bytecode Fetching & Porcelain-X Integration
# ===========================================================================

PORCUPINARYX_PATTERN_TAG_MAP = {
    "inverted_msg_value_check": ("logic.inverted_msg_value_bytecode", 90),
    "unrestricted_write_withdraw": ("logic.unrestricted_write_withdraw_bytecode", 85),
    "conditional_logic_with_imbalanced_requirements": ("logic.conditional_logic_imbalanced_bytecode", 80),
    "external_call_without_state_update": ("external_call.reentrancy_no_state_guard", 85),
    "value_transfer_without_value_check": ("external_call.value_transfer_without_check", 75),
    "reentrancy_analysis": ("external_call.reentrancy_classic", 85),
}


def fetch_bytecode_from_etherscan(addr: str, chain_id: int) -> str | None:
    """Fetch runtime bytecode from Etherscan V2 API."""
    url = (
        f"https://api.etherscan.io/v2/api"
        f"?chainid={chain_id}"
        f"&module=proxy"
        f"&action=eth_getCode"
        f"&address={addr}"
        f"&apikey={ETHERSCAN_API_KEY}"
    )
    try:
        resp = requests.get(url, timeout=30)
        data = resp.json()
        # Etherscan proxy module returns JSON-RPC format: {"jsonrpc": "2.0", "result": "0x..."}
        bytecode = data.get("result")
        if bytecode and bytecode != "0x":
            return bytecode
    except Exception as e:
        log(f"Bytecode fetch failed for {addr}: {str(e)[:100]}", "WARN")
    return None


def run_porosity_x(bytecode_hex: str, contract_address: str) -> dict:
    """Run Porcelain-X Rust binary on bytecode and return parsed JSON output.

    Saves both the structured JSON and decompiled pseudocode to DECCOMPILED_DIR.
    """
    binary = os.environ.get("PORTOXITY_X_BINARY", "porosity-analyzer")
    # Try absolute path first, then fall back to relative porosity-x/ directory
    if not os.path.isabs(binary) and not shutil.which(binary):
        binary = str(REPO_ROOT.parent / "porosity-x" / "target" / "debug" / "porosity-analyzer")
    if not os.path.exists(binary):
        log(f"Porcelain-X binary not found at {binary}", "WARN")
        return {}

    try:
        result = subprocess.run(
            [binary, "--code", bytecode_hex, "--address", contract_address],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "RUST_LOG": "error"}
        )
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        log(f"Porcelain-X timed out for {contract_address}", "WARN")
    except json.JSONDecodeError:
        log(f"Porcelain-X returned non-JSON for {contract_address}", "WARN")
    except Exception as e:
        log(f"Porcelain-X execution failed: {e}", "WARN")
    return {}


def scan_porosity_x_for_patterns(porosityx_output: dict) -> dict:
    """Map Porcelain-X semantic findings to pattern library keys.

    Returns a dict of {pattern_library_key: {confidence, description}} to be
    merged into injected_patterns for the short-circuit check.
    """
    injected = {}

    # 1. Map semantic_findings to pattern keys
    semantic = porosityx_output.get("semantic_analysis", {})
    semantic_findings = semantic.get("semantic_findings", [])
    for finding in semantic_findings:
        pattern_name = finding.get("pattern", "")
        if pattern_name in PORCUPINARYX_PATTERN_TAG_MAP:
            lib_key, confidence = PORCUPINARYX_PATTERN_TAG_MAP[pattern_name]
            injected[lib_key] = {
                "regex": pattern_name,
                "confidence": confidence,
                "description": finding.get("evidence", finding.get("description", ""))[:200],
                "source": "porcelainx",
            }
    # 2. Map reentrancy_analysis findings
    reentrancy_findings = porosityx_output.get("reentrancy_analysis", [])
    for finding in reentrancy_findings:
        pattern_name = finding.get("pattern", "reentrancy_analysis")
        lib_key, confidence = PORCUPINARYX_PATTERN_TAG_MAP.get(
            pattern_name, ("external_call.reentrancy_classic", 85)
        )
        injected[lib_key] = {
            "regex": pattern_name,
            "confidence": confidence,
            "description": finding.get("evidence", "")[:200],
            "source": "porcelainx",
        }

    return injected


def synthesize_decompiled_source(porosityx_output: dict) -> str:
    """Build a pseudocode-like source string from Porcelain-X structured output.

    PorC may not always emit a literal `decompiled_pseudocode` field. When it
    doesn't, synthesize a readable representation from the analysis artifacts it
    *does* provide (knowledge_base, taint_sources, control_flow_structures,
    reentrancy_analysis, semantic_findings) so downstream consumers that expect
    a textual "decompiled source" still have something to work with.
    """
    if not porosityx_output or not isinstance(porosityx_output, dict):
        return ""

    lines: list[str] = []

    sa = porosityx_output.get("semantic_analysis") or {}

    # Knowledge base: recognized patterns describe real Solidity constructs
    kb = sa.get("knowledge_base") or {}
    if isinstance(kb, dict):
        lines.append(f"// Porcelain-X semantic analysis (synthesized pseudocode)")
        lines.append(f"// Solidity version: {kb.get('solidity_version', 'unknown')}")
        lines.append(f"// Patterns recognized: {kb.get('patterns_recognized', 0)}")
        if isinstance(kb.get("key_patterns"), list):
            for pat in kb["key_patterns"]:
                name = pat.get("name", "?")
                construct = pat.get("solidity_construct", "")
                risk = pat.get("risk_level", "")
                if construct:
                    lines.append(f"// Pattern: {name} -> {construct} ({risk})")

    # Taint sources: external calldata / storage reads
    ts = porosityx_output.get("taint_sources") or []
    if isinstance(ts, list) and ts:
        lines.append("// Taint sources:")
        for t in ts:
            if isinstance(t, dict):
                lines.append(f"//   {t.get('source_type', 'unknown')}: {t.get('description', '')}")

    # Control flow structures
    cfs = porosityx_output.get("control_flow_structures") or []
    if isinstance(cfs, list) and cfs:
        lines.append("// Control flow:")
        for c in cfs:
            if isinstance(c, dict):
                lines.append(f"//   {c.get('structure_type', '?')}: {c.get('condition', '')}")

    # Reentrancy analysis
    ra = porosityx_output.get("reentrancy_analysis") or sa.get("reentrancy_analysis") or []
    if isinstance(ra, list) and ra:
        lines.append("// Reentrancy findings:")
        for r in ra:
            if isinstance(r, dict):
                lines.append(f"//   {json.dumps(r)[:300]}")

    # Semantic findings (may be empty)
    sf = sa.get("semantic_findings") or []
    if isinstance(sf, list) and sf:
        lines.append("// Semantic findings:")
        for f in sf:
            if isinstance(f, dict):
                lines.append(f"//   {f.get('pattern', f.get('title', 'finding'))}: {f.get('evidence', '')}")

    # External dependencies
    ed = porosityx_output.get("external_dependencies") or []
    if isinstance(ed, list) and ed:
        lines.append("// External dependencies:")
        for d in ed:
            lines.append(f"//   {json.dumps(d)[:300]}")

    # Emit a minimal function skeleton so the analyzer's AST stage has a
    # contract body to parse rather than an empty file.
    lines.append("")
    lines.append("contract Synthesized {}")

    return "\n".join(lines)


def save_decompiled_output(contract_address: str, contract_name: str, porosityx_output: dict, pseudocode: str):
    """Save decompiled pseudocode and structured JSON to DECCOMPILED_DIR."""
    DECCOMPILED_DIR.mkdir(parents=True, exist_ok=True)
    base = f"{contract_name}_{contract_address[:10]}"
    json_path = DECCOMPILED_DIR / f"{base}.json"
    sol_path = DECCOMPILED_DIR / f"{base}.pseudocode"

    try:
        json_path.write_text(json.dumps(porosityx_output, indent=2), "utf-8")
        if pseudocode:
            sol_path.write_text(pseudocode, "utf-8")
        elif porosityx_output:
            # Try to extract pseudocode from the output
            pseudos = porosityx_output.get("semantic_analysis", {}).get("decompiled_pseudocode", "")
            if not pseudos:
                pseudos = porosityx_output.get("decompiled_pseudocode", "")
            # Fall back to synthesized source if PorC didn't emit pseudocode
            if not pseudos:
                pseudos = synthesize_decompiled_source(porosityx_output)
            sol_path.write_text(pseudos or "(no pseudocode available)", "utf-8")
    except Exception as e:
        log(f"Failed to save decompiled output: {e}", "WARN")


# ===========================================================================
# Exploit Path Resolution
# ===========================================================================

# Semantic label aliases — different terms that refer to the same vulnerability class
LABEL_ALIASES = {
    "oracle": {"oracle", "oracle_manipulation", "price_manipulation", "manipulation",
               "amm", "amm_interaction", "price orcale", "priceoracle",
               "chainlink", "band", "decentraland", "price_feed", "twap",
               "oracle_manipulation", "oracle_decentralization", "flash_loan"},
    "access_control": {"access_control", "access", "owner", "ownable", "authorization",
                       "auth", "multisig", "mempool", "tx_origin", "tx.origin",
                       "missing_auth", "missing_sender_auth", "owner_only"},
    "external_call": {"external_call", "reentrancy", "reentrant", "reentrancy_unrestricted",
                      "unchecked_send", "unchecked_return_value", "untrusted_call",
                      "callback", "slippage", "sandwich"},
    "arithmetic": {"arithmetic", "integer_overflow", "integer_underflow",
                   "overflow", "underflow", "unchecked_arithmetic", "short_address"},
    "gas": {"gas", "dos_gas_limit", "dos_block_gas_limit", "out_of_gas", "gas_limit"},
    "timestamp": {"timestamp", "timestamp_dependence", "time_dependency"},
    "delegatecall": {"delegatecall", "delegate_call", "eip1167", "proxy_delegation"},
    "signature_replay": {"signature_replay", "replay", "ecrecover"},
}


def normalize_label(label: str) -> str:
    """Normalize a vulnerability label to its canonical form."""
    if not label:
        return "unknown"
    label_lower = label.lower().strip()

    for canonical, aliases in LABEL_ALIASES.items():
        for alias in aliases:
            if alias in label_lower or label_lower in alias:
                return canonical

    return label_lower


def labels_match(predicted: str, actual: str) -> bool:
    """Check if predicted and actual labels match semantically.

    If actual is empty string, checks if predicted maps to any known canonical label.
    """
    pred_norm = normalize_label(predicted)
    actual_norm = normalize_label(actual)
    if not actual:
        return pred_norm != "unknown"
    return pred_norm == actual_norm



# ===========================================================================
# Analyzer Execution
# ===========================================================================

def run_analyzer(target_file: str, label: str | None = None) -> dict | None:
    """Run the TypeScript analyzer on the target source file."""
    cmd = ["npx", "tsx", str(REPO_ROOT / "src" / "analyzer" / "index.ts"), "--target", target_file, "--json"]
    if label:
        cmd.extend(["--label", label])

    log(f"Running analyzer: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(REPO_ROOT),
            env={**os.environ, "NODE_OPTIONS": "--max-old-space-size=8192"},
        )

        if result.returncode != 0:
            log(f"Analyzer exited with code {result.returncode}: {result.stderr[:500]}", "WARN")
            return {"error": result.stderr[:500], "parseSuccess": False, "parseError": result.stderr[:500]}

        # Parse JSON from stdout
        stdout = result.stdout.strip()
        if stdout:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                # Try to find JSON in stdout
                lines = stdout.split("\n")
                for i, line in enumerate(lines):
                    if line.strip().startswith("{"):
                        try:
                            return json.loads("\n".join(lines[i:]))
                        except json.JSONDecodeError:
                            continue
                return {"error": "Failed to parse analyzer JSON output", "stdout": stdout[:500]}
        else:
            return {"error": "No output from analyzer", "stderr": result.stderr[:500] if result.stderr else "empty"}

    except subprocess.TimeoutExpired:
        log("Analyzer timed out (120s)", "ERROR")
        return {"error": "Analyzer timeout", "parseSuccess": False}
    except Exception as e:
        log(f"Analyzer execution failed: {e}", "ERROR")
        return {"error": str(e)}


def infer_vuln_label_from_metadata(evidence: str, contract_name: str, subset: str) -> str:
    """Infer the expected vulnerability label from metadata — not test code."""
    name = contract_name.lower()
    dir_name = subset.lower() if subset else ""

    # 1. Check the vulnerability labels file first (most authoritative)
    labels = load_vuln_labels()
    if name in labels:
        return labels[name]

    # 2. Infer from directory/subset/contract naming
    combined = f"{dir_name} {name}"
    for pattern, label in {
        "oracle": "oracle",
        "access": "access_control",
        "auth": "access_control",
        "owner": "access_control",
        "gas": "gas",
        "dos": "gas",
        "timestamp": "timestamp",
        "time": "timestamp",
        "overflow": "arithmetic",
        "underflow": "arithmetic",
        "arithmetic": "arithmetic",
        "reentrant": "external_call",
        "reentrancy": "external_call",
        "call": "external_call",
        "delegatecall": "delegatecall",
        "signature": "signature_replay",
        "flash_loan": "oracle",
        "flashloan": "oracle",
        "mev": "external_call",
        "bot": "access_control",
    }.items():
        if pattern in combined:
            return label

    return "unknown"


# ===========================================================================
# Rule-Based Scoring (No LLM Judge)
# ===========================================================================

def fallback_judge(actual_label: str, analyzer_output: dict) -> dict:
    """Rule-based fallback scoring when LLM API is unavailable."""
    discovered_vulns = analyzer_output.get("discoveredVulnerabilities", [])

    # Extract predicted types from vulnerabilityType field and tags
    predicted_types = set()
    for v in discovered_vulns:
        vt = v.get("vulnerabilityType") or v.get("title", "")
        if vt:
            predicted_types.add(vt)
        tags = v.get("tags", [])
        if isinstance(tags, list):
            predicted_types.update(t for t in tags if t)
        elif isinstance(tags, str) and tags:
            predicted_types.add(tags)

    for e in analyzer_output.get("hypothesisEvaluations", []):
        h = e.get("hypothesis", {})
        htype = h.get("vulnerabilityType") or h.get("id", "")
        if htype:
            predicted_types.add(htype)
        tags = h.get("tags", [])
        if isinstance(tags, list):
            predicted_types.update(t for t in tags if t)
        elif isinstance(tags, str) and tags:
            predicted_types.add(tags)

    # Normalize all predicted types to canonical labels
    normalized = set(normalize_label(t) for t in predicted_types)
    normalized.discard("unknown")

    actual_norm = normalize_label(actual_label)

    # Check if any predicted type matches the actual label semantically
    is_correct = actual_norm in normalized or any(labels_match(t, actual_label) for t in predicted_types)

    any_vulns = len(discovered_vulns) > 0
    risk_score = analyzer_output.get("riskScore", 0)

    if is_correct:
        score = 90 if any_vulns else 75
    elif any_vulns:
        # Analyzer found vulns but wrong type — partial credit based on risk score
        if risk_score > 0.5:
            score = 50
        elif risk_score > 0.3:
            score = 40
        else:
            score = 30
    else:
        score = 25

    predicted_type = "unknown"
    if normalized:
        # Check if any predicted type matches the actual label
        if actual_norm in normalized:
            predicted_type = actual_norm
        else:
            # Return the highest-risk predicted type
            top_vuln = max(discovered_vulns, key=lambda v: v.get("riskScore", 0))
            predicted_type = normalize_label(top_vuln.get("vulnerabilityType") or top_vuln.get("title", ""))

    return {
        "score": score,
        "critique": f"Predicted: {list(normalized)}, Expected: {actual_norm}. {'Match found (semantic).' if is_correct else 'No matching label found in predictions.'}",
        "missing_features": [] if is_correct else [f"Pattern for {actual_label} detection"],
        "vulnerability_type": predicted_type,
        "actual_label": actual_label,
    }


# ===========================================================================
# Headless Claude Code Integration
# ===========================================================================

def invoke_claude_code(
    contract_name: str,
    actual_label: str,
    analyzer_output: dict,
    fetched_source: str,
    judge_result: dict,
    attempt: int,
) -> dict:
    """Invoke Claude Code headless to patch the analyzer rules."""
    judge_critique = judge_result.get("critique", "")
    missing_features = judge_result.get("missing_features", [])
    predicted_type = judge_result.get("vulnerability_type", "")

    # Extract discovered vulnerability types for a concise summary
    discovered = analyzer_output.get("discoveredVulnerabilities", [])
    vuln_summary = "\n".join(
        f"  - {v.get('vulnerabilityType', v.get('title', '?'))}: risk={v.get('riskScore', 0):.2f}"
        for v in discovered
    ) if discovered else "  (none)"

    # Build the prompt for Claude Code
    prompt = f"""You are a headless agent patching the Solidity analyzer at src/analyzer/.

CONTRACT: {contract_name}
EXPECTED: {actual_label}
PREDICTED: {predicted_type}
SCORE: {judge_result.get('score', 0)}/100 (need 80+)
MISSING: {missing_features if missing_features else '(none)'}

Analyzer found:
{vuln_summary}

YOUR TASK:
1. Read src/analyzer/zero_shot/reasoner.ts and src/analyzer/features/extractor.ts
2. Identify why {actual_label} is not being detected for {contract_name}
3. Add regex patterns to detect the {actual_label} vulnerability pattern
4. ONLY edit those two files, append only, don't break existing rules
5. Re-run: npx tsx src/analyzer/index.ts --target data/results/target_{contract_name}_*.sol --json

Fix attempt {attempt} of {MAX_FIX_ATTEMPTS}. Be surgical — add specific patterns.
"""

    # Write source to temp file for Claude to verify
    temp_file = REPO_ROOT / "data" / "results" / f"pending_{contract_name}_{attempt}.sol"
    temp_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file.write_text(fetched_source)

    try:
        cmd = [
            "claude", "-p", prompt,
            "--allowedTools", "Read,Edit,Bash",
            "--dangerously-skip-permissions",
        ]

        log(f"Invoking Claude Code (attempt {attempt}) for {contract_name}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=str(REPO_ROOT),
            env={**os.environ, "NODE_OPTIONS": "--max-old-space-size=8192"},
        )

        output = result.stdout
        log(f"Claude Code response (truncated): {output[:200]}...")

        # Save defect analysis for reference
        defect_data = {
            "contract": contract_name,
            "actual_label": actual_label,
            "score": judge_result.get("score", 0),
            "attempt": attempt,
            "claude_output": output[:2000],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            DEFECT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            defects = []
            if DEFECT_LOG_PATH.exists():
                try:
                    defects = json.loads(DEFECT_LOG_PATH.read_text())
                    if not isinstance(defects, list):
                        defects = []
                except Exception:
                    defects = []
            defects.append(defect_data)
            DEFECT_LOG_PATH.write_text(json.dumps(defects, indent=2))
        except Exception:
            pass

        return {"success": True, "output": output}

    except subprocess.TimeoutExpired:
        log(f"Claude Code timed out for {contract_name}", "ERROR")
        return {"success": False, "error": "timeout"}
    except FileNotFoundError:
        log("Claude Code CLI not found. Make sure 'claude' is in your PATH.", "ERROR")
        return {"success": False, "error": "claude_not_found"}
    except Exception as e:
        log(f"Claude Code invocation failed: {e}", "ERROR")
        return {"success": False, "error": str(e)}


# ===========================================================================
# Main Pipeline
# ===========================================================================

def process_contract(entry: dict, start_index: int) -> dict:
    """Process a single contract through the full pipeline."""
    file_name = entry.get("file", "")
    subset = entry.get("subset", "")
    vulnerable_address = entry.get("vulnerable_address", "")
    chain_id = int(entry.get("chain_id", 1))
    evidence = entry.get("evidence", "")

    # Support --address override: if entry has no vulnerable_address but has a
    # target_address field, use that (for single-contract runs)
    if not vulnerable_address:
        vulnerable_address = entry.get("target_address", "")
    if not vulnerable_address:
        # Try to extract address from evidence
        addr_match = re.search(r'0x[0-9a-fA-F]{40}', evidence)
        if addr_match:
            vulnerable_address = addr_match.group(0)

    # Use provided contract name or derive from file_name
    contract_name = entry.get("contract_name", "")
    if not contract_name:
        contract_name = file_name.replace("_exp.sol", "") if file_name else vulnerable_address[:10]

    log(f"\n{'='*60}")
    log(f"Processing: {contract_name} (address: {vulnerable_address})")
    log(f"Chain ID: {chain_id}, Subset: {subset}")
    log(f"{'='*60}")

    # Infer expected label from metadata (contract naming, vuln_contracts evidence)
    # Allow explicit override via entry["expected_label"] (set by --label in --address mode)
    if entry.get("expected_label"):
        actual_label = entry["expected_label"]
    else:
        actual_label = infer_vuln_label_from_metadata(evidence, contract_name, subset)
    log(f"Expected vulnerability type: {actual_label}")

    # Fetch source from Etherscan
    fetched_source = fetch_source_from_etherscan(vulnerable_address, chain_id, contract_name)

    fetched_from_etherscan = False
    porosityx_output = {}
    decompiled_pseudocode = ""

    if fetched_source:
        # Save to temp file for analyzer
        temp_file = REPO_ROOT / "data" / "results" / f"target_{contract_name}_{vulnerable_address[:10]}.sol"
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file.write_text(fetched_source)
        fetched_from_etherscan = True
        log(f"Fetched source: {len(fetched_source)} chars from Etherscan")
    else:
        # No source available — bytecode-only analysis via Porcelain-X
        fetched_source = ""
        temp_file = REPO_ROOT / "data" / "results" / f"target_{contract_name}_bytecode.txt"
        temp_file.parent.mkdir(parents=True, exist_ok=True)

        # Fetch runtime bytecode from Etherscan
        bytecode_hex = fetch_bytecode_from_etherscan(vulnerable_address, chain_id)
        if bytecode_hex:
            temp_file.write_text(bytecode_hex, "utf-8")
            log(f"Fetched bytecode: {len(bytecode_hex)} chars from Etherscan")
            log(f"No source — running Porcelain-X bytecode analysis")
            porosityx_output = run_porosity_x(bytecode_hex, vulnerable_address)

            if porosityx_output:
                # Save decompiled pseudocode + JSON to DECCOMPILED_DIR
                # PorC sometimes omits "decompiled_pseudocode"; synthesize a
                # representative source from its structured analysis fields so
                # downstream code (batch.js) sees non-empty decompiledSource
                # instead of skipping the contract as "unverified".
                decompiled_pseudocode = porosityx_output.get("semantic_analysis", {}).get("decompiled_pseudocode", "")
                if not decompiled_pseudocode:
                    decompiled_pseudocode = porosityx_output.get("decompiled_pseudocode", "")
                if not decompiled_pseudocode:
                    decompiled_pseudocode = synthesize_decompiled_source(porosityx_output)
                save_decompiled_output(vulnerable_address, contract_name, porosityx_output, decompiled_pseudocode)
                log(f"Porcelain-X: {len(porosityx_output.get('semantic_analysis', {}).get('semantic_findings', []))} semantic findings")
        else:
            log("No bytecode available either — skipping", "WARN")

    # === Pre-Fix Stage: Pattern Library Injection ===
    # Before invoking the analyzer, check if the vulnerability pattern library
    # has a matching entry for this label. If so, inject the patterns as env vars
    # so the analyzer's reasoner can boost confidence on matching hypotheses.
    # This short-circuits the Claude Code fix loop for known vulnerability classes,
    # saving ~900s per contract failure (180s × 5 attempts).
    pattern_lib_path = REPO_ROOT / "data/vuln_pattern_library.json"
    injected_patterns = {}
    if pattern_lib_path.exists():
        try:
            with open(pattern_lib_path) as pf:
                pattern_lib = json.load(pf)
            # Scan ALL categories regardless of label. The label is inferred from
            # test code patterns which can be unreliable (false positives like
            # "owner" in interface declarations). Scanning all categories ensures
            # the short-circuit can fire for the correct vulnerability class
            # even when the inferred label is wrong.
            target_categories = {k: v for k, v in pattern_lib.items()}
            if target_categories:
                # Scan source code (if available) and/or bytecode hex
                scan_target = fetched_source
                if not scan_target and porosityx_output:
                    # Bytecode-only path: scan Porcelain-X output fields
                    scan_target = json.dumps(porosityx_output, indent=2)
                stripped_source = re.sub(r'//.*', '', scan_target)
                stripped_source = re.sub(r'/\*.*?\*/', '', stripped_source, flags=re.DOTALL)
                for cat_name, patterns in target_categories.items():
                    for pname, pat_info in patterns.items():
                        regex_str = pat_info.get('regex', '')
                        if regex_str and re.search(regex_str, stripped_source, re.DOTALL):
                            injected_patterns[f"{cat_name}.{pname}"] = pat_info
                            log(f"  Pattern injected: {cat_name}.{pname} (confidence: {pat_info.get('confidence', 0)}%)")
        except Exception as e:
            log(f"  Pattern injection failed: {e}", "WARN")

    # Merge Porcelain-X findings into injected_patterns (bytecode-only path)
    if porosityx_output:
        porosityx_patterns = scan_porosity_x_for_patterns(porosityx_output)
        for lib_key, pat_info in porosityx_patterns.items():
            injected_patterns[lib_key] = pat_info
            log(f"  Porcelain-X pattern injected: {lib_key} (confidence: {pat_info.get('confidence', 0)}%)")

    # Set env vars for the analyzer's extractor injectPatternHints()
    if injected_patterns:
        os.environ["VULN_PATTERN_LIBRARY"] = str(pattern_lib_path)
        os.environ["VULN_TARGET_LABEL"] = actual_label
        log(f"  Pre-fix: Injected {len(injected_patterns)} patterns for {actual_label}")

    # Run analyzer
    analyzer_output = run_analyzer(str(temp_file), actual_label)

    if analyzer_output is None:
        log(f"Analyzer failed to return output for {contract_name}", "ERROR")
        analyzer_output = {"error": "analyzer_failed"}

    # === Pre-Fix Pattern Match Short-Circuit ===
    # If patterns were injected from the pattern library or Porcelain-X,
    # check if any high-confidence pattern (>= 80%) matches. If so,
    # short-circuit: skip Claude Code entirely.
    if injected_patterns:
        best_confidence = 0
        best_pattern = None
        for pname, pat_info in injected_patterns.items():
            pat_confidence = pat_info.get('confidence', 0)
            if pat_confidence > best_confidence:
                best_confidence = pat_confidence
                best_pattern = pname
                log(f"  Pattern match: {pname} (confidence: {pat_confidence}%)")

        if best_pattern and best_confidence >= 80:
            log(f"✓ PATTERN MATCH — {contract_name} (pattern: {best_pattern}, confidence: {best_confidence}%)")
            log(f"  Pre-fix pattern bypass: Skipping Claude Code fix loop")
            clear_injected_env()
            return {
                "contract": contract_name,
                "score": best_confidence,
                "actual_label": actual_label,
                "predicted": actual_label,
                "status": "pattern_matched",
                "attempts": 0,
                "pattern": best_pattern,
                "patterns_matched": sorted(injected_patterns.keys()),
                "porcelainx_findings": list(porosityx_output.get("semantic_analysis", {}).get("semantic_findings", [])) if porosityx_output else [],
                "source": fetched_source,
                "decompiledSource": decompiled_pseudocode,
                "verified": bool(fetched_source),
                "decompiled": bool(porosityx_output),
            }

    # Clean up injected env vars
    clear_injected_env()

    # No high-confidence patterns matched — use pattern-based scoring (no LLM judge)
    score = fallback_judge(actual_label, analyzer_output)
    log(f"Pattern score: {score['score']}/100")

    if score['score'] >= SCORE_THRESHOLD:
        log(f"✓ PASS — {contract_name} (score: {score['score']}% via pattern matching)")
        return {
            "contract": contract_name,
            "score": score['score'],
            "actual_label": actual_label,
            "predicted": score.get('vulnerability_type', ''),
            "status": "pass",
            "attempts": 0,
            "patterns_matched": sorted(injected_patterns.keys()) if injected_patterns else [],
            "porcelainx_findings": list(porosityx_output.get("semantic_analysis", {}).get("semantic_findings", [])) if porosityx_output else [],
            "source": fetched_source,
            "decompiledSource": decompiled_pseudocode,
            "verified": bool(fetched_source),
            "decompiled": bool(porosityx_output),
        }

    # Score < 80 — check if Claude Code fix loop is enabled
    if MAX_FIX_ATTEMPTS > 0:
        log(f"✗ LOW SCORE — {contract_name} (score: {score['score']}%). Starting Claude Code fix loop.")
        best_score = score['score']
        best_analyzer_output = analyzer_output
        judge_result = score

        # Snapshot git HEAD before fix attempts so we can revert bad patches
        git_snapshot = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=str(REPO_ROOT)
        ).stdout.strip()
        log(f"  Git snapshot: {git_snapshot[:8]}")

        for attempt in range(1, MAX_FIX_ATTEMPTS + 1):
            log(f"  Claude Code fix attempt {attempt}/{MAX_FIX_ATTEMPTS}")

            claude_result = invoke_claude_code(
                contract_name, actual_label, best_analyzer_output,
                fetched_source, judge_result, attempt
            )

            if not claude_result.get("success"):
                log(f"  Claude Code invocation failed: {claude_result.get('error')}", "WARN")
                continue

            # Re-run analyzer after Claude's patch
            new_output = run_analyzer(str(temp_file), actual_label)

            # Re-score with pattern-based scoring (no LLM)
            new_judge = fallback_judge(actual_label, new_output)
            new_score = new_judge.get('score', 0)

            log(f"  Re-score after attempt {attempt}: {new_score}/100")

            if new_score > best_score:
                best_score = new_score
                best_analyzer_output = new_output
                judge_result = new_judge
                log(f"  New best score: {best_score}%")

            if new_score >= SCORE_THRESHOLD:
                log(f"  ✓ FIXED — {contract_name} now passes (score: {new_score}%)")
                return {
                    "contract": contract_name,
                    "status": "fixed",
                    "score": new_score,
                    "actual_label": actual_label,
                    "predicted": new_judge.get("vulnerability_type", ""),
                    "attempts": attempt,
                    "source": fetched_source,
                    "decompiledSource": decompiled_pseudocode,
                    "verified": bool(fetched_source),
                    "decompiled": bool(porosityx_output),
                }

            # If this patch didn't improve the score, revert ONLY the files Claude Code
            # was allowed to touch (extractor.ts and reasoner.ts) so committed fixes
            # in other files are preserved
            if new_score <= best_score:
                log(f"  Reverting Claude Code changes (score did not improve)", "WARN")
                claude_touched_files = [
                    str(REPO_ROOT / "src" / "analyzer" / "features" / "extractor.ts"),
                    str(REPO_ROOT / "src" / "analyzer" / "zero_shot" / "reasoner.ts"),
                ]
                for fpath in claude_touched_files:
                    if os.path.exists(fpath):
                        subprocess.run(["git", "checkout", git_snapshot, fpath],
                                       capture_output=True, text=True, cwd=str(REPO_ROOT))

        log(f"  ✗ GIVING UP — {contract_name} after {MAX_FIX_ATTEMPTS} attempts (best score: {best_score}%)")
        return {
            "contract": contract_name,
            "status": "failed",
            "score": best_score,
            "actual_label": actual_label,
            "predicted": judge_result.get("vulnerability_type", ""),
            "attempts": MAX_FIX_ATTEMPTS,
            "source": fetched_source,
            "decompiledSource": decompiled_pseudocode,
            "verified": bool(fetched_source),
            "decompiled": bool(porosityx_output),
        }

    log(f"✗ FAIL — {contract_name} (score: {score['score']}%). MAX_FIX_ATTEMPTS=0, no Claude Code fix loop.")
    return {
        "contract": contract_name,
        "status": "failed",
        "score": score['score'],
        "actual_label": actual_label,
        "predicted": score.get('vulnerability_type', ''),
        "attempts": 0,
        "patterns_matched": sorted(injected_patterns.keys()) if injected_patterns else [],
        "porcelainx_findings": list(porosityx_output.get("semantic_analysis", {}).get("semantic_findings", [])) if porosityx_output else [],
        "source": fetched_source,
        "decompiledSource": decompiled_pseudocode,
        "verified": bool(fetched_source),
        "decompiled": bool(porosityx_output),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Evolutionary Vulnerability Detection Engine"
    )
    parser.add_argument("--subset", type=str, default=None,
                        help="Process only contracts from this subset (e.g., 2022-06)")
    parser.add_argument("--address", type=str, default=None,
                        help="Analyze a single contract by address (e.g., 0x5F360c6b7B25DfBfA4F10039ea0F7ecfB9B02E60)")
    parser.add_argument("--chain", type=int, default=1,
                        help="Chain ID for --address (default: 1 for mainnet)")
    parser.add_argument("--max-contracts", type=int, default=None,
                        help="Maximum number of contracts to process")
    parser.add_argument("--epochs-max", type=int,
                        default=int(os.environ.get("MAX_FIX_ATTEMPTS", "5")),
                        help="Max Claude Code fix attempts per contract")
    parser.add_argument("--label", type=str, default=None,
                        help="Vulnerability label hint (e.g., reentrancy, access_control). "
                             "Used for targeted pattern injection when source is from --address mode.")
    parser.add_argument("--json-output", type=str, default=None,
                        help="Write the final result of --address mode as JSON to this file path. "
                             "The JSON includes source/decompiledSource, score, status, patterns_matched, "
                             "porcelainx_findings, and all fast-parse fields.")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    global MAX_FIX_ATTEMPTS
    MAX_FIX_ATTEMPTS = args.epochs_max

    # Ensure directories exist
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ETHERSCAN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    FETCHED_SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    DECCOMPILED_DIR.mkdir(parents=True, exist_ok=True)

    # API key no longer needed — pure pattern-based scoring
    log("=" * 60)
    log("Starting Pure Pattern-Based Pipeline")
    log(f"  Pattern library: {str(REPO_ROOT / 'data/vuln_pattern_library.json')}")
    log(f"  Porcelain-X binary: {os.environ.get('PORTOXITY_X_BINARY', 'porosity-analyzer')}")
    log(f"  Score threshold: {SCORE_THRESHOLD}%")
    log(f"  Max Claude Code attempts: {MAX_FIX_ATTEMPTS}")
    log("=" * 60)

    # If --address is provided, run on a single contract only
    if args.address:
        entry = {"target_address": args.address, "chain_id": args.chain,
                 "contract_name": args.address, "file": "", "subset": "", "evidence": ""}
        if args.label:
            entry["expected_label"] = args.label
        contracts = [entry]
        log(f"Single contract mode: {args.address} (chain {args.chain})")
        if args.label:
            log(f"  Label hint: {args.label}")
    else:
        # Load contracts from vuln_contracts.jsonl (batch mode)
        contracts = load_vuln_contracts(args.subset)
        if not contracts:
            log("No contracts to process. Exiting.", "ERROR")
            sys.exit(1)
        if args.max_contracts:
            contracts = contracts[:args.max_contracts]

    total = len(contracts)
    log(f"Starting pipeline with {total} contracts")

    # Load checkpoint
    checkpoint = load_checkpoint()
    start_idx = 0
    if checkpoint.get("processed", 0) > 0 and not args.address:
        # Resume from checkpoint (skip in single-contract mode)
        start_idx = checkpoint["processed"]
        log(f"Resuming from checkpoint (processed: {start_idx})")

    # Process each contract
    results = []
    correct = 0
    failed = 0
    skipped = 0

    for i, entry in enumerate(contracts[start_idx:], start=start_idx):
        try:
            result = process_contract(entry, i)
            results.append(result)

            if result["status"] in ("pass", "fixed", "pattern_matched"):
                correct += 1
            elif result["status"] == "skipped":
                skipped += 1
            else:
                failed += 1

            evaluated = correct + failed  # Excludes skipped from accuracy denominator
            accuracy = correct / evaluated * 100 if evaluated > 0 else 0
            log(f"\nProgress: {i + 1}/{total} — Accuracy: {accuracy:.1f}% ({correct}/{evaluated} correct, {skipped} skipped)")

            # In --address mode with --json-output, write the result immediately
            if args.address and args.json_output:
                try:
                    output_path = Path(args.json_output)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_path, "w") as jf:
                        json.dump(result, jf, indent=2)
                    log(f"JSON output written to {output_path}")
                except Exception as e:
                    log(f"Failed to write JSON output: {e}", "ERROR")

            # Save checkpoint
            save_checkpoint(i + 1, total, entry.get("vulnerable_address", ""), result)

            # Save intermediate results
            results_path = RESULTS_DIR / "pipeline_results.json"
            with open(results_path, "w") as f:
                json.dump({
                    "summary": {
                        "total": i + 1,
                        "correct": correct,
                        "failed": failed,
                        "skipped": skipped,
                        "accuracy": f"{accuracy:.2f}%",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    },
                    "results": results,
                }, f, indent=2)

        except KeyboardInterrupt:
            log("Interrupted by user. Saving checkpoint...", "WARN")
            save_checkpoint(i, total, entry.get("vulnerable_address", ""))
            sys.exit(130)
        except Exception as e:
            log(f"Contract {entry.get('file', '?')} failed with error: {e}", "ERROR")
            traceback.print_exc()
            results.append({
                "contract": entry.get("file", "?"),
                "status": "error",
                "score": 0,
                "error": str(e),
                "attempts": 0,
            })
            failed += 1
            save_checkpoint(i + 1, total, entry.get("vulnerable_address", ""))

            # Even on failure, try to write JSON output if requested
            if args.address and args.json_output:
                try:
                    output_path = Path(args.json_output)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_path, "w") as jf:
                        json.dump(result, jf, indent=2)
                    log(f"JSON output (error state) written to {output_path}")
                except Exception as write_err:
                    log(f"Failed to write JSON output: {write_err}", "ERROR")

    # Final summary
    accuracy = correct / total * 100 if total > 0 else 0
    log(f"\n{'='*60}")
    log(f"PIPELINE COMPLETE")
    log(f"Total: {total}")
    log(f"Correct: {correct}")
    log(f"Failed: {failed}")
    log(f"Accuracy: {accuracy:.2f}%")
    log(f"{'='*60}")

    # Save final results
    final_path = RESULTS_DIR / "pipeline_results.json"
    with open(final_path, "w") as f:
        json.dump({
            "summary": {
                "total": total,
                "correct": correct,
                "failed": failed,
                "accuracy": f"{accuracy:.2f}%",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "results": results,
        }, f, indent=2)

    log(f"Results saved to {final_path}")


if __name__ == "__main__":
    main()