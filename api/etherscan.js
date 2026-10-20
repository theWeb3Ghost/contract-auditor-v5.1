// GET /api/etherscan?address=0x...&chainId=1
// Looks up a contract's verified source via Etherscan's unified V2 API.
// If the contract is a proxy, resolves and returns the implementation's source instead.
// If source is not verified on Etherscan, falls back to the evolution_orchestrator
// which uses Porcelain-X Rust decompiler to produce pseudocode from bytecode.

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ORCHESTRATOR_PATH = process.env.EVOLUTION_ORCHESTRATOR_PATH ||
  '/home/ghost/projects/learner/evolution_orchestrator.py';
const PYTHON_BIN = process.env.PYTHON_BIN || 'python3';
const EVOLVE_TIMEOUT_MS = 180000;

async function runEvolutionOrchestrator(address, chainId) {
  const tmpDir = path.join(os.tmpdir(), 'v4-evolve');
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  const jsonOutputPath = path.join(tmpDir, `evolve_${Date.now()}_${Math.random().toString(36).slice(2)}.json`);

  const cmd = [
    PYTHON_BIN,
    ORCHESTRATOR_PATH,
    '--address', address,
    '--chain', String(chainId),
    '--json-output', jsonOutputPath,
    '--epochs-max', '0',
  ];

  return new Promise((resolve, reject) => {
    const child = spawn(cmd[0], cmd.slice(1), {
      cwd: path.dirname(ORCHESTRATOR_PATH),
      env: { ...process.env, NODE_OPTIONS: undefined },
    });

    let stderrBuffer = '';
    child.stderr.on('data', d => stderrBuffer += d.toString());

    const cleanup = () => {
      try { if (fs.existsSync(jsonOutputPath)) fs.unlinkSync(jsonOutputPath); } catch (_) {}
    };

    child.on('error', reject);

    const timeoutId = setTimeout(() => {
      child.kill('SIGKILL');
      cleanup();
      reject(new Error(`Evolution orchestrator timed out after ${EVOLVE_TIMEOUT_MS / 1000}s`));
    }, EVOLVE_TIMEOUT_MS);

    child.on('close', code => {
      clearTimeout(timeoutId);
      if (fs.existsSync(jsonOutputPath)) {
        try {
          const data = JSON.parse(fs.readFileSync(jsonOutputPath, 'utf-8'));
          cleanup();
          resolve(data);
        } catch (e) {
          cleanup();
          reject(new Error(`Failed to parse orchestrator JSON: ${e.message}`));
        }
      } else {
        cleanup();
        reject(new Error(`Orchestrator exited with code ${code}, no JSON output`));
      }
    });
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-etherscan-key');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const { address, chainId } = req.query;

  if (!address || !chainId) {
    return res.status(400).json({ error: 'address and chainId are required query params' });
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return res.status(400).json({ error: `not a valid address: ${address}` });
  }

  const apiKey = req.headers['x-etherscan-key'] || process.env.ETHERSCAN_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'No Etherscan API key provided (header x-etherscan-key or ETHERSCAN_API_KEY env var)' });
  }

  try {
    const base = await fetchSource(address, chainId, apiKey);
    if (!base) {
      return res.status(502).json({ error: 'Etherscan returned no result for this address' });
    }

    if (!base.SourceCode) {
      // Source not verified on Etherscan — fall back to evolution_orchestrator
      // which will attempt bytecode fetch + Porcelain-X decompilation.
      try {
        const evolveResult = await runEvolutionOrchestrator(address, chainId);
        if (evolveResult.decompiledSource || evolveResult.source) {
          return res.json({
            address,
            verified: evolveResult.verified || false,
            isDecompiled: true,
            source: evolveResult.decompiledSource || evolveResult.source || '',
            contractName: evolveResult.contract || address,
            isProxy: false,
            implementation: null,
            fastParseResult: {
              score: evolveResult.score,
              status: evolveResult.status,
              patterns_matched: evolveResult.patterns_matched || [],
              porcelainx_findings: evolveResult.porcelainx_findings || [],
              actual_label: evolveResult.actual_label,
              predicted: evolveResult.predicted,
            },
            note: 'Source not verified on Etherscan; code is decompiled pseudocode from Porcelain-X.'
          });
        }
      } catch (evolveErr) {
        // Orchestrator failed — return the basic unverified response
        console.error(`[etherscan] Orchestrator fallback failed: ${evolveErr.message}`);
      }

      return res.json({ address, verified: false });
    }

    let finalSource = base.SourceCode;
    let finalName = base.ContractName;
    let implementation = null;

    const looksLikeProxy =
      base.Proxy === '1' && /^0x[a-fA-F0-9]{40}$/.test(base.Implementation || '');

    if (looksLikeProxy) {
      implementation = base.Implementation;
      const implData = await fetchSource(implementation, chainId, apiKey);
      if (implData && implData.SourceCode) {
        finalSource = implData.SourceCode;
        finalName = implData.ContractName || finalName;
      } else {
        return res.json({
          address,
          verified: true,
          isProxy: true,
          implementation,
          implementationVerified: false,
          contractName: base.ContractName,
          note: 'Proxy contract; implementation address found but its source is not verified.',
        });
      }
    }

    const flattened = flattenSource(finalSource);

    let evolve = null;
    try {
      evolve = await runEvolutionOrchestrator(address, chainId);
    } catch (evolveErr) {
      console.error(`[etherscan] Orchestrator analysis failed for verified contract ${address}: ${evolveErr.message}`);
    }

    return res.json({
      address,
      verified: true,
      isProxy: looksLikeProxy,
      implementation,
      contractName: finalName || 'Unknown',
      source: flattened,
      fastParseResult: evolve ? {
        score: evolve.score,
        status: evolve.status,
        patterns_matched: evolve.patterns_matched || [],
        porcelainx_findings: evolve.porcelainx_findings || [],
        actual_label: evolve.actual_label,
        predicted: evolve.predicted,
      } : null,
    });
  } catch (err) {
    return res.status(500).json({ error: String(err && err.message ? err.message : err) });
  }
}

async function fetchSource(address, chainId, apiKey) {
  const url = `https://api.etherscan.io/v2/api?chainid=${encodeURIComponent(
    chainId
  )}&module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
  const r = await fetch(url);
  const j = await r.json();
  if (j.status !== '1' || !Array.isArray(j.result) || !j.result[0]) return null;
  return j.result[0];
}

function flattenSource(raw) {
  let s = (raw || '').trim();
  try {
    if (s.startsWith('{{') && s.endsWith('}}')) {
      s = s.slice(1, -1);
    }
    if (s.startsWith('{')) {
      const parsed = JSON.parse(s);
      const sources = parsed.sources || parsed;
      let out = '';
      for (const [file, content] of Object.entries(sources)) {
        const code = (content && (content.content || content)) || '';
        out += `// ==== FILE: ${file} ====\n${code}\n\n`;
      }
      return out.trim() || raw;
    }
  } catch (e) {
    // Not valid JSON — treat as a raw single-file source instead.
  }
  return raw;
      }


module.exports.fetchSource = fetchSource;
module.exports.flattenSource = flattenSource;
