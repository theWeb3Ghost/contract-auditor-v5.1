// api/evolve.js
//
// POST /api/evolve
// Spawns the learner/evolution_orchestrator.py as a subprocess and returns
// its fast-parse output + source (or decompiled pseudocode).
//
// This endpoint is the bridge between contract-auditor-v4 and the Python
// evolution_orchestrator. It delegates bytecode-only analysis to Porcelain-X
// when the contract source is not verified on Etherscan.

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const ORCHESTRATOR_PATH = process.env.EVOLUTION_ORCHESTRATOR_PATH ||
    path.join(__dirname, '..', 'learner', 'evolution_orchestrator.py');

const PYTHON_BIN = process.env.PYTHON_BIN || 'python3';

const EVOLVE_TIMEOUT_MS = 180000; // 3 minutes — covers Etherscan + analyzer + Porcelain-X

module.exports = async function evolveHandler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-etherscan-key');

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed. Use POST.' });
    }

    const { address, chainId, label } = req.body || {};

    if (!address) {
        return res.status(400).json({ error: 'address is required' });
    }

    if (!chainId) {
        return res.status(400).json({ error: 'chainId is required' });
    }

    const tmpDir = path.join(require('os').tmpdir(), 'v4-evolve');
    if (!fs.existsSync(tmpDir)) {
        fs.mkdirSync(tmpDir, { recursive: true });
    }
    const jsonOutputPath = path.join(tmpDir, `evolve_${Date.now()}_${Math.random().toString(36).slice(2)}.json`);

    const cmd = [
        PYTHON_BIN,
        ORCHESTRATOR_PATH,
        '--address', address,
        '--chain', String(chainId),
        '--json-output', jsonOutputPath,
        '--epochs-max', '0',  // Never invoke Claude Code fix loop in v4 integration
    ];

    if (label) {
        cmd.push('--label', label);
    }

    try {
        const child = spawn(cmd[0], cmd.slice(1), {
            cwd: path.dirname(ORCHESTRATOR_PATH),
            env: {
                ...process.env,
                NODE_OPTIONS: undefined,  // Don't pass Node options to Python
            },
            timeout: EVOLVE_TIMEOUT_MS,
        });

        let stderrBuffer = '';

        child.stderr.on('data', (data) => {
            stderrBuffer += data.toString();
        });

        const cleanup = () => {
            try {
                if (fs.existsSync(jsonOutputPath)) {
                    fs.unlinkSync(jsonOutputPath);
                }
            } catch (_) {}
        };

        child.on('error', (err) => {
            cleanup();
            console.error('[EVOLVE] Spawn error:', err.message);
            res.status(500).json({ error: `Failed to spawn orchestrator: ${err.message}` });
        });

        child.on('close', (code) => {
            // Even if the child exited, the JSON file should have been written
            // (the orchestrator writes it in the success and error paths).
            if (fs.existsSync(jsonOutputPath)) {
                try {
                    const raw = fs.readFileSync(jsonOutputPath, 'utf-8');
                    const data = JSON.parse(raw);
                    cleanup();

                    // Log stderr for debugging
                    if (stderrBuffer) {
                        console.log('[EVOLVE] Orchestrator stderr (truncated):',
                            stderrBuffer.slice(0, 2000));
                    }

                    if (code !== 0) {
                        console.error(`[EVOLVE] Orchestrator exited with code ${code}`);
                    }

                    res.status(200).json({
                        address,
                        chainId,
                        ...data,
                    });
                } catch (parseErr) {
                    cleanup();
                    console.error('[EVOLVE] Failed to parse orchestrator JSON output:', parseErr.message);
                    res.status(502).json({
                        error: 'Orchestrator produced invalid JSON output',
                        stderr: stderrBuffer.slice(0, 1000),
                    });
                }
            } else {
                cleanup();
                // No JSON file — the orchestrator crashed before writing
                res.status(502).json({
                    error: `Orchestrator exited with code ${code} and produced no JSON output`,
                    stderr: stderrBuffer.slice(0, 1000),
                });
            }
        });

        // Safety: kill the child if it takes too long
        setTimeout(() => {
            if (!child.killed) {
                child.kill('SIGKILL');
                cleanup();
                if (!res.headersSent) {
                    res.status(504).json({
                        error: `Orchestrator timed out after ${EVOLVE_TIMEOUT_MS / 1000}s`,
                        stderr: stderrBuffer.slice(0, 1000),
                    });
                }
            }
        }, EVOLVE_TIMEOUT_MS);

    } catch (err) {
        console.error('[EVOLVE] Unexpected error:', err.message);
        try { fs.unlinkSync(jsonOutputPath); } catch (_) {}
        res.status(500).json({ error: `Unexpected error: ${err.message}` });
    }
};
