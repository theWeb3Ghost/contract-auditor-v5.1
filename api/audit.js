
// api/audit.js
//
// POST /api/audit
// Starts an audit job and immediately returns a jobId.
//
// GET /api/audit/:jobId
// Returns the current status/result of an audit job.
//
// Jobs are persisted in MongoDB (collection: single_audit_jobs).
// A Render restart does not lose results for completed/failed jobs.

const crypto = require('crypto');
const { fetch, Agent } = require('undici');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  getDb
} = require('./db');

const ORCHESTRATOR_PATH = process.env.EVOLUTION_ORCHESTRATOR_PATH ||
  '/home/ghost/projects/learner/evolution_orchestrator.py';
const PYTHON_BIN = process.env.PYTHON_BIN || 'python3';
const EVOLVE_TIMEOUT_MS = 180000;

async function runEvolutionOrchestrator(address, chainId, label) {
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
  if (label) cmd.push('--label', label);

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

// ============================================================
// CONFIGURATION
// ============================================================

// Maximum Solidity source characters sent to the LLM
// Kept in sync with llm.js MAX_CHARS and batch.js MAX_SOURCE_CHARS.
const MAX_CHARS = 3000000;

// LLM timeout: 10 minutes
const LLM_TIMEOUT = 10 * 60 * 1000;


// ============================================================
// UNDICI AGENT
// ============================================================
//
// This Agent is specifically for long-running LLM requests.
//
// headersTimeout:
// Maximum time waiting for response headers.
//
// bodyTimeout:
// Maximum time allowed while receiving the response body.
//
// connect.timeout:
// Maximum time allowed to establish a connection.
//

const llmDispatcher = new Agent({
  headersTimeout: LLM_TIMEOUT,
  bodyTimeout: LLM_TIMEOUT,

  connect: {
    timeout: 30000
  }
});


// ============================================================
// HELPERS
// ============================================================

async function updateJob(jobId, updates) {
  const db = await getDb();

  await db
    .collection('single_audit_jobs')
    .updateOne(
      { jobId },
      { $set: updates }
    );
}


// ============================================================
// RUN AUDIT
// ============================================================

async function runAudit(jobId, data) {
  const db = await getDb();

  let job = await db
    .collection('single_audit_jobs')
    .findOne({ jobId });

  if (!job) {
    console.error(
      `[AUDIT ${jobId}] Job not found`
    );
    return;
  }


  try {

    // --------------------------------------------------------
    // UPDATE JOB STATUS
    // --------------------------------------------------------

    await updateJob(jobId, {
      status: 'running',
      startedAt: Date.now()
    });

    job.status = 'running';
    job.startedAt = Date.now();


    const {
      source,
      systemPrompt,
      model,
      contractName,
      address,
      llmUrl,
      apiKey,
      isDecompiled = false,
      additionalContext = '',
      fastParseResult = null
    } = data;


    // --------------------------------------------------------
    // VALIDATE SOURCE
    // --------------------------------------------------------

    if (!source || typeof source !== 'string') {
      throw new Error(
        'Invalid or empty Solidity source code'
      );
    }


    // --------------------------------------------------------
    // TRUNCATE LARGE CONTRACTS
    // --------------------------------------------------------

    let src = source;
    let truncated = false;

    if (src.length > MAX_CHARS) {
      src = src.slice(0, MAX_CHARS);
      truncated = true;

      console.log(
        `[AUDIT ${jobId}] Source truncated from ${source.length} to ${MAX_CHARS} characters`
      );
    }


    // --------------------------------------------------------
    // BUILD USER MESSAGE
    // --------------------------------------------------------

    const userMessage = `
You are auditing the following Solidity smart contract.

Contract Name: ${contractName || 'Unknown'}

Contract Address: ${address || 'Not provided'}

SOURCE CODE:

\`\`\`solidity
${src}
\`\`\`

${truncated
  ? '[WARNING: Source code was truncated because it exceeded the maximum allowed size.]'
  : ''
}
`;


    // --------------------------------------------------------
    // DETERMINE ENDPOINT
    // --------------------------------------------------------

    if (!llmUrl || typeof llmUrl !== 'string' || !/^https?:\/\//.test(llmUrl.trim())) {
      throw new Error('LLM API URL is required and must be supplied by the frontend');
    }

    const endpoint = llmUrl.trim();

    if (!model || typeof model !== 'string' || !model.trim()) {
      throw new Error('LLM model is required and must be supplied by the frontend');
    }


    // --------------------------------------------------------
    // LOG REQUEST DETAILS
    // --------------------------------------------------------

    console.log(
      `[AUDIT ${jobId}] ========================================`
    );

    console.log(
      `[AUDIT ${jobId}] Starting LLM audit`
    );

    console.log(
      `[AUDIT ${jobId}] Endpoint: ${endpoint}`
    );

    console.log(
      `[AUDIT ${jobId}] Model: ${model || 'gpt-4o-mini'}`
    );

    console.log(
      `[AUDIT ${jobId}] Contract: ${contractName || 'Unknown'}`
    );

    console.log(
      `[AUDIT ${jobId}] Source length: ${src.length} characters`
    );

    console.log(
      `[AUDIT ${jobId}] Node version: ${process.version}`
    );

    console.log(
      `[AUDIT ${jobId}] ========================================`
    );


    // --------------------------------------------------------
    // CREATE ABORT CONTROLLER
    // --------------------------------------------------------
    //
    // This is an additional safety timeout.
    // Undici handles connection/body/header timeouts,
    // while AbortController provides an overall request limit.
    //

    const controller = new AbortController();

    const timeoutId = setTimeout(() => {

      console.error(
        `[AUDIT ${jobId}] Overall request timeout reached after ${LLM_TIMEOUT}ms`
      );

      controller.abort();

    }, LLM_TIMEOUT);


    // --------------------------------------------------------
    // SEND REQUEST TO LLM
    // --------------------------------------------------------

    let response;

    try {

      console.log(
        `[AUDIT ${jobId}] Sending request to LLM: ${endpoint}`
      );


      response = await fetch(endpoint, {

        method: 'POST',

        dispatcher: llmDispatcher,

        signal: controller.signal,

        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`,
          'Accept': 'application/json'
        },

        body: JSON.stringify({

          model: model || 'gpt-4o-mini',

          messages: [

            {
              role: 'system',
              content: systemPrompt
            },

            {
              role: 'user',
              content: userMessage
            }

          ]

        })

      });

    } finally {

      // Always clear timeout when fetch finishes
      clearTimeout(timeoutId);

    }


    // --------------------------------------------------------
    // LOG RESPONSE STATUS
    // --------------------------------------------------------

    console.log(
      `[AUDIT ${jobId}] LLM response received`
    );

    console.log(
      `[AUDIT ${jobId}] HTTP status: ${response.status}`
    );

    console.log(
      `[AUDIT ${jobId}] HTTP status text: ${response.statusText}`
    );


    // --------------------------------------------------------
    // READ RESPONSE AS TEXT FIRST
    // --------------------------------------------------------
    //
    // We read raw text before JSON parsing so we can debug
    // non-JSON responses from proxies/providers.
    //

    const rawText = await response.text();


    console.log(
      `[AUDIT ${jobId}] Response length: ${rawText.length} characters`
    );

    console.log(
      `[AUDIT ${jobId}] Response preview: ${rawText.slice(0, 500)}`
    );


    // --------------------------------------------------------
    // HANDLE HTTP ERRORS
    // --------------------------------------------------------

    if (!response.ok) {

      throw new Error(
        `LLM API returned HTTP ${response.status}: ${rawText.slice(0, 2000)}`
      );

    }


    // --------------------------------------------------------
    // PARSE JSON
    // --------------------------------------------------------

    let json;

    try {

      json = JSON.parse(rawText);

    } catch (parseError) {

      console.error(
        `[AUDIT ${jobId}] Invalid JSON received from LLM`
      );

      throw new Error(
        `LLM returned invalid JSON: ${rawText.slice(0, 2000)}`
      );

    }


    // --------------------------------------------------------
    // HANDLE API ERROR OBJECT
    // --------------------------------------------------------

    if (json.error) {

      console.error(
        `[AUDIT ${jobId}] LLM API error:`,
        json.error
      );

      throw new Error(
        json.error.message ||
        JSON.stringify(json.error)
      );

    }


    // --------------------------------------------------------
    // EXTRACT LLM RESPONSE
    // --------------------------------------------------------

    const result =
      json?.choices?.[0]?.message?.content ||
      json?.choices?.[0]?.text ||
      json?.output_text ||
      '';


    // --------------------------------------------------------
    // VALIDATE RESULT
    // --------------------------------------------------------

    if (!result || !String(result).trim()) {

      console.error(
        `[AUDIT ${jobId}] Empty LLM response`
      );

      console.error(
        `[AUDIT ${jobId}] Full response structure:`,
        JSON.stringify(json).slice(0, 5000)
      );

      throw new Error(
        'LLM returned an empty audit response'
      );

    }


    // --------------------------------------------------------
    // SAVE SUCCESSFUL RESULT
    // --------------------------------------------------------

    const finishedAt = Date.now();

    await updateJob(jobId, {
      status: 'completed',
      result: String(result).trim(),
      error: null,
      truncated,
      isDecompiled,
      fastParseResult,
      finishedAt
    });

    job.status = 'completed';
    job.result = String(result).trim();
    job.error = null;
    job.truncated = truncated;
    job.isDecompiled = isDecompiled;
    job.fastParseResult = fastParseResult;
    job.finishedAt = finishedAt;

    const duration =
      job.finishedAt - job.startedAt;


    console.log(
      `[AUDIT ${jobId}] ========================================`
    );

    console.log(
      `[AUDIT ${jobId}] AUDIT COMPLETED SUCCESSFULLY`
    );

    console.log(
      `[AUDIT ${jobId}] Result length: ${job.result.length} characters`
    );

    console.log(
      `[AUDIT ${jobId}] Duration: ${duration}ms (${(duration / 1000).toFixed(2)} seconds)`
    );

    console.log(
      `[AUDIT ${jobId}] ========================================`
    );


  } catch (err) {

    // --------------------------------------------------------
    // MARK JOB AS FAILED
    // --------------------------------------------------------

    const finishedAt = Date.now();

    let jobError;

    if (
      err?.name === 'AbortError' ||
      err?.name === 'TimeoutError'
    ) {

      jobError =
        `LLM request timed out after ${LLM_TIMEOUT / 60000} minutes.`;

    } else {

      jobError = String(
        err?.cause?.message ||
        err?.message ||
        err ||
        'Unknown audit error'
      );

    }

    await updateJob(jobId, {
      status: 'failed',
      error: jobError,
      finishedAt
    });

    job.status = 'failed';
    job.finishedAt = finishedAt;
    job.error = jobError;


    // --------------------------------------------------------
    // DETAILED ERROR LOGGING
    // --------------------------------------------------------

    console.error(
      `[AUDIT ${jobId}] ========================================`
    );

    console.error(
      `[AUDIT ${jobId}] AUDIT FAILED`
    );

    console.error(
      `[AUDIT ${jobId}] ERROR DETAILS:`,
      {
        name: err?.name,

        message: err?.message,

        code: err?.code,

        cause: err?.cause
          ? {
              name: err.cause.name,
              message: err.cause.message,
              code: err.cause.code,
              errno: err.cause.errno,
              syscall: err.cause.syscall,
              hostname: err.cause.hostname
            }
          : null,

        stack: err?.stack
      }
    );

    console.error(
      `[AUDIT ${jobId}] ========================================`
    );

  }

}


// ============================================================
// EXPRESS API HANDLER
// ============================================================

module.exports = async function auditHandler(req, res) {


  // ----------------------------------------------------------
  // CORS HEADERS
  // ----------------------------------------------------------

  res.setHeader(
    'Access-Control-Allow-Origin',
    '*'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, x-openai-key'
  );


  // ----------------------------------------------------------
  // HANDLE OPTIONS
  // ----------------------------------------------------------

  if (req.method === 'OPTIONS') {

    return res.status(204).end();

  }


  // ==========================================================
  // POST /api/audit
  // START A NEW AUDIT
  // ==========================================================

  if (req.method === 'POST') {

    const {
      source,
      systemPrompt,
      model,
      contractName,
      address,
      llmUrl,
      chainId,
      label
    } = req.body || {};


    // --------------------------------------------------------
    // VALIDATE SOURCE OR FALLBACK TO ORCHESTRATOR
    // --------------------------------------------------------
    //
    // If no source is provided, attempt to fetch source (or decompiled
    // pseudocode via Porcelain-X) from the evolution_orchestrator.
    // This requires a valid chainId + address.

    let effectiveSource = source;
    let isDecompiled = false;
    let fastParseResult = null;

    if (!source) {
      if (!address || !chainId) {
        return res.status(400).json({
          error: 'Either source or (address + chainId) is required'
        });
      }

      try {
        console.log(`[AUDIT] No source provided — delegating to evolution_orchestrator for ${address} (chain ${chainId})`);
        const evolveResult = await runEvolutionOrchestrator(address, chainId, label);

        if (evolveResult.verified && evolveResult.source) {
          effectiveSource = evolveResult.source;
          console.log(`[AUDIT] Orchestrator returned verified source (${effectiveSource.length} chars)`);
        } else if (evolveResult.decompiledSource) {
          effectiveSource = evolveResult.decompiledSource;
          isDecompiled = true;
          console.log(`[AUDIT] Orchestrator returned decompiled pseudocode (${effectiveSource.length} chars)`);
        } else if (evolveResult.source) {
          effectiveSource = evolveResult.source;
          console.log(`[AUDIT] Orchestrator returned source (${effectiveSource.length} chars)`);
        } else {
          return res.status(502).json({
            error: 'Orchestrator could not retrieve or decompile source for this contract',
            evolveResult
          });
        }

        // Capture fast-parse findings for additionalContext
        fastParseResult = {
          score: evolveResult.score,
          status: evolveResult.status,
          patterns_matched: evolveResult.patterns_matched || [],
          porcelainx_findings: evolveResult.porcelainx_findings || [],
          actual_label: evolveResult.actual_label,
          predicted: evolveResult.predicted,
          pattern: evolveResult.pattern,
          decompiled: evolveResult.decompiled || false,
        };
      } catch (evolveErr) {
        console.error(`[AUDIT] Orchestrator failed: ${evolveErr.message}`);
        return res.status(502).json({
          error: `Could not fetch source for this contract: ${evolveErr.message}`
        });
      }
    } else {
      // Source was provided directly; validate type
      if (typeof source !== 'string') {
        return res.status(400).json({
          error: 'source must be a string'
        });
      }
      effectiveSource = source;

      // Even with verified source, run orchestrator for pattern analysis
      // if address + chainId are available
      if (address && chainId) {
        try {
          const evolveResult = await runEvolutionOrchestrator(address, chainId, label);
          fastParseResult = {
            score: evolveResult.score,
            status: evolveResult.status,
            patterns_matched: evolveResult.patterns_matched || [],
            porcelainx_findings: evolveResult.porcelainx_findings || [],
            actual_label: evolveResult.actual_label,
            predicted: evolveResult.predicted,
          };
        } catch (evolveErr) {
          console.error(`[AUDIT] Orchestrator analysis for verified source failed: ${evolveErr.message}`);
        }
      }
    }


    // --------------------------------------------------------
    // BUILD ADDITIONAL CONTEXT (fast-parse findings)
    // --------------------------------------------------------

    let additionalContext = '';
    if (fastParseResult) {
      const fastParseText = JSON.stringify(fastParseResult, null, 2);
      additionalContext = `=== FAST-PARSE ANALYSIS (Pattern-Based Pre-Audit) ===
Score: ${fastParseResult.score || 0}/100
Status: ${fastParseResult.status || 'unknown'}
Patterns Matched: ${(fastParseResult.patterns_matched || []).join(', ') || 'none'}
Porcelain-X Findings: ${JSON.stringify(fastParseResult.porcelainx_findings || [], null, 2)}
Predicted Label: ${fastParseResult.predicted || 'unknown'}
Pattern: ${fastParseResult.pattern || 'none'}

TRUST BUT VERIFY: This analysis was produced by an automated pattern-matching engine, not human review. These findings are hypotheses to guide your attention, not conclusions. Some may direct attention to non-exploitable paths, false-positive branches, or safe library code. Verify each independently before citing in your verdict.

Raw JSON for machine parsing:
${fastParseText}
=== END FAST-PARSE ===`;
    }

    // If decompiled, prepend a disclaimer
    if (isDecompiled && !additionalContext) {
      additionalContext = `=== DECOMPILED CODE NOTICE ===
This contract's source was NOT verified on Etherscan. The code below is decompiled pseudocode
generated by Peorcelain-X from on-chain bytecode. Semantic analysis may be incomplete; variable
names and control flow structure may be approximate. Treat with appropriate caution.
=== END DECOMPILED CODE NOTICE ===`;
    } else if (isDecompiled) {
      additionalContext = `=== DECOMPILED CODE NOTICE ===
This contract's source was NOT verified on Etherscan. The code below is decompiled pseudocode
generated by Peorcelain-X from on-chain bytecode. Semantic analysis may be incomplete; variable
names and control flow structure may be approximate. Treat with appropriate caution.
=== END DECOMPILED CODE NOTICE ===\n\n${additionalContext}`;
    }


    // --------------------------------------------------------
    // VALIDATE SYSTEM PROMPT
    // --------------------------------------------------------

    if (!systemPrompt) {

      return res.status(400).json({
        error: 'systemPrompt is required'
      });

    }


    // --------------------------------------------------------
    // GET API KEY
    // --------------------------------------------------------

    const apiKey = req.headers['x-openai-key'];


    if (!apiKey) {

      return res.status(500).json({
        error:
          'No API key provided. Set x-openai-key or OPENAI_API_KEY.'
      });

    }


    // --------------------------------------------------------
    // CREATE JOB
    // --------------------------------------------------------

    const jobId = crypto.randomUUID();

    const createdAt = Date.now();

    const db = await getDb();

    await db
      .collection('single_audit_jobs')
      .insertOne({

        jobId,

        status: 'queued',

        result: null,

        error: null,

        truncated: false,

        isDecompiled,

        fastParseResult,

      createdAt,

      startedAt: null,

      startedAt: null,

      finishedAt: null

    });


    console.log(
      `[AUDIT ${jobId}] New audit job created`
    );


    // --------------------------------------------------------
    // RETURN IMMEDIATELY
    // --------------------------------------------------------
    //
    // Important:
    // The frontend receives the jobId immediately.
    // The long LLM audit continues in the background.
    //

    res.status(202).json({

      jobId,

      status: 'queued'

    });


    // --------------------------------------------------------
    // RUN AUDIT IN BACKGROUND
    // --------------------------------------------------------

    runAudit(jobId, {

      source: effectiveSource,

      systemPrompt,

      model,

      contractName,

      address,

      llmUrl,

      apiKey,

      isDecompiled,

      additionalContext,

      fastParseResult

    }).catch((err) => {

      console.error(
        `[AUDIT ${jobId}] Unexpected background error:`,
        err
      );

    });


    return;

  }


  // ==========================================================
  // GET /api/audit/:jobId
  // CHECK AUDIT STATUS
  // ==========================================================

  if (req.method === 'GET') {

    const jobId = req.params.jobId;


    if (!jobId) {

      return res.status(400).json({
        error: 'jobId is required'
      });

    }


    const db = await getDb();

    const job = await db
      .collection('single_audit_jobs')
      .findOne(
        { jobId },
        {
          projection: {
            _id: 0,
            jobId: 1,
            status: 1,
            result: 1,
            error: 1,
            truncated: 1,
            isDecompiled: 1,
            fastParseResult: 1,
            createdAt: 1,
            startedAt: 1,
            finishedAt: 1
          }
        }
      );


    if (!job) {

      return res.status(404).json({
        error: 'Audit job not found'
      });

    }


    return res.status(200).json({

      jobId,

      status: job.status,

      result:
        job.status === 'completed'
          ? job.result
          : null,

      error:
        job.status === 'failed'
          ? job.error
          : null,

      truncated: job.truncated,

      isDecompiled: job.isDecompiled || false,

      fastParseResult: job.fastParseResult || null,

      createdAt: job.createdAt,

      startedAt: job.startedAt,

      finishedAt: job.finishedAt

    });

  }


  // ==========================================================
  // METHOD NOT ALLOWED
  // ==========================================================

  return res.status(405).json({
    error: 'Method not allowed. Use GET or POST.'
  });

};
