/**
 * API Server for Solidity Security Learning Framework.
 *
 * Endpoints:
 * - POST /api/analyze  — Analyze a Solidity contract
 * - POST /api/train    — Trigger training run
 * - GET  /api/metrics  — Training metrics and calibration
 * - GET  /api/bugs     — Bug database query
 * - GET  /api/status   — Service status
 * - POST /api/feedback — Submit feedback for reward mechanism
 *
 * The server bridges TypeScript feature extraction with the Python model
 * via subprocess calls to model/train.py.
 */

import express from 'express';
import { Logger } from '../lib/logger.js';
import { FeatureExtractor, FeatureVector } from '../analyzer/features/extractor.js';
import { bugDatabase, BugEntry } from '../analyzer/models/bug_database.js';
import { ModelTrainer } from '../training/trainer.js';
import { DEFAULT_CONFIG, ModelPrediction } from '../analyzer/models/architecture.js';
import { spawn } from 'child_process';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { z } from 'zod';

const log = new Logger('api-server');

const app = express();
app.use(express.json({ limit: '10mb' }));

// ===========================================================================
// Request Schemas
// ===========================================================================

const AnalyzeRequest = z.object({
  sourceCode: z.string().min(10, 'Source code too short'),
  contractName: z.string().optional(),
  fileName: z.string().optional(),
  runPorosityX: z.boolean().default(false)
});

const TrainRequest = z.object({
  epochs: z.number().min(1).max(200).default(50),
  dataDir: z.string().default('data'),
  resumeFrom: z.string().optional(),
  gpu: z.boolean().default(false)
});

const FeedbackRequest = z.object({
  contractId: z.string(),
  predicted: z.array(z.string()),
  actual: z.array(z.string()),
  isClean: z.boolean(),
  isNovel: z.boolean().optional(),
  notes: z.string().optional()
});

// ===========================================================================
// Routes
// ===========================================================================

// Status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    status: 'running',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    bugDatabaseSize: bugDatabase.size,
    featuresAvailable: true,
    modelAvailable: false
  });
});

// Analyze a Solidity contract
app.post('/api/analyze', async (req, res) => {
  const parseResult = AnalyzeRequest.safeParse(req.body);

  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Invalid request',
      details: parseResult.error.errors
    });
  }

  const { sourceCode, contractName, fileName, runPorosityX: shouldRunPorosityX } = parseResult.data;

  try {
    log.info(`Analyzing contract: ${contractName || 'unnamed'}`);

    // Step 1: Extract features
    const featureVector = FeatureExtractor.extract(sourceCode, {
      contractName: contractName || 'unnamed',
      contractAddress: null,
      sourceFile: fileName || 'inline'
    });

    // Step 2: Run Porosity-X if requested
    let porosityXFeatures: number[] = [];
    let porosityXOutput: any = null;

    if (shouldRunPorosityX) {
      try {
        porosityXOutput = await runPorosityX(sourceCode);
        porosityXFeatures = extractPorosityFeatures(porosityXOutput);
      } catch (error: any) {
        log.warn('Porosity-X failed:', error.message);
      }
    }

    // Step 3: Run model prediction
    const prediction = await runModelPrediction(featureVector, porosityXFeatures);

    // Step 4: Match against known bugs
    const bugMatches = findSimilarBugs(featureVector, prediction);

    res.json({
      success: true,
      contractName,
      fileName,
      features: {
        riskScore: featureVector.vulnerabilityPatterns.overallRisk,
        numFeatures: featureVector.numericVector.length,
        featureNames: FeatureExtractor.getFeatureNames()
      },
      prediction: {
        riskScore: prediction.riskScore,
        confidence: prediction.confidence,
        isNovel: prediction.isNovel,
        noveltyScore: prediction.noveltyScore,
        vulnerabilityScores: prediction.vulnerabilityScores
      },
      matchedBugs: bugMatches.map(b => ({
        id: b.id,
        title: b.title,
        description: b.description,
        severity: b.severity,
        cwe: b.cwe,
        pattern: b.pattern,
        impact: b.impact
      })),
      porosityX: porosityXOutput ? {
        available: true,
        findings: porosityXOutput.findings || [],
        taintPaths: porosityXOutput.taintPaths?.length || 0
      } : {
        available: false
      }
    });
  } catch (error: any) {
    log.error('Analysis failed:', error);
    res.status(500).json({
      error: 'Analysis failed',
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Trigger training
app.post('/api/train', async (req, res) => {
  const parseResult = TrainRequest.safeParse(req.body);

  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Invalid request',
      details: parseResult.error.errors
    });
  }

  const { epochs, dataDir, resumeFrom, gpu } = parseResult.data;

  res.status(202).json({
    status: 'training_started',
    epochs,
    dataDir,
    gpu,
    message: 'Training started in background. Check /api/metrics for updates.'
  });

  // Start training in background
  trainBackground(epochs, dataDir, resumeFrom, gpu).catch(error => {
    log.error('Background training failed:', error);
  });
});

// Get training metrics
app.get('/api/metrics', async (req, res) => {
  try {
    const checkpointDir = 'results/checkpoints';
    const latestPath = join(checkpointDir, 'latest_metrics.json');

    let metrics: any = null;
    try {
      metrics = JSON.parse(await readFile(latestPath, 'utf-8'));
    } catch {
      metrics = null;
    }

    res.json({
      timestamp: new Date().toISOString(),
      checkpoints: await listCheckpoints(),
      latest: metrics
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Query bug database
app.get('/api/bugs', (req, res) => {
  const { pattern, severity, impact, keyword } = req.query;

  let results: BugEntry[] = [];

  if (keyword) {
    results = bugDatabase.search(keyword as string);
  } else if (pattern) {
    results = bugDatabase.searchByPattern(pattern as any);
  } else if (impact) {
    results = bugDatabase.getByImpact(impact as any);
  } else {
    results = Array.from(bugDatabase.bugs.values());
  }

  if (severity) {
    results = results.filter(r => r.severity === severity);
  }

  res.json({
    count: results.length,
    bugs: results.map(b => ({
      id: b.id,
      title: b.title,
      pattern: b.pattern,
      severity: b.severity,
      cwe: b.cwe,
      description: b.description,
      difficulty: b.difficulty,
      impact: b.impact
    }))
  });
});

// Submit feedback for reward mechanism
app.post('/api/feedback', async (req, res) => {
  const parseResult = FeedbackRequest.safeParse(req.body);

  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Invalid request',
      details: parseResult.error.errors
    });
  }

  const feedback = parseResult.data;
  log.info(`Feedback received for ${feedback.contractId}`);

  // Log feedback for training
  const feedbackPath = join('data', 'feedback', `${feedback.contractId}.json`);
  await mkdir(join('data', 'feedback'), { recursive: true });
  await writeFile(feedbackPath, JSON.stringify(feedback, null, 2));

  res.json({
    success: true,
    message: 'Feedback recorded',
    feedbackId: feedback.contractId
  });
});

// ===========================================================================
// Helper functions
// ===========================================================================

async function runPorosityX(sourceCode: string): Promise<any> {
  // In production, this would run the Porosity-X Rust binary
  // The Rust binary outputs JSON that we parse
  log.debug('Running Porosity-X static analysis...');

  try {
    const rustBinary = process.env.POROSITY_X_PATH || 'target/release/porosity-x';

    const proc = spawn(rustBinary, ['--stdin', '--format', 'json'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    proc.stdin.write(sourceCode);
    proc.stdin.end();

    let output = '';
    let error = '';

    proc.stdout.on('data', (data) => { output += data.toString(); });
    proc.stderr.on('data', (data) => { error += data.toString(); });

    const exitCode = await new Promise<number>((resolve, reject) => {
      proc.on('error', reject);
      proc.on('close', resolve);
    });

    if (exitCode !== 0) {
      throw new Error(`Porosity-X exited with code ${exitCode}: ${error}`);
    }

    return JSON.parse(output);
  } catch (error: any) {
    log.warn('Porosity-X not available:', error.message);
    // Return empty result
    return {
      findings: [],
      taintPaths: [],
      invariants: []
    };
  }
}

function extractPorosityFeatures(porosityOutput: any): number[] {
  // Convert Porosity-X output to fixed-size feature vector
  const features: number[] = [];

  // Finding counts by type
  const findingTypes = ['reentrancy', 'arithmetic', 'access', 'taint', 'storage'];
  for (const type of findingTypes) {
    const count = (porosityOutput.findings || [])
      .filter((f: any) => f.type?.toLowerCase().includes(type))
      .length;
    features.push(count);
  }

  // Taint path metrics
  features.push((porosityOutput.taintPaths || []).length);
  features.push((porosityOutput.taintPaths || [])
    .filter((p: any) => p.maxPriority >= 4)
    .length);

  // Invariant candidates
  features.push((porosityOutput.invariants || []).length);

  // Pad to expected size
  const expectedSize = DEFAULT_CONFIG.porosityXFeatureDim;
  while (features.length < expectedSize) {
    features.push(0);
  }

  return features.slice(0, expectedSize);
}

async function runModelPrediction(features: FeatureVector, porosityXFeatures: number[]): Promise<ModelPrediction> {
  // In production, this would call the Python model
  // For now, return a simulated prediction based on feature values

  const riskScore = features.vulnerabilityPatterns.overallRisk;
  const confidence = Math.min(0.9, 0.5 + riskScore * 0.4);

  // Map feature scores to vulnerability categories
  const vulnScores: Record<string, number> = {};

  if (features.taintAnalysis.hasReentrantPath || features.taintAnalysis.hasTaintedExternalCall) {
    vulnScores['reentrancy'] = features.vulnerabilityPatterns.reentrancyRisk;
  }

  if (features.vulnerabilityPatterns.arithmeticRisk > 0.5) {
    vulnScores['integer_overflow'] = features.vulnerabilityPatterns.arithmeticRisk;
  }

  if (features.vulnerabilityPatterns.accessControlRisk > 0.5) {
    vulnScores['access_control'] = features.vulnerabilityPatterns.accessControlRisk;
  }

  vulnScores['risk_score'] = riskScore;

  return {
    vulnerabilityScores: vulnScores,
    riskScore,
    confidence,
    isNovel: features.controlFlow.cyclomaticComplexity > 10 && features.taintAnalysis.maxTaintDepth > 3,
    noveltyScore: Math.min(1, features.controlFlow.cyclomaticComplexity / 20),
    attentionWeights: {
      astAttention: [],
      cfgAttention: [],
      crossAttention: []
    },
    topContributingTokens: [],
    topContributingNodes: []
  };
}

function findSimilarBugs(features: FeatureVector, prediction: ModelPrediction): BugEntry[] {
  const matches: BugEntry[] = [];

  // Match against bug database based on feature patterns
  const reentrancyScore = features.vulnerabilityPatterns.reentrancyRisk;
  if (reentrancyScore > 0.5) {
    const reentrancyBugs = bugDatabase.searchByPattern('reentrancy');
    matches.push(...reentrancyBugs.slice(0, 3));
  }

  const overflowScore = features.vulnerabilityPatterns.arithmeticRisk;
  if (overflowScore > 0.5) {
    const overflowBugs = bugDatabase.searchByPattern('integer_overflow');
    matches.push(...overflowBugs.slice(0, 2));
  }

  const accessScore = features.vulnerabilityPatterns.accessControlRisk;
  if (accessScore > 0.3) {
    const accessBugs = bugDatabase.searchByPattern('access_control');
    matches.push(...accessBugs.slice(0, 2));
  }

  // Deduplicate
  const seen = new Set<string>();
  return matches.filter(b => {
    if (seen.has(b.id)) return false;
    seen.add(b.id);
    return true;
  });
}

async function trainBackground(epochs: number, dataDir: string, resumeFrom?: string, gpu: boolean = false): Promise<void> {
  log.info(`Starting background training: ${epochs} epochs, dataDir=${dataDir}`);

  try {
    const trainer = new ModelTrainer(DEFAULT_CONFIG);

    if (resumeFrom) {
      await trainer.resumeFromCheckpoint(resumeFrom);
    }

    const report = await trainer.train(dataDir, epochs);

    log.info('Training complete:', report);

    // Save final metrics
    const metricsPath = join('results', 'checkpoints', 'latest_metrics.json');
    await mkdir(dirname(metricsPath), { recursive: true });
    await writeFile(metricsPath, JSON.stringify(report, null, 2));

  } catch (error: any) {
    log.error('Training failed:', error);
  }
}

async function listCheckpoints(): Promise<Array<{ path: string; epoch: number; auc: number; timestamp: string }>> {
  const checkpoints: Array<{ path: string; epoch: number; auc: number; timestamp: string }> = [];
  const checkpointDir = 'results/checkpoints';

  try {
    const { readdir } = require('fs/promises');
    const files = await readdir(checkpointDir, { withFileTypes: true });

    for (const file of files) {
      if (file.isFile() && file.name.startsWith('checkpoint_') && file.name.endsWith('.json')) {
        try {
          const data = JSON.parse(await readFile(join(checkpointDir, file.name), 'utf-8'));
          checkpoints.push({
            path: join(checkpointDir, file.name),
            epoch: data.epoch || 0,
            auc: data.metrics?.auc || 0,
            timestamp: new Date(data.timestamp || Date.now()).toISOString()
          });
        } catch {
          // Skip corrupted checkpoints
        }
      }
    }

    checkpoints.sort((a, b) => b.epoch - a.epoch);
  } catch {
    // Directory doesn't exist yet
  }

  return checkpoints;
}

function dirname(path: string): string {
  return path.split('/').slice(0, -1).join('/');
}

// ===========================================================================
// Start Server
// ===========================================================================

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, () => {
  log.info(`API server running on http://${HOST}:${PORT}`);
  log.info('Endpoints:');
  log.info(`  POST /api/analyze   — Analyze Solidity contract`);
  log.info(`  POST /api/train     — Start training`);
  log.info(`  GET  /api/metrics  — Training metrics`);
  log.info(`  GET  /api/bugs      — Bug database query`);
  log.info(`  POST /api/feedback  — Submit feedback`);
});

export { app };
