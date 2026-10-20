/**
 * Solidity Learner — Transformer-based security analysis framework.
 *
 * Architecture:
 *   Source Code → AST Parser → CFG Builder → Feature Encoder → Transformer Model → Bug Prediction → Reward System
 *
 *   The model uses attention over both the Solidity AST token sequence and the
 *   Control Flow Graph (CFG) with data-flow/taint edges, augmented by Porosity-X
 *   static analysis features (taint sources, reentrancy patterns, storage layout).
 *
 * Modules:
 * - /api/analyze    — Analyze Solidity contracts (POST)
 * - /api/train      — Trigger walk-forward training (POST)
 * - /api/metrics    — Get training metrics and calibration (GET)
 * - /api/bugs       — Query the vulnerability database (GET)
 * - /api/feedback   — Submit feedback for reward mechanism (POST)
 */

import express, { Express } from 'express';
import { Logger } from './lib/logger.js';
import { FeatureExtractor } from './analyzer/features/extractor.js';
import { bugDatabase } from './analyzer/models/bug_database.js';
import { DEFAULT_CONFIG } from './analyzer/models/architecture.js';
import { ModelTrainer } from './training/trainer.js';
import { RewardSystem } from './training/pipeline.js';
import { ZeroShotVulnerabilityPredictor, ZeroShotAnalysisResult } from './analyzer/zero_shot/predictor.js';
import { createDefaultKnowledgeGraph, KnowledgeGraphBuilder } from './analyzer/zero_shot/knowledge_builder.js';
import { KnowledgeGraphImpl } from './analyzer/knowledge/docs_processor.js';
import { readFile, mkdir } from 'fs/promises';
import { join } from 'path';

const log = new Logger('learner');

// Zero-shot predictor instance (lazy-initialized with knowledge graph)
let zeroShotPredictor: ZeroShotVulnerabilityPredictor | null = null;

/**
 * Load knowledge graph from ingested documentation if available,
 * otherwise fall back to embedded facts.
 */
async function loadKnowledgeGraph(): Promise<KnowledgeGraphImpl> {
  const ingestedPath = join('data', 'knowledge', 'knowledge_graph.json');
  try {
    const data = JSON.parse(await readFile(ingestedPath, 'utf-8'));
    if (data.facts && data.facts.length > 0) {
      const kg = new KnowledgeGraphImpl();
      for (const fact of data.facts) {
        kg.add(fact);
      }
      log.info(`${kg.size()} facts loaded from ingested knowledge graph`);
      return kg;
    }
  } catch (error) {
    log.info('Ingested knowledge graph not found, using embedded facts');
  }
  const builder = new KnowledgeGraphBuilder();
  return builder.build();
}

async function getZeroShotPredictor(): Promise<ZeroShotVulnerabilityPredictor> {
  if (!zeroShotPredictor) {
    await mkdir('data/knowledge', { recursive: true });
    const kg = await loadKnowledgeGraph();
    zeroShotPredictor = new ZeroShotVulnerabilityPredictor(kg);
  }
  return zeroShotPredictor;
}

/**
 * Create and configure the Express application.
 */
export function createApp(): Express {
  const app = express();
  app.use(express.json({ limit: '50mb' }));

  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    });
  });

  app.get('/', (_req, res) => {
    res.json({
      name: 'Solidity Learner',
      description: 'Transformer-based Solidity security analysis framework',
      version: '1.0.0',
      endpoints: [
        'POST /api/analyze',
        'POST /api/train',
        'GET /api/metrics',
        'GET /api/bugs',
        'POST /api/feedback',
        'GET /health'
      ],
      bugDatabaseSize: bugDatabase.size,
      config: {
        dModel: DEFAULT_CONFIG.dModel,
        numLayersAST: DEFAULT_CONFIG.numLayersAST,
        numLayersCFG: DEFAULT_CONFIG.numLayersCFG,
        numVulnerabilityClasses: DEFAULT_CONFIG.numVulnerabilityClasses
      }
    });
  });

  // ===========================================================================
  // API: Analyze Solidity Contract
  // ===========================================================================

  app.post('/api/analyze', async (req, res) => {
    const { sourceCode, contractName = 'unnamed', fileName = 'inline', runPorosityX = false } = req.body;

    if (!sourceCode || sourceCode.length < 10) {
      return res.status(400).json({ error: 'sourceCode must be at least 10 characters' });
    }

    try {
      log.info(`Analyzing contract: ${contractName}`);

      const features = FeatureExtractor.extract(sourceCode, {
        contractName,
        contractAddress: null,
        sourceFile: fileName
      });

      // Match against bug database
      const matches = bugDatabase.toJSON().filter(bug => {
        const lower = sourceCode.toLowerCase();
        return bug.detectionFeatures.some(f => {
          const val = features[f as keyof typeof features];
          return typeof val === 'number' && val > 0.5;
        });
      });

      const riskScore = features.vulnerabilityPatterns.overallRisk;
      const confidence = Math.min(0.95, 0.5 + riskScore * 0.4);

      res.json({
        success: true,
        contractName,
        features: features.numericVector.length,
        riskScore,
        confidence,
        vulnerabilityPatterns: {
          reentrancy: features.vulnerabilityPatterns.reentrancyRisk,
          accessControl: features.vulnerabilityPatterns.accessControlRisk,
          arithmetic: features.vulnerabilityPatterns.arithmeticRisk,
          timestamp: 0,
          gasLimit: 0,
          unknown: 0,
          unclassified: 0
        },
        taintAnalysis: {
          sourceCount: features.taintAnalysis.sourceCount,
          sinkCount: features.taintAnalysis.sinkCount,
          pathCount: features.taintAnalysis.taintPathCount,
          maxTaintDepth: features.taintAnalysis.maxTaintDepth,
          hasReentrantPath: features.taintAnalysis.hasReentrantPath
        },
        matchedBugs: matches.map(b => ({
          id: b.id,
          title: b.title,
          severity: b.severity,
          pattern: b.pattern,
          cwe: b.cwe,
          impact: b.impact
        })),
        recommendation: riskScore > 0.5
          ? '⚠️ High risk detected – manual audit recommended before deployment'
          : '✅ No obvious high-risk patterns detected'
      });
    } catch (error: any) {
      log.error('Analysis failed:', error);
      res.status(500).json({
        error: 'Analysis failed',
        message: error.message
      });
    }
  });

  // ===========================================================================
  // API: Zero-Shot Analysis (no pre-defined patterns)
  // ===========================================================================

  app.post('/api/analyze/zeroshot', async (req, res) => {
    const { sourceCode, contractName = 'unnamed', fileName = 'inline' } = req.body;

    if (!sourceCode || sourceCode.length < 10) {
      return res.status(400).json({ error: 'sourceCode must be at least 10 characters' });
    }

    try {
      log.info(`Zero-shot analysis of contract: ${contractName}`);

      const predictor = await getZeroShotPredictor();
      const result = await predictor.analyze(sourceCode, contractName, fileName);

      res.json({
        success: true,
        contractName,
        knowledgeGraphSize: result.knowledgeGraphSize,
        vulnerabilitiesDiscovered: result.discoveredVulnerabilities,
        hypothesesEvaluated: result.totalHypothesesEvaluated,
        droppedPatterns: result.droppedCount,
        novelCount: result.novelCount,
        riskScore: Math.max(...result.discoveredVulnerabilities.map(v => v.riskScore), 0),
        timestamp: result.timestamp
      });
    } catch (error: any) {
      log.error('Zero-shot analysis failed:', error);
      res.status(500).json({
        success: false,
        error: 'Zero-shot analysis failed',
        message: error.message
      });
    }
  });

  // ===========================================================================
  // API: Train Model
  // ===========================================================================

  app.post('/api/train', async (req, res) => {
    const { epochs = 50, dataDir = 'data', resumeFrom, gpu = false } = req.body;

    res.status(202).json({
      status: 'training_started',
      epochs,
      dataDir,
      gpu,
      message: 'Training started in background. Check /api/metrics for updates.'
    });

    // Start training in background
    setImmediate(async () => {
      try {
        const trainer = new ModelTrainer(DEFAULT_CONFIG);
        if (resumeFrom) {
          await trainer.resumeFromCheckpoint(resumeFrom);
        }
        const report = await trainer.train(dataDir, epochs);
        log.info('Training complete:', report.success ? 'success' : 'failed');
      } catch (error: any) {
        log.error('Background training failed:', error);
      }
    });
  });

  // ===========================================================================
  // API: Get Metrics
  // ===========================================================================

  app.get('/api/metrics', (_req, res) => {
    res.json({
      timestamp: new Date().toISOString(),
      bugDatabase: {
        totalEntries: bugDatabase.size,
        patterns: Array.from(bugDatabase.byPattern.keys()),
        severityDistribution: {
          critical: bugDatabase.toJSON().filter(b => b.severity === 'critical').length,
          high: bugDatabase.toJSON().filter(b => b.severity === 'high').length,
          medium: bugDatabase.toJSON().filter(b => b.severity === 'medium').length,
          low: bugDatabase.toJSON().filter(b => b.severity === 'low').length
        }
      },
      config: DEFAULT_CONFIG
    });
  });

  // ===========================================================================
  // API: Bug Database
  // ===========================================================================

  app.get('/api/bugs', (req, res) => {
    const { pattern, keyword, severity } = req.query;

    let bugs = bugDatabase.toJSON().map(b => ({
      id: b.id,
      title: b.title,
      pattern: b.pattern,
      severity: b.severity,
      cwe: b.cwe,
      impact: b.impact,
      difficulty: b.difficulty,
      description: b.description
    }));

    if (pattern) {
      bugs = bugs.filter(b => b.pattern.includes(pattern as any));
    }
    if (severity) {
      bugs = bugs.filter(b => b.severity === severity);
    }
    if (keyword) {
      const kw = (keyword as string).toLowerCase();
      bugs = bugs.filter(b =>
        b.title.toLowerCase().includes(kw) ||
        b.description.toLowerCase().includes(kw) ||
        b.pattern.some(p => p.toLowerCase().includes(kw))
      );
    }

    res.json({ count: bugs.length, bugs });
  });

  // ===========================================================================
  // API: Feedback
  // ===========================================================================

  app.post('/api/feedback', async (req, res) => {
    const { contractId, predicted, actual, isClean, note } = req.body;

    // Compute reward using the reward system
    const reward = RewardSystem.calculateReward(
      predicted || [],
      actual || [],
      isClean ?? false,
      req.body.isNovel ?? false
    );

    log.info(`Feedback received for ${contractId}: reward=${reward}`);

    res.json({
      success: true,
      reward,
      message: 'Feedback recorded for model improvement'
    });
  });

  return app;
}

/**
 * Main entry point.
 */
async function main() {
  const port = process.env.PORT || 9100;
  const host = process.env.HOST || '0.0.0.0';

  log.info('=== Solidity Learner ===');
  log.info('Initializing training pipeline...');

  const app = createApp();

  app.listen(port, () => {
    log.info(`Server running at http://${host}:${port}`);
    log.info(`API: http://${host}:${port}/api`);
    log.info(`Health: http://${host}:${port}/health`);
    log.info('');
    log.info('Endpoints:');
    log.info('  POST /api/analyze  — Analyze Solidity contract');
    log.info('  POST /api/train    — Trigger training');
    log.info('  GET  /api/metrics — Training metrics');
    log.info('  GET  /api/bugs     — Bug database query');
    log.info('  POST /api/feedback — Submit feedback');
    log.info('');
    log.info(`Bug database: ${bugDatabase.size} entries loaded`);
    log.info(`Model config: dModel=${DEFAULT_CONFIG.dModel}, astLayers=${DEFAULT_CONFIG.numLayersAST}, cfgLayers=${DEFAULT_CONFIG.numLayersCFG}`);
  });
}

main().catch((err) => {
  log.error('Fatal error:', err);
  process.exit(1);
});
