/**
 * Zero-Shot Vulnerability Predictor.
 *
 * This module uses the knowledge graph + chain-of-thought reasoner to
 * discover vulnerabilities WITHOUT any pre-defined pattern database.
 *
 * The flow:
 * 1. Ingest Solidity/EVM/Blockchain documentation → KnowledgeGraph
 * 2. Build attacker hypotheses from documented semantics
 * 3. Parse source code → AST → CFG → TaintGraph
 * 4. Extract features from AST/CFG/Taint
 * 5. Run SemanticReasoner: for each hypothesis, check if preconditions
 *    are satisfied in the code
 * 6. Discovered vulnerabilities are "novel" by definition (found via
 *    reasoning, not pattern matching)
 * 7. Unknown patterns that don't match any hypothesis are dropped
 */

import { Logger } from '../../lib/logger.js';
import { KnowledgeGraphImpl, KnowledgeFact, KnowledgeRelation } from '../knowledge/docs_processor.js';
import { SemanticReasoner, AttackerHypothesis, HypothesisEvaluation } from './reasoner.js';
import { FeatureExtractor, FeatureVector } from '../features/extractor.js';
import { SolidityParser } from '../ast/parser.js';
import { CFGBuilder, CFG } from '../cfg/builder.js';
import { TaintGraph } from '../taint/graph.js';
import { BugEntry, VulnerabilityPattern } from '../models/bug_database.js';
import { ModelConfig } from '../models/architecture.js';

const log = new Logger('zero-shot-predictor');

// ===========================================================================
// Vulnerability Discovery Result
// ===========================================================================

export interface DiscoveredVulnerability {
  id: string;
  vulnerabilityType: string;
  hypothesisId: string;        // The actual ID of the hypothesis that produced this finding
  title: string;
  riskScore: number;        // 0-1
  confidence: number;        // 0-1
  attackGoal: string;
  preconditionsMet: string[];
  preconditionsUnmet: string[];
  semanticChain: string[];
  evidence: string[];
  explanation: string;
  knowledgeSources: string[]; // Where this hypothesis came from
  isNovel: boolean;
  classification: {
    attackVector?: string;
    affectedComponent?: string;
    rootCause?: string;
  };
}

export interface ZeroShotAnalysisResult {
  sourceCode: string;
  contractName: string;
  features: FeatureVector;
  discoveredVulnerabilities: DiscoveredVulnerability[];
  hypothesisEvaluations: HypothesisEvaluation[];
  knowledgeGraphSize: number;
  novelCount: number;
  droppedCount: number;       // Bugs not matching any hypothesis — dropped
  totalHypothesesEvaluated: number;
  timestamp: string;
}

// ===========================================================================
// Zero-Shot Vulnerability Predictor
// ===========================================================================

export class ZeroShotVulnerabilityPredictor {
  private knowledgeGraph: KnowledgeGraphImpl;
  private reasoner: SemanticReasoner;
  private featureExtractor: FeatureExtractor;

  constructor(
    knowledgeGraph: KnowledgeGraphImpl,
    config: ModelConfig = DEFAULT_CONFIG
  ) {
    this.knowledgeGraph = knowledgeGraph;
    this.reasoner = new SemanticReasoner(knowledgeGraph);
    this.featureExtractor = new FeatureExtractor();
  }

  /**
   * Analyze a Solidity contract using zero-shot reasoning.
   *
   * This method:
   * 1. Parses the source code into AST
   * 2. Builds CFG and performs taint analysis
   * 3. Extracts features combining AST, CFG, taint, and Porosity-X
   * 4. Runs the chain-of-thought reasoner to discover vulnerabilities
   * 5. Converts satisfied hypotheses into vulnerability findings
   */
  async analyze(
    sourceCode: string,
    contractName: string = 'unnamed',
    fileName: string = 'inline'
  ): Promise<ZeroShotAnalysisResult> {
    log.info(`Zero-shot analysis of contract: ${contractName}`);

    const startTime = Date.now();

    // Step 1: Parse source code
    log.info('Step 1: Parsing Solidity source code...');
    const ast = SolidityParser.parse(sourceCode, fileName);
    const contracts = ast.children.filter((c: any) => c.type === 'ContractDefinition');
    log.info(`  AST parsed: ${contracts.length} contracts, ${ast.children.length} top-level nodes`);

    // Step 2: Build CFG
    log.info('Step 2: Building Control Flow Graph...');
    const cfgBuilder = new CFGBuilder();
    const cfgs = cfgBuilder.buildFromAST(ast);
    const cfg = cfgs[0];
    log.info(`  CFG built: ${cfgs.length} functions, ${cfg?.nodes.length || 0} nodes, ${cfg?.edges.length || 0} edges`);

    // Step 3: Perform taint analysis
    log.info('Step 3: Performing taint analysis...');
    const taintGraph = cfg?.taintGraph || new TaintGraph([], []);

    // Step 4: Extract features
    log.info('Step 4: Extracting features...');
    const features = FeatureExtractor.extract(sourceCode, {
      contractName,
      contractAddress: null,
      sourceFile: fileName
    });

    // Step 5: Evaluate attacker hypotheses
    // First, ensure LLM-generated hypotheses are merged in (if not already)
    await this.reasoner.waitForLLMHypotheses();

    log.info('Step 5: Running chain-of-thought reasoning...');
    const hypothesisEvaluations = this.reasoner.evaluate(features);

    // Step 6: Convert satisfied hypotheses to vulnerabilities
    const vulnerabilities = this.hypothesesToVulnerabilities(hypothesisEvaluations);

    // Step 7: Discover novel patterns by combining knowledge graph facts.
    // Uses cached result — the O(N²) combinatorial search over knowledge graph
    // subjects only runs once, not per-contract, to avoid CPU explosion.
    log.info('Step 6: Discovering novel attack patterns...');
    const novelHypotheses = this.reasoner.getCachedNovelPatterns();

    // Optionally re-evaluate with novel hypotheses
    for (const novelHyp of novelHypotheses) {
      const evaluation = this.evaluateHypothesis(novelHyp, features);
      if (evaluation.riskScore > 0.3) {
        vulnerabilities.push(this.hypothesisToVulnerability(evaluation));
      }
    }

    const droppedCount = this.countDroppedPatterns(hypothesisEvaluations);

    // Build a minimal result — we strip out the large AST/CFG/taint data but
    // keep the semantic and vulnerability features needed by the dashboard's
    // Risk Radar and other panels. Only the small structured subsets are retained;
    // the full FeatureVector (AST node list, CFG edges, taint graph) is dropped.
    const result = {
      sourceCode: '',
      contractName,
      features: features ? {
        contractName: features.contractName,
        contractAddress: features.contractAddress,
        sourceFile: features.sourceFile,
        source: features.source,
        structural: features.structural,
        controlFlow: features.controlFlow,
        semantic: features.semantic,
        vulnerabilityPatterns: features.semantic,
        vulnerability: features.vulnerability,
        porosityX: features.porosityX,
        astNodeCount: features.astNodeCount,
        numericVector: features.numericVector,
        featureNames: features.featureNames,
        injectedPatterns: features.injectedPatterns || {},
        taintAnalysis: features.taintAnalysis
      } : null,
      discoveredVulnerabilities: vulnerabilities,
      hypothesisEvaluations: hypothesisEvaluations.map(e => ({
        hypothesisId: e.hypothesis.id,
        confidence: e.confidence,
        riskScore: e.riskScore,
        satisfiedPreconditions: e.satisfiedPreconditions.length,
        unsatisfiedPreconditions: e.unsatisfiedPreconditions.length,
        isMet: e.satisfiedPreconditions.length > 0
      })),
      knowledgeGraphSize: this.knowledgeGraph.size(),
      novelCount: vulnerabilities.filter(v => v.isNovel).length,
      droppedCount,
      totalHypothesesEvaluated: hypothesisEvaluations.length,
      timestamp: new Date().toISOString()
    } as ZeroShotAnalysisResult;

    const elapsed = Date.now() - startTime;
    log.info(`Analysis complete in ${elapsed}ms: ${vulnerabilities.length} vulnerabilities discovered, ${droppedCount} patterns dropped`);

    return result;
  }

  /**
   * Convert hypothesis evaluations to vulnerability findings.
   * Only hypotheses with sufficient risk score are kept.
   */
  private hypothesesToVulnerabilities(evaluations: HypothesisEvaluation[]): DiscoveredVulnerability[] {
    const vulns: DiscoveredVulnerability[] = [];

    for (const eval_ of evaluations) {
      // Only keep hypotheses with meaningful risk
      if (eval_.riskScore < 0.25 && eval_.confidence < 0.3) {
        continue;
      }

      vulns.push(this.hypothesisToVulnerability(eval_));
    }

    // Sort by risk score
    vulns.sort((a, b) => b.riskScore - a.riskScore);

    return vulns;
  }

  private hypothesisToVulnerability(eval_: HypothesisEvaluation): DiscoveredVulnerability {
    const hyp = eval_.hypothesis;

    // Try to classify the vulnerability using knowledge graph facts
    const classification = this.classifyVulnerability(hyp);

    // Map the hypothesis's primary tag to a standard vulnerability type label
    // that aligns with the training dataset's label space (external_call, arithmetic,
    // access_control, timestamp, gas, oracle, delegatecall, signature_replay, etc.).
    // LLM-generated hypotheses may use tags like "gas-limit", "state-corruption", etc.
    // that don't directly map to these canonical labels.
    let vulnType: string;
    if (hyp.tags.length > 0) {
      vulnType = this.normalizeVulnType(hyp.tags[0]);
    } else {
      vulnType = hyp.name;
    }

    return {
      id: `vuln_${hyp.id}_${Date.now()}`,
      vulnerabilityType: vulnType,
      hypothesisId: hyp.id,
      title: hyp.name,
      riskScore: eval_.riskScore,
      confidence: eval_.confidence,
      attackGoal: hyp.attackGoal,
      preconditionsMet: eval_.satisfiedPreconditions,
      preconditionsUnmet: eval_.unsatisfiedPreconditions,
      semanticChain: hyp.semanticChain,
      evidence: eval_.evidence,
      explanation: eval_.explanation,
      knowledgeSources: hyp.knowledgeEvidence.map(eid => {
        const fact = this.knowledgeGraph.facts.get(eid);
        return fact ? fact.source : eid;
      }),
      isNovel: eval_.novel,
      classification
    };
  }

  private evaluateHypothesis(hyp: AttackerHypothesis, features: FeatureVector): HypothesisEvaluation {
    // This is a simplified evaluation for novel hypotheses
    return this.reasoner.evaluate(features).find(e => e.hypothesis.id === hyp.id) || {
      hypothesis: hyp,
      satisfiedPreconditions: [],
      unsatisfiedPreconditions: hyp.preconditions,
      confidence: 0,
      riskScore: 0,
      evidence: [],
      novel: true,
      explanation: 'Novel hypothesis not yet evaluated against code'
    };
  }

  /**
   * Classify a vulnerability using knowledge graph facts.
   * Instead of hardcoding CWEs, we deduce the classification from
   * what the knowledge graph tells us about the attack.
   */
  private classifyVulnerability(hyp: AttackerHypothesis): DiscoveredVulnerability['classification'] {
    // Collect all knowledge facts for this hypothesis
    const relatedFacts: KnowledgeFact[] = [];
    for (const evidenceId of hyp.knowledgeEvidence) {
      const fact = this.knowledgeGraph.facts.get(evidenceId);
      if (fact) relatedFacts.push(fact);
    }

    // Determine attack vector from facts
    const attackVectorFact = relatedFacts.find(f => f.relation === 'ATTACK_VECTOR');
    const attackVector = attackVectorFact ? attackVectorFact.subject : hyp.attackGoal;

    // Determine affected component
    const stateFacts = relatedFacts.filter(f =>
      f.subject.includes('state') || f.subject.includes('storage') || f.subject.includes('balance')
    );
    const affectedComponent = stateFacts.length > 0 ? stateFacts[0].subject : 'contract_state';

    // Determine root cause from semantic rules
    const semanticFacts = relatedFacts.filter(f => f.relation === 'SEMANTIC_RULE' || f.relation === 'LANGUAGE_GOTCHA');
    const rootCause = semanticFacts.length > 0
      ? semanticFacts[semanticFacts.length - 1].object
      : 'Not specified in documentation';

    return { attackVector, affectedComponent, rootCause };
  }

  /**
   * Normalize a hypothesis tag to a canonical vulnerability type label.
   * Maps LLM-generated or variant tags (e.g. "gas-limit", "state-corruption")
   * to the standard label space used by the training dataset.
   */
  private normalizeVulnType(tag: string): string {
    const tagLower = tag.toLowerCase();

    // Direct mappings for common variant tags
    const normalized: Record<string, string> = {
      // Map reentrancy variants to external_call to align with the training
      // dataset's canonical label space (where "reentrancy" → "external_call").
      'reentrancy': 'external_call',
      'reentrancy_unrestricted': 'external_call',
      'gas-limit': 'gas',
      'state-corruption': 'external_call',
      'shift-op': 'gas',
      'shift-arithmetic': 'gas',
      'memory-aliasing': 'delegatecall',
      'reference-types': 'delegatecall',
      'storage-collision': 'delegatecall',
      'value_manipulation': 'oracle',
      'multi-delegate': 'delegatecall',
      'context-confusion': 'access_control',
      'privilege-escalation': 'access_control',
      'auth-bypass': 'access_control',
      'state-confusion': 'external_call',
      'silent-corruption': 'arithmetic',
      'silent-failure': 'external_call',
      'callback-abuse': 'external_call',
      'return-data': 'external_call',
      'identity-shift': 'external_call',
      'cei-violation': 'external_call',
      'post-call-state-update': 'reentrancy',
      'recursive-call-confusion': 'reentrancy',
      'control-flow': 'external_call',
      'expression-order': 'arithmetic',
      'state-mutation': 'external_call',
      'funding-trick': 'access_control',
      'fallback-init': 'access_control',
      'approval-flaw': 'external_call',
      'try-catch': 'external_call',
      'transfer-revert': 'external_call',
      'precompile-spoofing': 'signature_replay',
      'signature': 'signature_replay',
      'ecrecover': 'signature_replay',
      'nonce-mimicry': 'signature_replay',
      'transaction-forgery': 'signature_replay',
      'auth-spoofing': 'access_control',
      'custom-errors': 'gas',
      'panic-suppression': 'gas',
      'event-manipulation': 'oracle',
      'log-inconsistency': 'oracle',
      'indexer-trick': 'oracle',
      'abi-decode': 'external_call',
      'empty-payload': 'external_call',
      'control-flow-abuse': 'external_call',
      'invariant-drift': 'oracle',
      'sequence-confusion': 'access_control',
    };

    if (normalized[tagLower]) return normalized[tagLower];

    // Check if the tag contains/contains a canonical label
    const canonicalLabels = ['external_call', 'arithmetic', 'access_control',
      'timestamp', 'gas', 'oracle', 'delegatecall', 'signature_replay', 'reentrancy'];
    for (const label of canonicalLabels) {
      if (tagLower === label || tagLower.includes(label.replace('_', '-')) || tagLower.includes(label)) {
        return label;
      }
    }

    // Fall back to the original tag if no mapping found
    return tag;
  }

  /**
   * Count patterns that were dropped — hypotheses not matching any
   * documented attack vectors. These represent bugs that can't be
   * verified through documentation-based reasoning.
   */
  private countDroppedPatterns(evaluations: HypothesisEvaluation[]): number {
    // Count hypotheses with very low risk — these represent patterns
    // that don't match documented semantics and should be dropped
    return evaluations.filter(e =>
      e.riskScore < 0.1 && e.confidence < 0.2
    ).length;
  }

  // ===========================================================================
  // Public API
  // ===========================================================================

  getKnowledgeGraph(): KnowledgeGraphImpl {
    return this.knowledgeGraph;
  }

  getReasoner(): SemanticReasoner {
    return this.reasoner;
  }

  /**
   * Export discovered vulnerabilities as BugEntry format (for API compatibility).
   */
  toBugEntries(result: ZeroShotAnalysisResult): BugEntry[] {
    return result.discoveredVulnerabilities.map(vuln => ({
      id: vuln.id,
      title: vuln.title,
      pattern: vuln.semanticChain,
      cwe: vuln.classification.attackVector || 'Unknown',
      severity: this.riskToSeverity(vuln.riskScore),
      impact: vuln.attackGoal,
      difficulty: vuln.confidence < 0.5 ? 'low' : vuln.confidence < 0.8 ? 'medium' : 'high',
      description: vuln.explanation,
      exploitChain: vuln.semanticChain,
      detectionFeatures: vuln.knowledgeEvidence,
      exploitability: vuln.attackGoal === 'steal_funds' ? 'high' : 'medium',
      affectedCode: vuln.evidence.join('; '),
      remediation: `Verify against ${vuln.knowledgeSources.join(', ')}`
    }));
  }

  private riskToSeverity(risk: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (risk >= 0.8) return 'critical';
    if (risk >= 0.6) return 'high';
    if (risk >= 0.4) return 'medium';
    if (risk >= 0.2) return 'low';
    return 'info';
  }
}

// ===========================================================================
// Default Configuration
// ===========================================================================

import { DEFAULT_CONFIG } from '../models/architecture.js';

/**
 * Create a zero-shot predictor with a fresh knowledge graph.
 * In a real deployment, the knowledge graph would be pre-populated
 * by the documentation ingestion pipeline.
 */
export function createZeroShotPredictor(
  knowledgeGraph?: KnowledgeGraphImpl,
  config?: ModelConfig
): ZeroShotVulnerabilityPredictor {
  const kg = knowledgeGraph || new KnowledgeGraphImpl();
  return new ZeroShotVulnerabilityPredictor(kg, config || DEFAULT_CONFIG);
}
