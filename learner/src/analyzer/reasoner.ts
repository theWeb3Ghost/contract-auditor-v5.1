/**
 * Zero-Shot Vulnerability Reasoner.
 *
 * This is the core of the self-learning system. Instead of using pre-defined
 * vulnerability patterns (like "reentrancy" or "integer overflow"), the reasoner:
 *
 * 1. Builds attacker hypotheses from the knowledge graph (EVM opcodes,
 *    Solidity semantics, blockchain concepts)
 * 2. Simulates attack paths through the contract's AST + CFG + taint graph
 * 3. Identifies which attacker hypotheses are satisfied
 * 4. Assigns novel vulnerability scores based on discovered patterns
 *
 * The reasoner thinks like an attacker: "How can I steal funds?" — and then
 * traces the contract code to find paths that match.
 *
 * Key principle: Everything is discovered from documentation semantics,
 * not from hardcoded pattern names.
 */

import { Logger } from '../../lib/logger.js';
import { KnowledgeGraphImpl, KnowledgeFact, KnowledgeRelation } from '../knowledge/docs_processor.js';
import { FeatureVector, FeatureExtractor } from '../features/extractor.js';
import { SolidityParser } from '../ast/parser.js';
import { ASTSourceUnit, ASTContractDefinition, ASTFunctionDefinition, ASTNode } from '../ast/types.js';
import { CFGBuilder, CFG, CFGNode } from '../cfg/builder.js';
import { TaintGraph, TaintVariable, TaintPath, TaintLabel, TAINT_PRIORITY } from '../taint/graph.js';
import { ModelConfig, DEFAULT_CONFIG } from '../models/architecture.js';
import { generateLLMHypotheses } from './llm_patterns.js';
import { getRLFeedbackEngine } from '../../training/rl_feedback.js';

const log = new Logger('zero-shot-reasoner');

// ===========================================================================
// Attacker Hypothesis
// ===========================================================================

/**
 * An attacker hypothesis is a structured way of thinking about how to steal
 * value from a contract. Each hypothesis has:
 * - An attack goal (what the attacker wants to achieve)
 * - Preconditions (what must be true in the code)
 * - A semantic chain (sequence of conditions that enable the attack)
 * - A confidence score (how likely this hypothesis is)
 */
export interface AttackerHypothesis {
  id: string;
  name: string;           // Human-readable name (not a "pattern" — a goal)
  description: string;    // How the attack works
  attackGoal: string;     // What the attacker wants: "steal_funds", "bypass_auth", etc.
  preconditions: string[]; // What must exist in the code
  semanticChain: string[]; // Sequence of semantic conditions
  confidence: number;     // 0-1
  source: string;         // Where this hypothesis came from (documented fact)
  novel: boolean;         // Whether this is a newly discovered pattern
  tags: string[];         // Classification tags
  knowledgeEvidence: string[]; // IDs of knowledge facts that support this hypothesis
}

/**
 * Result of evaluating a hypothesis against a contract.
 */
export interface HypothesisEvaluation {
  hypothesis: AttackerHypothesis;
  satisfiedPreconditions: string[];
  unsatisfiedPreconditions: string[];
  confidence: number;      // How well the code matches the hypothesis
  riskScore: number;       // Risk from 0-1
  evidence: string[];      // Evidence from the code
  novel: boolean;          // Whether this is a novel discovery
  explanation: string;     // Human-readable explanation
}

// ===========================================================================
// Semantic Reasoning Engine
// ===========================================================================

/**
 * The SemanticReasoner performs chain-of-thought reasoning like an attacker.
 *
 * It starts with attack goals derived from the knowledge graph, then traces
 * through the contract's code to find paths that satisfy each hypothesis.
 */
export class SemanticReasoner {
  private knowledgeGraph: KnowledgeGraphImpl;
  private hypotheses: AttackerHypothesis[] = [];
  private novelPatternsCache: AttackerHypothesis[] | null = null;
  private llmReady: boolean = false;
  private llmInitPromise: Promise<void> | null = null;

  constructor(knowledgeGraph: KnowledgeGraphImpl) {
    this.knowledgeGraph = knowledgeGraph;
    this.initializeHypotheses();

    // Fire off async LLM hypothesis generation in the background.
    // This expands from the base 6 hardcoded hypotheses to 20+ LLM-generated ones.
    // The hypotheses are added to this.hypotheses once ready; analyze() calls
    // will use whatever hypotheses are available at evaluation time.
    this.llmInitPromise = this.initLLMHypotheses();
  }

  /**
   * Asynchronously request LLM-generated hypotheses and merge them in.
   * Resolves once the hypotheses are available (cached or fetched).
   */
  private async initLLMHypotheses(): Promise<void> {
    try {
      const llmHyps = await generateLLMHypotheses(this.knowledgeGraph);
      if (llmHyps.length > 0) {
        for (const h of llmHyps) {
          this.addHypothesis(h);
        }
        log.info(`LLM expanded hypothesis pool: ${this.hypotheses.length} total (${llmHyps.length} from LLM)`);
      }
      this.llmReady = true;
    } catch (err: any) {
      log.warn(`LLM hypothesis generation failed: ${err.message}. Proceeding with base hypotheses only.`);
      this.llmReady = true;
    }
  }

  /**
   * Initialize attacker hypotheses from the knowledge graph.
   * Each hypothesis is derived from documented security facts.
   */
  private initializeHypotheses(): void {
    log.info('Initializing attacker hypotheses from knowledge graph...');

    // Hypothesis: Attacker can manipulate state via external calls
    this.addHypothesis({
      id: 'attacker_manipulate_state_via_external_call',
      name: 'External Call State Manipulation',
      description: 'An attacker can manipulate contract state by causing external calls to execute before state updates, enabling reentrancy or state corruption.',
      attackGoal: 'steal_funds',
      preconditions: [
        'has_external_call',
        'has_state_change',
        'call_before_state_update',
        'trust_boundary_can_be_crossed'
      ],
      semanticChain: [
        'External call to untrusted address',
        'External call executes attacker-controlled code',
        'State is updated AFTER the external call',
        'Attacker callback modifies the expected balance or state',
        'Attacker receives more value than intended'
      ],
      confidence: 0.85,
      source: 'knowledge://solidity-docs:security-considerations',
      novel: false,
      tags: ['external_call', 'state_manipulation', 'reentrancy_like'],
      knowledgeEvidence: this.findEvidence([
        'CALL', 'DELEGATECALL', 'SSTORE', 'reentrancy', 'state'
      ])
    });

    // Hypothesis: Attacker can manipulate arithmetic operations
    this.addHypothesis({
      id: 'attacker_manipulate_arithmetic',
      name: 'Arithmetic Manipulation',
      description: 'An attacker can cause integer overflow or underflow in arithmetic operations, leading to incorrect values and fund theft.',
      attackGoal: 'steal_funds',
      preconditions: [
        'has_arithmetic_operation',
        'no_safe_math_or_solidity_8_checks',
        'user_controlled_input',
        'value_used_for_state_or_transfer'
      ],
      semanticChain: [
        'User provides value to arithmetic operation',
        'Operation overflows/underflows without check',
        'Result wraps to unexpected value',
        'Wrapped value used for transfer or state',
        'Attacker gains more value or bypasses limits'
      ],
      confidence: 0.75,
      source: 'knowledge://evm-docs:opcode-semantics',
      novel: false,
      tags: ['arithmetic', 'overflow', 'underflow', 'value_manipulation'],
      knowledgeEvidence: this.findEvidence([
        'ADD', 'SUB', 'overflow', 'underflow', 'uint256', 'arithmetic'
      ])
    });

    // Hypothesis: Attacker can bypass authorization
    this.addHypothesis({
      id: 'attacker_bypass_authorization',
      name: 'Authorization Bypass',
      description: 'An attacker can call privileged functions by manipulating trust boundaries, using tx.origin phishing, or exploiting weak checks.',
      attackGoal: 'access_bypassed',
      preconditions: [
        'has_authorization_check',
        'uses_tx_origin_or_weak_check',
        'attacker_can_control_input',
        'privilege_escalation_possible'
      ],
      semanticChain: [
        'Authorization check uses attacker-influenceable value',
        'Attacker manipulates the checked value',
        'Check passes despite unauthorized access',
        'Attacker performs privileged operation',
        'Governance or funds compromised'
      ],
      confidence: 0.80,
      source: 'knowledge://solidity-docs:security-considerations',
      novel: false,
      tags: ['access_control', 'authorization', 'tx_origin', 'privilege'],
      knowledgeEvidence: this.findEvidence([
        'tx.origin', 'msg.sender', 'CALLER', 'ORIGIN', 'authorization',
        'onlyOwner', 'access', 'priv'
      ])
    });

    // Hypothesis: Attacker can manipulate time-based logic
    this.addHypothesis({
      id: 'attacker_manipulate_timestamp',
      name: 'Timestamp Manipulation',
      description: 'An attacker (as miner) can manipulate block.timestamp within a window, causing incorrect outcomes in time-dependent logic.',
      attackGoal: 'steal_funds',
      preconditions: [
        'uses_block_timestamp',
        'timestamp_affects_critical_logic',
        'no_alternative_randomness_source',
        'mining_power_or_collusion'
      ],
      semanticChain: [
        'Contract uses block.timestamp for critical decisions',
        'Miner can adjust timestamp by ~15 seconds',
        'Adjustment causes different code path execution',
        'Attacker profits from manipulated outcome',
        'Honest users lose funds or opportunities'
      ],
      confidence: 0.70,
      source: 'knowledge://evm-docs:opcode-TIMESTAMP',
      novel: false,
      tags: ['timestamp', 'miner_manipulation', 'randomness', 'time_dependency'],
      knowledgeEvidence: this.findEvidence([
        'TIMESTAMP', 'timestamp', 'block.timestamp', 'block.number',
        'randomness', 'miner'
      ])
    });

    // Hypothesis: Attacker can exploit gas limitations
    this.addHypothesis({
      id: 'attacker_exploit_gas_limit',
      name: 'Gas Limit Exploitation',
      description: 'An attacker can cause operations to fail or be reverted due to gas limits, leading to denial of service or fund loss.',
      attackGoal: 'service_denied',
      preconditions: [
        'has_loop_or_recursion',
        'gas_consumption_grows_with_input',
        'no_gas_limit_check',
        'attacker_controls_input_size'
      ],
      semanticChain: [
        'Contract has loop that scales with input',
        'Attacker provides large or crafted input',
        'Gas consumption exceeds limit',
        'Operation reverts, affecting all users',
        'Contract becomes unusable'
      ],
      confidence: 0.65,
      source: 'knowledge://evm-docs:gas-costs',
      novel: false,
      tags: ['gas', 'dos', 'loop', 'revert', 'out_of_gas'],
      knowledgeEvidence: this.findEvidence([
        'GAS', 'gas', 'loop', 'FOR', 'loop_depth', 'unbounded'
      ])
    });

    // Hypothesis: Attacker can manipulate oracle or external data
    this.addHypothesis({
      id: 'attacker_manipulate_oracle',
      name: 'Oracle Data Manipulation',
      description: 'An attacker can manipulate external data feeds (price oracles, L2 bridges) to cause incorrect contract behavior.',
      attackGoal: 'steal_funds',
      preconditions: [
        'reads_external_data',
        'data_source_is_manipulable',
        'data_affects_value_transfer',
        'no_median_or_decentralization'
      ],
      semanticChain: [
        'Contract relies on external data for pricing',
        'Attacker manipulates the data source',
        'Incorrect price fed to contract',
        'Attacker trades at manipulated price',
        'Contract or other users lose funds'
      ],
      confidence: 0.75,
      source: 'knowledge://eips:oracle-manipulation',
      novel: false,
      tags: ['oracle', 'price_manipulation', 'flash_loan', 'external_data'],
      knowledgeEvidence: this.findEvidence([
        'oracle', 'price', 'feed', 'external_data', 'manipulat',
        'median', 'average', 'decentraliz'
      ])
    });

    log.info(`Initialized ${this.hypotheses.length} attacker hypotheses`);
  }

  private addHypothesis(hyp: AttackerHypothesis): void {
    // If this hypothesis is derived from novel knowledge not in the standard patterns,
    // mark it as novel
    hyp.novel = this.isNovelHypothesis(hyp);
    this.hypotheses.push(hyp);
  }

  private isNovelHypothesis(hyp: AttackerHypothesis): boolean {
    // A hypothesis is novel if its knowledge evidence includes facts from
    // recently ingested documents that weren't in the original bug database
    for (const evidenceId of hyp.knowledgeEvidence) {
      const fact = this.knowledgeGraph.facts.get(evidenceId);
      if (fact && fact.tags?.includes('recent')) {
        return true;
      }
    }
    return false;
  }

  private findEvidence(keywords: string[]): string[] {
    const evidence: string[] = [];

    for (const keyword of keywords) {
      const facts = this.knowledgeGraph.getFactsBySubject(keyword);
      for (const fact of facts) {
        evidence.push(fact.id);
      }

      // Also search in object fields
      const objFacts = this.knowledgeGraph.getFactsByObject(keyword);
      for (const fact of objFacts) {
        if (!evidence.includes(fact.id)) {
          evidence.push(fact.id);
        }
      }
    }

    return [...new Set(evidence)];
  }

  // ===========================================================================
  // Evaluation
  // ===========================================================================

  /**
   * Evaluate all hypotheses against a contract's feature vector.
   * Returns all hypotheses that are satisfied to some degree.
   */
  evaluate(featureVector: FeatureVector): HypothesisEvaluation[] {
    const results: HypothesisEvaluation[] = [];

    // Get RL feedback engine for confidence weight adjustments
    let rlEngine: ReturnType<typeof getRLFeedbackEngine> | null = null;
    try {
      rlEngine = getRLFeedbackEngine();
    } catch {
      // RL engine not available, skip weight adjustment
    }

    // Base thresholds for including a hypothesis evaluation in results.
    // These are scaled per-hypothesis by the RL confidence multiplier so that
    // hypotheses driven to low weights are progressively filtered out.
    const BASE_RISK_THRESHOLD = 0.1;
    const BASE_CONF_THRESHOLD = 0.3;

    for (const hyp of this.hypotheses) {
      const evaluation = this.evaluateHypothesis(hyp, featureVector);

      // Apply learned confidence multiplier from RL feedback (only when
      // an RL engine is actually configured with feedback data)
      let thresholdRisk = BASE_RISK_THRESHOLD;
      let thresholdConf = BASE_CONF_THRESHOLD;

      if (rlEngine && rlEngine.isConfigured()) {
        const multiplier = rlEngine.getConfidenceMultiplier(hyp.id);
        if (multiplier !== 1.0) {
          evaluation.confidence = Math.min(1.0, evaluation.confidence * multiplier);
          evaluation.riskScore = Math.min(1.0, evaluation.riskScore * multiplier);
        }
        // Scale thresholds so that hypotheses driven to low weights are
        // progressively filtered out. Using threshold = BASE + (1 - mult)
        // ensures aggressive filtering:
        // - mult=1.0: threshold stays at base (no change)
        // - mult=0.5: threshold = 0.1 + 0.5 = 0.6 (6x stricter)
        // - mult=0.3: threshold = 0.1 + 0.7 = 0.8 (very strict)
        // - mult=0.1: threshold = 0.1 + 0.9 = 1.0 (effectively disabled)
        const penalty = 1.0 - multiplier;
        thresholdRisk = BASE_RISK_THRESHOLD + penalty;
        thresholdConf = BASE_CONF_THRESHOLD + penalty;
      }

      if (evaluation.riskScore > thresholdRisk || evaluation.confidence > thresholdConf) {
        results.push(evaluation);
      }
    }

    // Sort by risk score
    results.sort((a, b) => b.riskScore - a.riskScore);

    return results;
  }

  /**
   * Evaluate a single hypothesis against the code.
   */
  private evaluateHypothesis(hyp: AttackerHypothesis, features: FeatureVector): HypothesisEvaluation {
    let satisfied = 0;
    let total = hyp.preconditions.length;
    const evidence: string[] = [];

    const struct = features.structural;
    const ctrl = features.controlFlow;
    const sem = features.semantic;
    const vuln = features.vulnerability;

    for (const precondition of hyp.preconditions) {
      const result = this.checkPrecondition(precondition, struct, ctrl, sem, vuln);
      if (result.satisfied) {
        satisfied++;
        evidence.push(...result.evidence);
      }
    }

    const confidence = hyp.confidence * (satisfied / total);
    const riskScore = this.computeRisk(hyp, confidence, features, evidence);

    return {
      hypothesis: hyp,
      satisfiedPreconditions: hyp.preconditions.slice(0, satisfied),
      unsatisfiedPreconditions: hyp.preconditions.slice(satisfied),
      confidence,
      riskScore,
      evidence,
      novel: hyp.novel,
      explanation: this.generateExplanation(hyp, satisfied, total, evidence)
    };
  }

  private checkPrecondition(
    precondition: string,
    struct: any,
    ctrl: any,
    sem: any,
    vuln: any
  ): { satisfied: boolean; evidence: string[] } {
    const evidence: string[] = [];

    const checks: Record<string, { satisfied: boolean; evidence: string[] }> = {
      has_external_call: {
        // Require a tainted external call — the call target must be
        // attacker-influenceable, not just any .call() to a variable.
        satisfied: vuln.hasExternalCall && (vuln.hasTaintedExternalCallTarget || ctrl.taintSourceCount > 0),
        evidence: vuln.hasExternalCall ? ['External call to potentially tainted address detected'] : []
      },
      has_state_change: {
        satisfied: struct.numStateMutations > 0,
        evidence: struct.numStateMutations > 0 ? [`${struct.numStateMutations} state mutations detected`] : []
      },
      call_before_state_update: {
        satisfied: vuln.hasStateMutationAfterCall,
        evidence: vuln.hasStateMutationAfterCall ? ['State change found after external call'] : []
      },
      trust_boundary_can_be_crossed: {
        satisfied: ctrl.hasReentrantPath || vuln.hasTaintedExternalCallTarget,
        evidence: ctrl.hasReentrantPath ? ['Tainted path from external call to state'] : []
      },
      has_arithmetic_operation: {
        // Flag arithmetic operations when the feature extractor detected
        // unchecked arithmetic or overflow-prone operations. We require
        // actual code evidence, not just '+' in comments/strings.
        satisfied: vuln.hasUncheckedArithmetic || (vuln.hasOverflowRisk && struct.numStateMutations > 0),
        evidence: vuln.hasUncheckedArithmetic ? ['Unchecked arithmetic operation detected'] :
                  vuln.hasOverflowRisk ? ['Overflow-prone arithmetic in state-modifying functions'] : []
      },
      no_safe_math_or_solidity_8_checks: {
        satisfied: vuln.hasUncheckedArithmetic || (vuln.hasOverflowRisk && struct.numStateMutations > 0),
        evidence: vuln.hasUncheckedArithmetic ? ['Unchecked arithmetic detected'] :
                  vuln.hasOverflowRisk ? ['No overflow protection detected'] : []
      },
      user_controlled_input: {
        satisfied: ctrl.taintSourceCount > 0,
        evidence: ctrl.taintSourceCount > 0 ? [`${ctrl.taintSourceCount} user-controlled inputs detected`] : []
      },
      value_used_for_state_or_transfer: {
        satisfied: vuln.hasExternalCall && vuln.hasStateMutationAfterCall && (vuln.hasTaintedExternalCallTarget || ctrl.taintSourceCount > 0),
        evidence: ['External call value flows to state changes']
      },
      has_authorization_check: {
        satisfied: vuln.hasOwnerCheck || vuln.hasMsgSenderCheck,
        evidence: vuln.hasMsgSenderCheck ? ['Authorization check detected (msg.sender)'] : []
      },
      uses_tx_origin_or_weak_check: {
        satisfied: vuln.hasTxOriginCheck,
        evidence: vuln.hasTxOriginCheck ? ['Uses tx.origin for auth (weak)'] : []
      },
      attacker_can_control_input: {
        satisfied: ctrl.taintSourceCount > 0,
        evidence: ctrl.taintSourceCount > 0 ? [`${ctrl.taintSourceCount} attacker-controllable inputs`] : []
      },
      privilege_escalation_possible: {
        // Only flag if the function actually modifies state AND lacks any
        // authorization check AND has user-controllable input.
        // Previously: !hasOwnerCheck + state vars + taint → fires on nearly all contracts.
        satisfied: !vuln.hasOwnerCheck && !vuln.hasMsgSenderCheck &&
                   struct.numStateMutations > 0 && ctrl.taintSourceCount > 0,
        evidence: !vuln.hasOwnerCheck && !vuln.hasMsgSenderCheck
          ? ['State-modifying functions lack authorization checks with user-controllable inputs']
          : []
      },
      uses_block_timestamp: {
        satisfied: false, // Would need taint analysis to detect
        evidence: []
      },
      timestamp_affects_critical_logic: {
        satisfied: false,
        evidence: []
      },
      no_alternative_randomness_source: {
        satisfied: false,
        evidence: []
      },
      has_loop_or_recursion: {
        satisfied: ctrl.maxLoopDepth > 0,
        evidence: ctrl.maxLoopDepth > 0 ? [`Loop depth ${ctrl.maxLoopDepth} detected`] : []
      },
      gas_consumption_grows_with_input: {
        satisfied: ctrl.maxLoopDepth > 1 || struct.totalLinesOfCode > 100,
        evidence: ['Gas consumption may grow with input size']
      },
      no_gas_limit_check: {
        satisfied: ctrl.maxLoopDepth > 0,
        evidence: ctrl.maxLoopDepth > 0 ? [`Unbounded loop (depth ${ctrl.maxLoopDepth}) with no gas limit check`] : []
      },
      attacker_controls_input_size: {
        satisfied: ctrl.taintSourceCount > 0,
        evidence: ['Attacker can control input size']
      },
      reads_external_data: {
        satisfied: false, // Would need oracle detection
        evidence: []
      },
      data_source_is_manipulable: {
        satisfied: false,
        evidence: []
      },
      data_affects_value_transfer: {
        satisfied: vuln.hasExternalCall,
        evidence: vuln.hasExternalCall ? ['External data affects call value'] : []
      },
      no_median_or_decentralization: {
        satisfied: false,
        evidence: []
      }
    };

    const result = checks[precondition] || this.fallbackPreconditionCheck(precondition, struct, ctrl, sem, vuln);
    return result;
  }

  /**
   * Fallback string-matching mechanism for unknown (e.g., LLM-generated) preconditions.
   * Maps natural-language precondition strings to existing feature checks via
   * keyword normalization. This allows LLM hypotheses to be evaluated even when
   * their precondition strings don't exactly match the enumerated check keys.
   */
  private fallbackPreconditionCheck(
    precondition: string,
    struct: any,
    ctrl: any,
    sem: any,
    vuln: any
  ): { satisfied: boolean; evidence: string[] } {
    const pc = precondition.toLowerCase().trim();
    const evidence: string[] = [];

    const check = (condition: boolean, msg: string): { satisfied: boolean; evidence: string[] } => {
      if (condition) evidence.push(msg);
      return { satisfied: condition, evidence };
    };

    // External call detection
    if (pc.includes('external call') || pc.includes('delegatecall') || pc.includes('low.level') ||
        pc.includes('untrusted') || pc.includes('attacker') && pc.includes('controll')) {
      return check(vuln.hasExternalCall && (vuln.hasTaintedExternalCallTarget || ctrl.taintSourceCount > 0), 'External call to attacker-influenceable target detected');
    }

    // State change / mutation detection
    if (pc.includes('state change') || pc.includes('state mutat') || pc.includes('sstore') ||
        pc.includes('storage') || pc.includes('balance')) {
      return check(struct.numStateMutations > 0, `${struct.numStateMutations} state mutations detected`);
    }

    // Call before state update (reentrancy-like ordering)
    if (pc.includes('call') && pc.includes('before') || pc.includes('before') && pc.includes('state')) {
      return check(vuln.hasStateMutationAfterCall, 'State change found after external call');
    }

    // Trust boundary
    if (pc.includes('trust') || pc.includes('boundary') || pc.includes('crossed')) {
      return check(ctrl.hasReentrantPath || vuln.hasTaintedExternalCallTarget, 'Tainted path from external call to state');
    }

    // Arithmetic / overflow
    if (pc.includes('arithmetic') || pc.includes('overflow') || pc.includes('underflow') ||
        pc.includes('math') || pc.includes('uint')) {
      return check(ctrl.totalCFGNodes > 10, 'Complex control flow suggests arithmetic operations');
    }

    // User-controlled input
    if (pc.includes('user') && pc.includes('input') || pc.includes('attacker') && pc.includes('input') ||
        pc.includes('control')) {
      return check(ctrl.taintSourceCount > 0, `${ctrl.taintSourceCount} user-controlled inputs detected`);
    }

    // Authorization / access control
    if (pc.includes('authoriz') || pc.includes('access') || pc.includes('owner') || pc.includes('auth') ||
        pc.includes('msg.sender') || pc.includes('onlyowner')) {
      return check(vuln.hasOwnerCheck || vuln.hasMsgSenderCheck, 'Authorization check detected (msg.sender)');
    }

    // tx.origin
    if (pc.includes('tx.origin') || pc.includes('tx origin')) {
      return check(vuln.hasTxOriginCheck, 'Uses tx.origin for auth (weak)');
    }

    // Timestamp
    if (pc.includes('timestamp') || pc.includes('block.timestamp') || pc.includes('time')) {
      // Check source for block.timestamp / TIMESTAMP usage
      const sourceStr = JSON.stringify(struct);
      return check(sourceStr.includes('block.timestamp') || sourceStr.includes('TIMESTAMP'), 'block.timestamp usage detected');
    }

    // Loop / gas
    if (pc.includes('loop') || pc.includes('gas') || pc.includes('recursion')) {
      return check(ctrl.maxLoopDepth > 0, `Loop depth ${ctrl.maxLoopDepth} detected`);
    }

    // External data / oracle
    if (pc.includes('oracle') || pc.includes('external data') || pc.includes('price') ||
        pc.includes('feed') || pc.includes('external source')) {
      return check(vuln.hasExternalCall, 'External data dependency through external call');
    }

    // Interaction between components (novel patterns)
    if (pc.includes('interaction') || pc.includes('combination') || pc.includes('combined')) {
      return check(vuln.hasExternalCall && ctrl.taintSourceCount > 0, 'Interaction between tainted input and external call');
    }

    // Default: don't satisfy unknown preconditions
    return { satisfied: false, evidence: [] };
  }

  private computeRisk(
    hyp: AttackerHypothesis,
    confidence: number,
    features: FeatureVector,
    evidence: string[]
  ): number {
    // Base risk from hypothesis confidence
    let risk = confidence;

    // Scale by feature-based indicators — only add bonuses for hypotheses
    // whose preconditions actually include these features. This prevents
    // generic risk bonuses from inflating scores for unrelated hypotheses.
    const vuln = features.vulnerability;
    const ctrl = features.controlFlow;
    const hasPrecondition = (pc: string) => hyp.preconditions.includes(pc);

    if (hasPrecondition('has_external_call') && vuln.hasExternalCall) risk += 0.15;
    if (hasPrecondition('call_before_state_update') && vuln.hasStateMutationAfterCall) risk += 0.20;
    if (hasPrecondition('trust_boundary_can_be_crossed') && (ctrl.hasReentrantPath || vuln.hasTaintedExternalCallTarget)) risk += 0.25;
    if (hasPrecondition('user_controlled_input') && ctrl.taintSourceCount > 0) risk += 0.10;

    // Cap at 1.0
    return Math.min(risk, 1.0);
  }

  private generateExplanation(
    hyp: AttackerHypothesis,
    satisfied: number,
    total: number,
    evidence: string[]
  ): string {
    const percent = Math.round((satisfied / total) * 100);
    return `${hyp.name}: ${percent}% of preconditions satisfied. ` +
           `Evidence: ${evidence.slice(0, 3).join('; ')}. ` +
           `Attack chain: ${hyp.semanticChain.slice(0, 2).join(' → ')} → ...`;
  }

  // ===========================================================================
  // Novel Pattern Discovery
  // ===========================================================================

  /**
   * Discover novel vulnerability patterns by combining knowledge graph facts
   * that haven't been seen together before.
   *
   * NOTE: This is an O(N²) combinatorial search over all knowledge graph
   * subjects. Results are cached after the first computation to avoid
   * repeated CPU-intensive scans on every contract analysis.
   */
  discoverNovelPatterns(): AttackerHypothesis[] {
    if (this.novelPatternsCache) {
      return this.novelPatternsCache;
    }

    const novel: AttackerHypothesis[] = [];
    const allSubjects = this.knowledgeGraph.getAllSubjects();

    // Look for combinations of facts that suggest new attack vectors
    for (let i = 0; i < allSubjects.length; i++) {
      for (let j = i + 1; j < allSubjects.length; j++) {
        const combined = this.tryCombineSubjects(allSubjects[i], allSubjects[j]);
        if (combined && combined.novel) {
          novel.push(combined);
        }
      }
    }

    log.info(`Discovered ${novel.length} potentially novel attack patterns`);
    this.novelPatternsCache = novel;
    return novel;
  }

  /**
   * Cached accessor for novel patterns. Same as discoverNovelPatterns()
   * but makes the caching intent explicit at call sites.
   */
  getCachedNovelPatterns(): AttackerHypothesis[] {
    return this.discoverNovelPatterns();
  }

  private tryCombineSubjects(subjectA: string, subjectB: string): AttackerHypothesis | null {
    const factsA = this.knowledgeGraph.getFactsBySubject(subjectA);
    const factsB = this.knowledgeGraph.getFactsBySubject(subjectB);

    // Look for complementary attack conditions
    const attackA = factsA.find(f => f.relation === 'ATTACK_VECTOR');
    const attackB = factsB.find(f => f.relation === 'ATTACK_VECTOR');

    if (attackA && attackB && attackA.confidence > 0.5 && attackB.confidence > 0.5) {
      const id = `novel_${subjectA}_${subjectB}_${attackA.id}_${attackB.id}`;

      if (this.hypotheses.some(h => h.id === id)) {
        return null; // Already exists
      }

      return {
        id,
        name: `${subjectA} + ${subjectB} Combined Attack`,
        description: `Combines ${attackA.object} and ${attackB.object}`,
        attackGoal: 'steal_funds',
        preconditions: [
          `has_${subjectA}`,
          `has_${subjectB}`,
          'interaction_between_components'
        ],
        semanticChain: [
          attackA.object,
          'Combined with',
          attackB.object,
          'Results in novel exploitation path'
        ],
        confidence: Math.min(attackA.confidence * attackB.confidence * 2, 1.0),
        source: `${attackA.source} + ${attackB.source}`,
        novel: true,
        tags: ['novel', 'combined', subjectA, subjectB],
        knowledgeEvidence: [attackA.id, attackB.id]
      };
    }

    return null;
  }

  // ===========================================================================
  // Public API
  // ===========================================================================

  /**
   * Wait for LLM-generated hypotheses to be loaded before evaluating.
   * This ensures the expanded hypothesis pool is available for analysis.
   * Resolves immediately if already loaded.
   */
  async waitForLLMHypotheses(): Promise<void> {
    if (this.llmInitPromise) {
      await this.llmInitPromise;
    }
  }

  getHypotheses(): AttackerHypothesis[] {
    return this.hypotheses;
  }

  getHypothesis(hypothesisId: string): AttackerHypothesis | undefined {
    return this.hypotheses.find(h => h.id === hypothesisId);
  }
}
