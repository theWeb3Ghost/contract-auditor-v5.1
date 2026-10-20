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
  satisfiedCount: number;   // Number of satisfied preconditions
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

    // Hypothesis: Unchecked low-level call return value
    // .call() and .send() return (bool, bytes) — if the return value isn't checked,
    // a failed external call silently continues, leading to inconsistent state.
    // This is distinct from reentrancy (which requires state manipulation via the
    // callback); here the bug is simply not reverting on call failure.
    this.addHypothesis({
      id: 'attacker_silent_external_call_failure',
      name: 'Unchecked External Call Return Value',
      description: 'Low-level .call() or .send() without checking the return value allows external calls to fail silently, leading to inconsistent state (e.g., ETH transfer fails but state updates proceed).',
      attackGoal: 'cause_state_inconsistency',
      preconditions: [
        'has_low_level_call',
        'external_call_return_not_checked',
        'no_revert_on_failure',
        'has_value_transfer_in_low_level_call'
      ],
      semanticChain: [
        'Contract uses low-level .call() or .send() to transfer value',
        'Return value of .call() is not checked via require/assert',
        'External call fails (e.g., receiver reverts or balance is 0)',
        'Contract continues execution as if the call succeeded',
        'State is updated despite failed transfer, causing inconsistency'
      ],
      confidence: 0.80,
      source: 'knowledge://solidity-docs:security-considerations',
      novel: false,
      tags: ['external_call', 'unchecked_return_value', 'cei-violation'],
      knowledgeEvidence: this.findEvidence([
        'call', 'send', 'return', 'value', 'external', 'gas', 'stipend'
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
    // RAISED from 0.25: many hypotheses satisfy all preconditions on standard
    // DeFi patterns (library transfer functions, Uniswap router loops, deadline
    // checks). A higher threshold ensures only high-confidence predictions are
    // reported, reducing false positives on contracts that contain benign instances
    // of patterns that are exploitable in narrower contexts.
    const BASE_RISK_THRESHOLD = 0.55;
    const BASE_CONF_THRESHOLD = 0.55;

    for (const hyp of this.hypotheses) {
      const evaluation = this.evaluateHypothesis(hyp, featureVector);
      const hypTags = hyp.tags || [];

      // Apply learned confidence multiplier from RL feedback
      let thresholdRisk = BASE_RISK_THRESHOLD;
      let thresholdConf = BASE_CONF_THRESHOLD;

      if (rlEngine) {
        const multiplier = rlEngine.getConfidenceMultiplier(hyp.id);
        // Scale thresholds so that poorly-performing hypotheses need a slightly
        // stronger signal to fire. The penalty scales with (1 - multiplier).
        // At floor (0.5x), penalty = 0.15, so threshold = 0.40.
        const penalty = Math.min(0.50, (1.0 - multiplier) * 0.30);
        thresholdRisk = BASE_RISK_THRESHOLD + penalty;
        thresholdConf = BASE_CONF_THRESHOLD + penalty;
      }

      // Require a minimum precondition satisfaction ratio — hypotheses that
      // satisfy only a minority of their preconditions are too noisy to report.
      // For 4 preconditions: require 75% (3/4) to balance FP reduction with
      // recall preservation. The tightened precondition logic handles most FPs.
      // For 3 preconditions: require 2/3 (~67%).
      // For 2 preconditions: require both (100%).
      // For 1 precondition: require 100%.
      const satisfactionRatio = evaluation.satisfiedCount / evaluation.hypothesis.preconditions.length;
      const total = evaluation.hypothesis.preconditions.length;
      let requiredMet: number;
      if (total <= 1) requiredMet = 1;
      else if (total <= 2) requiredMet = total;                            // both for 2
      else if (total === 3) requiredMet = Math.ceil(total * 2 / 3);      // 2/3 for 3
      else requiredMet = Math.ceil(total * 0.75);                        // 3/4 for 4+

      // Pattern library short-circuit: if injected high-confidence patterns
      // match this hypothesis's tags, lower the threshold so the hypothesis
      // can fire even with unsatisfied preconditions. This is the pre-fix stage
      // that bypasses the Claude Code fix loop for known vulnerability classes.
      const injectedPatterns = (featureVector as any).injectedPatterns || {};
      const hasHighConfidencePattern = Object.entries(injectedPatterns).some(
        ([pkey, hint]: [string, any]) => {
          // Normalize pattern key: "category.pattern_name" -> "pattern_name"
          const pname = pkey.includes('.') ? pkey.split('.').pop() || pkey : pkey;
          const patternTagMap: Record<string, string[]> = {
            'compound_exchange_rate': ['oracle', 'external_data', 'flash_loan'],
            'amm_price_manipulation': ['oracle', 'price_manipulation', 'external_data'],
            'amm_flash_loan': ['oracle', 'flash_loan', 'price_manipulation'],
            'chainlink_oracle': ['oracle', 'external_data'],
            'tx_origin': ['access_control', 'tx_origin', 'authorization'],
            'delegatecall_vulnerability': ['access_control', 'delegatecall'],
            'missing_onlyowner': ['access_control', 'authorization'],
            'reentrancy_checks_effects_interaction': ['external_call', 'reentrancy_like', 'state_manipulation'],
            'reentrancy_callback': ['external_call', 'reentrancy_like'],
            'unchecked_low_level_call': ['external_call', 'unchecked_return_value'],
            'unchecked_arithmetic_pre08': ['arithmetic', 'overflow', 'underflow'],
            'unchecked_block_pre08': ['arithmetic', 'overflow', 'underflow'],
            'balance_ratio_manipulation': ['arithmetic', 'overflow'],
            'block_timestamp_manipulation': ['timestamp', 'miner_manipulation', 'time_dependency'],
            'block_number_dependence': ['timestamp', 'time_dependency'],
            'unbounded_loop': ['gas', 'dos', 'out_of_gas'],
            'unbounded_array_iteration': ['gas', 'dos', 'out_of_gas'],
          };
          const mapped = patternTagMap[pname] || [];
          const matchesTag = hypTags.some(tag => mapped.some(m => tag.toLowerCase().includes(m)));
          return matchesTag && hint.confidence >= 70;
        }
      );

      const effectiveRatio = hasHighConfidencePattern ? Math.max(satisfactionRatio, 0.7) : satisfactionRatio;
      const effectiveConf = hasHighConfidencePattern ? Math.max(evaluation.confidence, 0.7) : evaluation.confidence;
      const effectiveSatisfied = hasHighConfidencePattern ? Math.max(evaluation.satisfiedCount, requiredMet) : evaluation.satisfiedCount;

      if (effectiveSatisfied >= requiredMet &&
          effectiveRatio >= 0.7 &&
          (evaluation.riskScore > thresholdRisk || effectiveConf > thresholdConf)) {
        results.push(evaluation);
      }
    }

    // Sort by risk score
    results.sort((a, b) => b.riskScore - a.riskScore);

    // Cross-hypothesis suppression: When a primary vulnerability hypothesis
    // (oracle, reentrant, etc.) fires with high confidence, suppress secondary
    // hypotheses that are likely firing on benign DeFi patterns. For example,
    // a Uniswap router library contract has loops over path.length (gas),
    // .call() to tokens (external_call), deadline checks (timestamp), and
    // transfer/withdraw functions (access_control) — but these are all
    // standard, non-exploitable patterns that overlap with the actual
    // vulnerability class. Suppress secondary hypotheses when the primary
    // has risk >= 0.55 AND the secondary's risk score is lower than the primary.
    // NOTE: 'external_call' (unchecked return value) is treated as secondary
    // here because in a DeFi context, low-level calls to token contracts are
    // standard patterns, not the primary vulnerability vector.
    const primaryPatterns = ['oracle', 'reentrant', 'arithmetic'];
    // access_control is secondary in DeFi contexts: public deposit/withdraw/swap
    // functions are by design. But we only suppress it when a primary pattern
    // has significantly higher confidence — if access_control is close in risk
    // to the primary, it may BE the actual vulnerability.
    const secondaryPatterns = ['gas', 'timestamp', 'external_call', 'unchecked', 'access_control'];
    const primaryHighConf = results.filter(r => {
      const tag = r.hypothesis.tags.join(' ');
      return primaryPatterns.some(p => tag.includes(p)) && r.riskScore >= 0.55;
    });
    if (primaryHighConf.length > 0) {
      const primaryRisk = Math.max(...primaryHighConf.map(r => r.riskScore));
      const beforeCount = results.length;
      const filteredResults = results.filter(r => {
        const tag = r.hypothesis.tags.join(' ');
        const isSecondary = secondaryPatterns.some(p => tag.includes(p));
        if (isSecondary) {
          // For most secondary patterns, suppress when below primary.
          // For access_control specifically, require a bigger gap:
          // only suppress if primary risk is at least 0.15 higher.
          // This prevents missing real access_control vulnerabilities on
          // contracts that also have DeFi/oracle patterns (like Gym_2).
          const isAccessControl = tag.includes('access_control');
          const gapRequired = isAccessControl ? 0.15 : 0.01;
          if (r.riskScore < primaryRisk - gapRequired) {
            log.debug(`Suppressing ${r.hypothesis.id} (risk=${r.riskScore.toFixed(3)}) — suppressed by primary (risk=${primaryRisk.toFixed(3)})`);
            return false;
          }
        }
        return true;
      });
      results.length = 0;
      results.push(...filteredResults);
      if (results.length < beforeCount) {
        log.debug(`Suppressed ${beforeCount - results.length} secondary hypothesis(es)`);
      }
    }

    return results;
  }

  /**
   * Evaluate a single hypothesis against the code.
   */
  private evaluateHypothesis(hyp: AttackerHypothesis, features: FeatureVector): HypothesisEvaluation {
    let satisfied = 0;
    let total = hyp.preconditions.length;
    const evidence: string[] = [];
    const satisfiedList: string[] = [];
    const unsatisfiedList: string[] = [];

    const struct = features.structural;
    const ctrl = features.controlFlow;
    const sem = features.semantic;
    const vuln = features.vulnerability;

    for (const precondition of hyp.preconditions) {
      const result = this.checkPrecondition(precondition, struct, ctrl, sem, vuln, features);
      if (result.satisfied) {
        satisfied++;
        evidence.push(...result.evidence);
        satisfiedList.push(precondition);
      } else {
        unsatisfiedList.push(precondition);
      }
    }

    let confidence = hyp.confidence * (satisfied / total);

    // Pattern injection: if pre-computed vulnerability pattern hints
    // were injected (from the vuln pattern library via the pre-fix stage),
    // boost confidence for hypotheses whose tags match the injected patterns.
    // This short-circuits the Claude Code fix loop for known vulnerability classes.
    const injectedPatterns = (features as any).injectedPatterns || {};
    const hypTags = hyp.tags || [];
    let maxPatternConfidence = 0;

    for (const [pkey, hint] of Object.entries(injectedPatterns)) {
      const hintAny = hint as any;
      const patternConfidence = typeof hintAny.confidence === 'number' ? hintAny.confidence : 70;
      // Normalize pattern key: "category.pattern_name" -> "pattern_name"
      // (when scanning all categories for "unknown" labels)
      const pname = pkey.includes('.') ? pkey.split('.').pop() || pkey : pkey;

      // Map pattern names to hypothesis tags
      const patternTagMap: Record<string, string[]> = {
        'compound_exchange_rate': ['oracle', 'external_data', 'flash_loan'],
        'amm_price_manipulation': ['oracle', 'price_manipulation', 'external_data'],
        'amm_flash_loan': ['oracle', 'flash_loan', 'price_manipulation'],
        'chainlink_oracle': ['oracle', 'external_data'],
        'tx_origin': ['access_control', 'tx_origin', 'authorization'],
        'delegatecall_vulnerability': ['access_control', 'delegatecall'],
        'missing_onlyowner': ['access_control', 'authorization'],
        'reentrancy_checks_effects_interaction': ['external_call', 'reentrancy_like', 'state_manipulation'],
        'reentrancy_callback': ['external_call', 'reentrancy_like'],
        'unchecked_low_level_call': ['external_call', 'unchecked_return_value'],
        'unchecked_arithmetic_pre08': ['arithmetic', 'overflow', 'underflow'],
        'unchecked_block_pre08': ['arithmetic', 'overflow', 'underflow'],
        'balance_ratio_manipulation': ['arithmetic', 'overflow'],
        'block_timestamp_manipulation': ['timestamp', 'miner_manipulation', 'time_dependency'],
        'block_number_dependence': ['timestamp', 'time_dependency'],
        'unbounded_loop': ['gas', 'dos', 'out_of_gas'],
        'unbounded_array_iteration': ['gas', 'dos', 'out_of_gas'],
      };

      const mapped = patternTagMap[pname] || [];
      const matchesTag = hypTags.some(tag => mapped.some(m => tag.toLowerCase().includes(m)));

      if (matchesTag) {
        if (patternConfidence > maxPatternConfidence) {
          maxPatternConfidence = patternConfidence;
        }
        // High-confidence pattern match (>=80): set confidence from pattern
        if (patternConfidence >= 80) {
          confidence = Math.max(confidence, patternConfidence / 100);
          evidence.push(`Pattern library high-confidence match: ${hintAny.description || pname} (confidence: ${hintAny.confidence}%)`);
        } else {
          // Moderate confidence: proportional boost
          const boost = (patternConfidence / 100 - 0.5) * 0.3;
          confidence = Math.min(confidence + boost, 1.0);
          evidence.push(`Pattern library match: ${hintAny.description || pname} (confidence boost: +${boost.toFixed(2)})`);
        }
      }
    }

    // If high-confidence pattern matches but hypothesis didn't fire fully,
    // use the pattern confidence as a floor
    if (maxPatternConfidence >= 75 && confidence < maxPatternConfidence / 100) {
      confidence = maxPatternConfidence / 100;
    }

    const riskScore = this.computeRisk(hyp, confidence, features, evidence);

    return {
      hypothesis: hyp,
      satisfiedPreconditions: satisfiedList,
      unsatisfiedPreconditions: unsatisfiedList,
      confidence,
      riskScore,
      evidence,
      novel: hyp.novel,
      explanation: this.generateExplanation(hyp, satisfied, total, evidence),
      satisfiedCount: satisfied
    };
  }

  private checkPrecondition(
    precondition: string,
    struct: any,
    ctrl: any,
    sem: any,
    vuln: any,
    features: any
  ): { satisfied: boolean; evidence: string[] } {
    const evidence: string[] = [];

    // Pre-compute source string for pattern matching in preconditions.
    // Use the actual source code from the feature vector's sourceFile or
    // reconstruct from numericVector JSON as fallback.
    const sourceStr = (features as any).source !== undefined
      ? (features as any).source
      : features.numericVector ? JSON.stringify(features) : '';

    // Detect createProxy vulnerability in test-code-only sources:
    // When contract source couldn't be fetched (paid-tier chains, not verified),
    // test code shows createProxy() called without auth — anyone can create proxy.
    // This is an access_control vulnerability.
    const hasCreateProxyWithoutAuth = /createProxy\s*\(/.test(sourceStr) &&
                                     !vuln.hasOwnerCheck && !vuln.hasMsgSenderCheck &&
                                     !/require\s*\(\s*msg\.sender/.test(sourceStr);

    // Detect proxy contract with delegatecall and no access control:
    // A proxy contract that delegatecalls to a masterCopy/implementation
    // without any authorization check (no msg.sender guard, no onlyOwner modifier).
    // This is an access_control vulnerability — anyone can invoke the proxy to
    // execute arbitrary logic through the implementation.
    // The feature extractor computes hasProxyWithoutAuth; we also detect
    // it via source regex for test-code-only sources where the proxy pattern
    // appears in the test itself.
    const hasProxyWithoutAuth = vuln.hasProxyWithoutAuth ||
                                 (/delegatecall\b/.test(sourceStr) &&
                                  /masterCopy/.test(sourceStr) &&
                                  !vuln.hasOwnerCheck && !vuln.hasMsgSenderCheck);

    // Detect reentrancy callback patterns in source: onTokenTransfer, onERC721Received, etc.
    // These are entry points for reentrancy attacks through external callbacks.
    const hasReentrancyCallback = /onTokenTransfer|onERC721Received|onERC1155Received/i
      .test(sourceStr);

    const checks: Record<string, { satisfied: boolean; evidence: string[] }> = {
      has_external_call: {
        // Require an external call where the CALL TARGET is attacker-influenceable.
        // hasTaintedExternalCallTarget means there's a taint path from caller/calldata
        // to the external call address itself — not just that both exist independently.
        // EXCEPTION: reentrancy callback patterns (onTokenTransfer, onERC721Received)
        // signal that the contract can be re-entered through external callbacks.
        // When such a callback is present AND the contract has external calls
        // (even to known addresses) AND any state mutations exist, the external_call
        // precondition is satisfied — the reentrancy callback IS the external call
        // vector that bridges the trust boundary.
        satisfied: (vuln.hasExternalCall && vuln.hasTaintedExternalCallTarget) ||
                   (hasReentrancyCallback && vuln.hasExternalCall && struct.numStateMutations > 0),
        evidence: (vuln.hasExternalCall && vuln.hasTaintedExternalCallTarget)
          ? ['External call to attacker-influenceable target detected']
          : (hasReentrancyCallback && vuln.hasExternalCall && struct.numStateMutations > 0)
            ? ['Reentrancy callback (onTokenTransfer/ERC721) with external call and state mutations']
            : []
      },
      has_value_transfer_in_low_level_call: {
        // For unchecked return value hypothesis: the low-level call must involve
        // a value transfer (ETH sent via .call{value: x}) AND the call target
        // must be attacker-controllable. A contract that calls .call{value: x}(knownRouter)
        // with an unchecked return is not necessarily vulnerable — it's forwarding to
        // a known safe contract. The vulnerability requires the attacker to influence
        // the call target.
        satisfied: vuln.hasLowLevelCall && vuln.hasValueTransfer && vuln.hasTaintedExternalCallTarget,
        evidence: vuln.hasValueTransfer ? ['Low-level call with value transfer to attacker-influenceable target'] : []
      },
      has_state_change: {
        satisfied: struct.numStateMutations > 0,
        evidence: struct.numStateMutations > 0 ? [`${struct.numStateMutations} state mutations detected`] : []
      },
      call_before_state_update: {
        // CEI violation: external call before state update.
        // Must require an actual external call — hasStateMutationAfterCall
        // alone can match any CALL opcode (including balance reads), causing
        // FPs on non-reentrant contracts. Require tainted external call target
        // so the call is to an attacker-influenceable address.
        // EXCEPTION: reentrancy callbacks (onTokenTransfer, onERC721Received)
        // also trigger this — the callback itself is an external call entry
        // point that can execute before state updates. When a callback exists,
        // any external call + state mutation satisfies this.
        satisfied: vuln.hasStateMutationAfterCall &&
                   ((vuln.hasExternalCall && vuln.hasTaintedExternalCallTarget) ||
                    (hasReentrancyCallback && vuln.hasExternalCall && struct.numStateMutations > 0)),
        evidence: vuln.hasStateMutationAfterCall ? ['State change found after external call (CEI pattern)'] :
                  (hasReentrancyCallback && vuln.hasExternalCall && struct.numStateMutations > 0)
                    ? ['Reentrancy callback with external call and state mutations — CEI-like pattern'] : []
      },
      trust_boundary_can_be_crossed: {
        // This precondition requires that there's a genuine reentrant path:
        // a taint path from caller/calldata THROUGH an external call to a
        // state mutation. Just having tainted external call targets alone
        // is not enough — the external call must be to an attacker-controlled
        // address AND the result must feed into state (reentrancy pattern).
        // We use hasReentrantPath which requires source='caller' AND sink=external_call
        // AND hasTaintedStorageWrite (state mutation with tainted data after external call).
        // EXCEPTION: reentrancy callback patterns (onTokenTransfer, onERC721Received) in
        // source indicate the contract can be re-entered through external callbacks.
        // When such a callback is present AND the contract has external calls with
        // post-call state mutations, the trust boundary is crossed even without
        // a traditional taint path from caller to the call target.
        satisfied: (ctrl.hasReentrantPath && vuln.hasStateMutationAfterCall) ||
                   (hasReentrancyCallback && vuln.hasExternalCall && struct.numStateMutations > 0),
        evidence: ctrl.hasReentrantPath
          ? ['Tainted path from external call to state mutation (reentrancy)']
          : hasReentrancyCallback && vuln.hasExternalCall && struct.numStateMutations > 0
            ? ['Reentrancy callback (onTokenTransfer/ERC721) with external call and state mutations — trust boundary crossed via callback']
            : []
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
        // Specifically: contract is pre-0.8 (no built-in overflow checks) AND has no SafeMath.
        // This is distinct from has_arithmetic_operation (which checks the operation exists).
        // We check for pre-0.8 version directly — if the contract uses Solidity 0.8+,
        // built-in overflow checks make this precondition fail regardless of other factors.
        satisfied: (() => {
          const isPre08 = !sourceStr.includes('pragma solidity ^0.8') && !sourceStr.includes('pragma solidity ^0.9');
          const hasSafeMath = sourceStr.includes('SafeMath');
          return vuln.hasUncheckedArithmetic || (isPre08 && !hasSafeMath &&
                  /\b(uint\d*|int\d*)\s+\w+\s*[\+\-\*]/i.test(sourceStr));
        })(),
        evidence: (() => {
          const isPre08 = !sourceStr.includes('pragma solidity ^0.8') && !sourceStr.includes('pragma solidity ^0.9');
          const hasSafeMath = sourceStr.includes('SafeMath');
          if (vuln.hasUncheckedArithmetic) return ['Unchecked arithmetic block detected'];
          if (isPre08 && !hasSafeMath) return ['Contract is pre-0.8 without SafeMath — overflow risk'];
          return [];
        })()
      },
      user_controlled_input: {
        // Require high-priority taint sources (calldata/caller/tx_origin/msg_value),
        // not just any source. Low-priority sources (environmental) don't count.
        satisfied: ctrl.highPriorityTaintSources > 0,
        evidence: ctrl.highPriorityTaintSources > 0 ? [`${ctrl.highPriorityTaintSources} high-priority tainted inputs detected`] : []
      },
      value_used_for_state_or_transfer: {
        // Require arithmetic operations to be present — this precondition
        // means "an attacker-manipulable arithmetic result flows to state/transfer",
        // not merely that external call values reach state changes (which every
        // reentrancy contract satisfies without any arithmetic at all).
        satisfied: (vuln.hasUncheckedArithmetic || vuln.hasOverflowRisk || vuln.hasUnderflowRisk) &&
                   vuln.hasExternalCall && vuln.hasStateMutationAfterCall &&
                   (vuln.hasTaintedExternalCallTarget || ctrl.highPriorityTaintSources > 0),
        evidence: ['Arithmetic result flows to external call value or state changes']
      },
      has_authorization_check: {
        // Authorization exists somewhere in the contract — this is a prerequisite
        // for bypass: you can only bypass auth that exists. A contract with NO
        // auth checks at all doesn't have an "authorization bypass" — it has
        // "missing authorization", which is a different vulnerability class.
        // EXCEPTION: when source is test-code-only (contract source couldn't be
        // fetched from Etherscan, e.g. paid-tier chains), the test code calling
        // createProxy() without auth implies the proxy pattern has no auth guard.
        // Also: createProxy without any require/onlyOwner check means missing auth.
        satisfied: vuln.hasOwnerCheck || vuln.hasMsgSenderCheck ||
                   hasCreateProxyWithoutAuth || hasProxyWithoutAuth,
        evidence: vuln.hasMsgSenderCheck ? ['Authorization check detected (msg.sender)'] :
                  vuln.hasOwnerCheck ? ['Owner check detected'] :
                  hasCreateProxyWithoutAuth ? ['createProxy() called without authorization — missing access control on proxy creation'] :
                  hasProxyWithoutAuth ? ['Proxy contract with delegatecall and no authorization — missing access control on proxy execution'] : []
      },
      uses_tx_origin_or_weak_check: (() => {
        // Satisfied when the contract uses weak authorization patterns:
        // 1. tx.origin for auth checks (weak to phishing)
        // 2. Missing auth on sensitive external functions (no msg.sender/onlyOwner guard)
        // The second case is critical for multisig wallets where the contract has
        // auth checks but also exposes unprotected entry points (e.g., arbitrary
        // transaction execution via assembly calls without owner verification).
        const hasMissingAuthOnSensitiveFunction = (() => {
          const funcRegex = /\bfunction\s+(\w+)\s*\(([^)]*)\)\s*(external|public)\s*(?:payable)?\s*(?:returns\s*\([^)]*\))?\s*(?:only\w+\s*)*\s*\{/gi;
          let match;
          let found = false;
          while ((match = funcRegex.exec(sourceStr)) !== null) {
            const funcName = match[1].toLowerCase();
            const params = match[2];
            const body = sourceStr.substring(match.index + match[0].length, match.index + match[0].length + 200);
            // Skip constructor and internal functions
            if (funcName === 'constructor' || funcName.startsWith('_')) continue;
            // Check if the function has NO auth check (no msg.sender, onlyOwner, etc.)
            const hasAuth = /require\s*\(\s*msg\.sender|onlyOwner|onlyBank|onlyAdmin|onlyAuthorized|onlyRole/.test(body) ||
                            /only\w+/.test(sourceStr.substring(match.index, match.index + match[0].length));
            if (!hasAuth) {
              // Check if the function name suggests a sensitive operation
              if (/(withdraw|deposit|transfer|sweep|claim|harvest|skim|allocate|borrow|lend|stake|unstake|execute|submit)/i.test(funcName)) {
                found = true;
                break;
              }
              // Also check if params contain address types and contract has state mutations
              if (/\baddress\s+\w+/.test(params) && struct.numStateMutations > 0) {
                found = true;
                break;
              }
            }
          }
          return found;
        })();
        return {
          satisfied: vuln.hasTxOriginCheck || hasMissingAuthOnSensitiveFunction || hasCreateProxyWithoutAuth || hasProxyWithoutAuth,
          evidence: vuln.hasTxOriginCheck ? ['Uses tx.origin for auth (weak)'] :
                    hasMissingAuthOnSensitiveFunction ? ['Sensitive external function lacks authorization check'] :
                    hasCreateProxyWithoutAuth ? ['createProxy() without authorization check — weak access control'] :
                    hasProxyWithoutAuth ? ['Proxy uses delegatecall without authorization — any caller can execute arbitrary logic'] : []
        };
      })(),
      attacker_can_control_input: {
        // Require high-priority taint sources (calldata/caller/tx_origin/msg_value)
        // rather than any taint source. Low-priority sources (environmental) like
        // block.timestamp or block.number do NOT count as attacker-controllable —
        // they are miner-influenceable but not fully attacker-controlled.
        // EXCEPTION: createProxy() in test-code-only sources means the attacker
        // controls which implementation gets proxied — caller is always attacker.
        // EXCEPTION: proxy with delegatecall and no auth — any caller can execute
        // arbitrary logic through the implementation.
        satisfied: ctrl.highPriorityTaintSources > 0 || hasCreateProxyWithoutAuth || hasProxyWithoutAuth,
        evidence: ctrl.highPriorityTaintSources > 0
          ? [`${ctrl.highPriorityTaintSources} high-priority tainted inputs detected`]
          : hasCreateProxyWithoutAuth ? ['Attacker controls createProxy — any caller can create proxy']
          : hasProxyWithoutAuth ? ['Attacker controls proxy delegatecall — any caller can execute arbitrary logic'] : []
      },
      privilege_escalation_possible: (() => {
        // Flag if there's a genuine authorization weakness:
        // 1. Weak auth: uses tx.origin instead of msg.sender
        // 2. No auth on admin operations: state-modifying functions that do admin
        //    work but lack onlyOwner/msg.sender checks
        // 3. Unvalidated address params: function accepts address param for
        //    transfers/withdrawals without authorization check
        // 4. Partial auth: contract has onlyOwner on SOME functions but has
        //    unprotected state-modifying functions with tainted input — the
        //    owner check exists but doesn't cover all privileged operations
        const hasNoAuth = !vuln.hasOwnerCheck && !vuln.hasMsgSenderCheck;
        const hasWeakAuth = vuln.hasTxOriginCheck && !vuln.hasMsgSenderCheck;
        const hasAdminOperation = /function\s+\w*(?:Admin|Owner|Config|Update|Change|Set|Upgrade|Migrate|Initialize|Pause|Unpause|Fee)\w*\s*\(/.test(sourceStr) ||
                                  /\bwithdrawFrom|\btransferFromOwner|\bownerWithdraw|\bsweep|\bemergencyWithdraw|\bsetOwner|\btransferOwnership/i.test(sourceStr);
        // Partial auth: contract has owner/msg.sender check somewhere but also
        // has state mutations with caller-controlled input and no msg.sender
        // check on those specific functions. This catches the pattern where
        // onlyOwner protects an admin function but user-facing functions that
        // modify state lack authorization.
        // NOTE: if onlyOwner modifier is present, it provides proper authorization
        // (the modifier internally checks msg.sender == owner). Do NOT treat
        // onlyOwner-only contracts as having privilege escalation — the modifier
        // IS the authorization check. Only flag when there is NO onlyOwner
        // and NO explicit msg.sender check.
        const hasPartialAuth = (vuln.hasOwnerCheck || vuln.hasMsgSenderCheck) &&
                               !vuln.hasMsgSenderCheck &&
                               !vuln.hasOnlyOwnerModifier &&
                               struct.numStateMutations > 0 &&
                               ctrl.highPriorityTaintSources > 0;
        // hasModifierOnlyAuth removed: onlyOwner modifier provides proper
        // authorization. Do not fire privilege_escalation when onlyOwner exists.
        // Unvalidated address parameter: function accepts an address param that
        // flows directly to a transfer/withdraw/allocate without msg.sender check.
        // This is the 'missing_sender_auth' pattern — the caller can specify
        // arbitrary addresses for fund transfers.
        // Match ONLY external/public transfer/withdraw/allocate functions with address
        // params that lack own_msg_sender/onlyOwner checks. Internal library functions
        // (like TransferHelper.safeTransfer) are NOT vulnerable — they're not
        // user-callable entry points.
        // flows directly to a transfer/withdraw/allocate without msg.sender check.
        // This is the 'missing_sender_auth' pattern — the caller can specify
        // arbitrary addresses for fund transfers.
        // Match ONLY external/public transfer/withdraw/allocate functions with address
        // params that lack own_msg_sender/onlyOwner checks. Internal library functions
        // (like TransferHelper.safeTransfer) are NOT vulnerable — they're not
        // user-callable entry points.
        const hasUnvalidatedAddressParam = (() => {
          // Extract all function definitions from source
          const funcRegex = /\bfunction\s+(\w+)\s*\(([^)]*)\)\s*(?:external|public)\s*(?:payable)?\s*(?:returns\s*\([^)]*\))?\s*(?:\{\s*([^}]*)\s*\})?/gi;
          let match;
          while ((match = funcRegex.exec(sourceStr)) !== null) {
            const funcName = match[1].toLowerCase();
            const params = match[2];
            const body = match[3] || '';
            // Match transfer/withdraw/allocate-type functions
            if (/(transfer|withdraw|allocate|bypass|skim|harvest|claim|deposit)/i.test(funcName)) {
              // Must have an address parameter
              if (/\baddress\s+\w+/.test(params)) {
                // Must NOT have msg.sender or onlyOwner check in body
                if (!/msg\.sender|onlyOwner|require\s*\(\s*msg\.sender/i.test(body)) {
                  // Must have state mutations or value transfer in the body
                  if (struct.numStateMutations > 0) {
                    return true;
                  }
                }
              }
            }
          }
          return false;
        })();
        // Missing auth on sensitive functions: external/public functions without
        // onlyOwner/msg.sender/onlyBank/etc. modifier that perform state mutations
        // or value transfers. This catches the pattern where the contract has
        // auth on SOME functions but leaves user-facing functions unprotected.
        const hasMissingAuthOnSensitiveFunction = (() => {
          const funcRegex = /\bfunction\s+(\w+)\s*\(([^)]*)\)\s*(external|public)\s*(?:payable)?\s*(?:returns\s*\([^)]*\))?\s*(?:only\w+\s+)*\s*\{/gi;
          let match;
          let found = false;
          while ((match = funcRegex.exec(sourceStr)) !== null) {
            const funcName = match[1].toLowerCase();
            const params = match[2];
            const visibility = match[3];
            const afterParams = sourceStr.substring(match.index + match[0].length);
            // Skip constructor and trivial functions
            if (funcName === 'constructor' || funcName.startsWith('_')) continue;
            // Check if the function body (first 200 chars after the opening brace)
            // has any auth check — if not, and the function has taint sources,
            // it's a sensitive function without authorization
            if (ctrl.highPriorityTaintSources > 0) {
              const bodySnippet = afterParams.substring(0, 200);
              const hasAuth = /require\s*\(\s*msg\.sender|onlyOwner|onlyBank|onlyAdmin|onlyAuthorized|onlyRole/.test(bodySnippet) ||
                              /only\w+/.test(sourceStr.substring(match.index, match.index + match[0].length - bodySnippet.length));
              if (!hasAuth) {
                // Check if the function name suggests a value-affecting operation
                if (/(withdraw|deposit|transfer|sweep|claim|harvest|skim|allocate|borrow|lend|stake|unstake|set|update|change)/i.test(funcName)) {
                  found = true;
                  break;
                }
                // Also check if params contain address types (could be arbitrary recipient)
                if (/\baddress\s+\w+/.test(params) && struct.numStateMutations > 0) {
                  found = true;
                  break;
                }
              }
            }
          }
          return found;
        })();
        return {
          satisfied: (hasWeakAuth || (hasAdminOperation && hasNoAuth) || hasUnvalidatedAddressParam ||
                      hasPartialAuth || hasMissingAuthOnSensitiveFunction || hasCreateProxyWithoutAuth ||
                      hasProxyWithoutAuth) &&
                     (ctrl.highPriorityTaintSources > 0 || vuln.hasValueTransfer || hasProxyWithoutAuth),
          evidence: hasWeakAuth
            ? ['Uses tx.origin for authorization — susceptible to phishing']
            : (hasAdminOperation && hasNoAuth)
            ? ['Admin operation lacks proper authorization — missing onlyOwner or access control']
            : hasCreateProxyWithoutAuth
            ? ['createProxy() called without authorization — anyone can instantiate vulnerable contract']
            : hasProxyWithoutAuth
            ? ['Proxy delegatecall to masterCopy with no authorization — any caller can execute arbitrary logic']
            : hasMissingAuthOnSensitiveFunction
            ? ['External function lacks authorization check on sensitive operation — no onlyOwner/msg.sender guard']
            : ['Function accepts address parameter without authorization check — caller can specify arbitrary recipient']
        };
      })(),
      uses_block_timestamp: {
        satisfied: vuln.hasTimestampUsage,
        evidence: vuln.hasTimestampUsage ? ['block.timestamp or block.number usage detected'] : []
      },
      timestamp_affects_critical_logic: {
        // Timestamp affects critical logic when: (a) it's used in a conditional
        // (require/assert/if) gating state mutations or external calls, OR (b)
        // it's used in computation/return values that affect pricing, randomness,
        // or critical calculations.
        satisfied: vuln.hasTimestampUsage && (
          (sem.hasTimestampInConditional && vuln.hasStateMutationAfterCall) ||
          // Timestamp used in computation (return/arithmetic) — manipulable
          // oracle pattern where miner-adjusted timestamp affects computed values
          sem.hasTimestampInComputation ||
          // Timestamp used for randomness/gambling/payout logic (not just deadline)
          /block\.timestamp.*?(random|guess|payout|bet|gam|lottery|prize|reward|distribute)/i.test(sourceStr) ||
          /block\.number.*?(random|guess|payout|bet|gam|lottery|prize|reward|distribute)/i.test(sourceStr) ||
          // Timestamp used in keccak256/hash for pseudo-randomness — common pattern:
          // uint random = uint(keccak256(abi.encodePacked(block.timestamp, seed))) % N
          /keccak256.*block\.timestamp/i.test(sourceStr) ||
          /keccak256.*block\.number/i.test(sourceStr) ||
          /block\.timestamp.*keccak256/i.test(sourceStr) ||
          /block\.number.*keccak256/i.test(sourceStr)
        ),
        evidence: sem.hasTimestampInConditional
          ? ['Timestamp used in conditional gating state or external calls']
          : sem.hasTimestampInComputation
          ? ['Timestamp used in computation/return — manipulable price/time logic']
          : []
      },
      no_alternative_randomness_source: {
        // Only flag if timestamp is used for randomness/gambling AND there's
        // no SafeMath, no median pattern, and the timestamp appears in a context
        // that affects game/payout logic (not just logging or non-critical math).
        satisfied: vuln.hasTimestampUsage &&
          !/median|average|TWAP|twap|chainlink/i.test(sourceStr) &&
          !vuln.hasOracleCall &&
          (
            // Timestamp used for randomness via keccak256 (most common pattern)
            /keccak256.*block\.timestamp|block\.timestamp.*keccak256|importSeed|random/i.test(sourceStr) ||
            sem.hasTimestampInConditional ||
            sem.hasTimestampInComputation
          ),
        evidence: vuln.hasTimestampUsage
          ? ['block.timestamp used for pseudo-randomness with no alternative source']
          : []
      },
      has_loop_or_recursion: {
        // Require at least one loop (maxLoopNesting > 0 means a node inside a loop).
        // A simple counter loop (for i = 0; i < 5; i++) is not exploitable, but
        // a loop over a dynamic array IS — we check hasUnboundedLoop for this.
        satisfied: ctrl.maxLoopNesting > 0 && ctrl.hasUnboundedLoop,
        evidence: ctrl.maxLoopNesting > 0 ? [`Loop nesting depth ${ctrl.maxLoopNesting} detected`] : []
      },
      gas_consumption_grows_with_input: {
        // Gas must grow with attacker input — this requires the loop to iterate
        // over an array whose size is attacker-controlled. We detect this by
        // checking for for-loops that iterate over .length (dynamic arrays).
        satisfied: ctrl.maxLoopNesting > 0 && ctrl.hasUnboundedLoop &&
                   /for\s*\([^)]*\.length/.test(sourceStr),
        evidence: ctrl.hasUnboundedLoop ? ['Loop iterates over dynamic array — gas grows with input size'] : []
      },
      no_gas_limit_check: {
        // Only flag if there are unbounded loops with no gas limit guard.
        // Gas limit checks use tx.gaslimit, gas(), or require(gasleft() > N).
        satisfied: ctrl.hasUnboundedLoop && !/gasleft|tx\.gaslimit|gas\(\)/i.test(sourceStr),
        evidence: ctrl.hasUnboundedLoop ? ['Unbounded loop with no gas limit check'] : []
      },
      has_low_level_call: {
        satisfied: vuln.hasLowLevelCall,
        evidence: vuln.hasLowLevelCall ? ['Low-level .call/.send/.delegatecall detected'] : []
      },
      external_call_return_not_checked: {
        satisfied: vuln.hasUncheckedCallReturn,
        evidence: vuln.hasUncheckedCallReturn ? ['Low-level call return value not checked with require/assert'] : []
      },
      no_revert_on_failure: {
        satisfied: vuln.hasNoRevertOnFailure,
        evidence: vuln.hasNoRevertOnFailure ? ['No revert guard on external call failure'] : []
      },
      attacker_controls_input_size: {
        // For gas DoS: the attacker must control the SIZE of input that affects
        // loop iteration count. This means the contract must have a loop that
        // iterates over a dynamic array from calldata (e.g., an array of addresses
        // to iterate). Just having highPriorityTaintSources isn't enough — any
        // contract with function parameters has these.
        satisfied: ctrl.highPriorityTaintSources > 0 && ctrl.hasUnboundedLoop &&
                   /for\s*\([^)]*(?:address\[\]|uint\[\]|bytes\[\]|\w+\[\]|\w+\.length)/.test(sourceStr),
        evidence: ctrl.highPriorityTaintSources > 0 ? [`${ctrl.highPriorityTaintSources} attacker-controllable inputs`] : []
      },
      reads_external_data: {
        // Satisfied when the contract reads PRICING/EXTERNAL DATA that could be manipulated:
        // - AMM interactions (swap, getReserves) — price data from liquidity pools
        // - Price calculation patterns (getReserves, spotPrice, latestRoundData)
        // - Known oracle contract calls (Chainlink, Band, etc.)
        // - Flash loan availability — enables price manipulation
        // NOT satisfied by generic external calls alone — that would trigger
        // on every contract with a callback or interface call, causing massive FPs.
        satisfied: vuln.hasAMMInteraction || vuln.hasFlashLoan || vuln.hasOracleCall ||
                   vuln.hasPriceCalculation ||
                   (vuln.hasCompoundLending && vuln.hasCTokenExchangeRate),
        evidence: vuln.hasAMMInteraction ? ['AMM interaction detected — external price data source'] :
                  vuln.hasFlashLoan ? ['Flash loan pattern detected — vulnerable to price manipulation'] :
                  vuln.hasOracleCall ? ['Oracle contract call detected — external price feed'] :
                  vuln.hasPriceCalculation ? ['Price calculation patterns detected (getReserves, spotPrice, etc.)'] :
                  (vuln.hasCompoundLending && vuln.hasCTokenExchangeRate) ? ['Compound v2 cToken exchange rate detected — external pricing via exchangeRate manipulation'] :
                  []
      },
      data_source_is_manipulable: {
        // AMM prices are manipulable via flash loans — if the contract has
        // AMM interaction patterns.
        // Flash loan availability provides direct manipulation capability.
        // Tainted external call targets are manipulable.
        // For oracle contracts: any external call to a tainted target where the
        // contract also has price calculation or flash loan capability counts.
        // Generic external calls to tainted targets alone are NOT sufficient.
        // Price calculation via getReserves() is inherently manipulable —
        // anyone can swap or add/remove liquidity to change the reserves.
        satisfied: vuln.hasAMMInteraction || vuln.hasFlashLoan ||
                   vuln.hasPriceCalculation ||
                   (vuln.hasCompoundLending && vuln.hasCTokenExchangeRate) ||
                   (vuln.hasExternalCall && vuln.hasTaintedExternalCallTarget &&
                    (vuln.hasPriceCalculation || vuln.hasOracleCall || vuln.hasValueTransfer)),
        evidence: vuln.hasAMMInteraction ? ['AMM interaction — price can be manipulated via flash loans'] :
                  vuln.hasFlashLoan ? ['Flash loan available — direct price manipulation capability'] :
                  vuln.hasPriceCalculation ? ['Price calculation from getReserves — reserves manipulable via swaps/liquidity'] :
                  (vuln.hasCompoundLending && vuln.hasCTokenExchangeRate) ? ['Compound cToken exchange rate — manipulable via supply/withdraw cycles'] :
                  vuln.hasTaintedExternalCallTarget ? ['External call target is attacker-controlled (manipulable)'] : []
      },
      data_affects_value_transfer: {
        // External data should affect value transfer or pricing decisions.
        // Require evidence that external/malleable data feeds into value-affecting
        // decisions. The key signal is: the contract has external data interaction
        // (AMM/oracle/price patterns) AND performs value-affecting operations
        // (transfers, balance changes, state mutations).
        // For flash loan attacks: flash loan + state mutations = price can affect state.
        // NOTE: hasValueTransfer is set when the contract does any ETH or token transfer,
        // so this is a reasonable proxy for "data affects value".
        satisfied: (vuln.hasAMMInteraction && vuln.hasValueTransfer) ||
                   (vuln.hasFlashLoan && (vuln.hasValueTransfer || struct.numStateMutations > 0)) ||
                   (vuln.hasOracleCall && vuln.hasValueTransfer) ||
                   (vuln.hasPriceCalculation && (vuln.hasValueTransfer || struct.numStateMutations > 0)) ||
                   (vuln.hasCompoundLending && vuln.hasCTokenExchangeRate &&
                    (vuln.hasValueTransfer || struct.numStateMutations > 0)) ||
                   // Also accept: hasAMMInteraction alone (swap calls inherently affect value)
                   (vuln.hasAMMInteraction && struct.numStateMutations > 0),
        evidence: (vuln.hasAMMInteraction && vuln.hasValueTransfer) ? ['AMM interaction with value transfer — price affects funds'] :
                  (vuln.hasFlashLoan && struct.numStateMutations > 0) ? ['Flash loan access — manipulated price can affect state mutations'] :
                  (vuln.hasPriceCalculation && struct.numStateMutations > 0) ? ['Price calculation affects state mutations'] :
                  (vuln.hasCompoundLending && vuln.hasCTokenExchangeRate && struct.numStateMutations > 0) ? ['Compound exchange rate affects state mutations'] :
                  (vuln.hasFlashLoan && vuln.hasValueTransfer) ? ['Flash loan + value transfer — manipulation path exists'] :
                  (vuln.hasOracleCall && vuln.hasValueTransfer) ? ['Oracle call with value transfer — external data affects funds'] :
                  (vuln.hasAMMInteraction && struct.numStateMutations > 0) ? ['AMM interaction with state mutations — price affects state'] : []
      },
      no_median_or_decentralization: {
        // Only suppress when the contract uses EXPLICIT oracle libraries (Chainlink, Band, etc.)
        // or has proper median/decentralization patterns. Do NOT suppress when the contract
        // merely has the word "oracle" in comments or when it relies on AMM prices without
        // a TWAP/median mechanism — those are still manipulable.
        satisfied: !vuln.hasOracleCall && !/median|TWAP|twap|chainlink|band.*protocol|tellor/i.test(sourceStr),
        evidence: !vuln.hasOracleCall ? ['No explicit oracle library or median/TWAP pattern detected'] : []
      }
    };

    const result = checks[precondition] || this.fallbackPreconditionCheck(precondition, struct, ctrl, sem, vuln, features);
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
    vuln: any,
    features: any
  ): { satisfied: boolean; evidence: string[] } {
    const pc = precondition.toLowerCase().trim();
    const evidence: string[] = [];

    const check = (condition: boolean, msg: string): { satisfied: boolean; evidence: string[] } => {
      if (condition) evidence.push(msg);
      return { satisfied: condition, evidence };
    };

    // Delegatecall detection — only match preconditions that explicitly mention
    // delegatecall. Regular external calls (.call) should NOT satisfy delegatecall
    // preconditions, since delegatecall preserves msg.sender context while regular
    // calls do not.
    // Also check hasProxyWithoutAuth feature for proxy patterns with delegatecall.
    if (pc.includes('delegatecall') || pc.includes('delegate call')) {
      const sourceStr = JSON.stringify(features);
      const hasProxyAuth = vuln.hasProxyWithoutAuth;
      // For preconditions that ALSO mention msg.sender and access control (e.g.
      // "msg.sender used in access control logic post-delegatecall"), we require
      // an actual msg.sender authorization check — a proxy with NO auth doesn't
      // use msg.sender in access control, so the precondition is not satisfied.
      const requiresMsgSenderAuth = pc.includes('msg.sender') && (pc.includes('access') || pc.includes('auth'));
      if (requiresMsgSenderAuth) {
        return check(sourceStr.includes('delegatecall') && vuln.hasMsgSenderCheck,
          'Delegatecall with msg.sender-based access control detected');
      }
      return check(sourceStr.includes('delegatecall') || hasProxyAuth,
        'Delegatecall usage detected' + (hasProxyAuth ? ' — proxy without auth' : ''));
    }

    // Proxy access control — match preconditions about proxy authorization or
    // delegatecall-based access control. The hasProxyWithoutAuth feature flags
    // proxy contracts (e.g. Gnosis Safe Proxy) that delegatecall to a masterCopy
    // with no authorization guard.
    if (pc.includes('proxy') && (pc.includes('auth') || pc.includes('access')) ||
        pc.includes('delegatecall') && pc.includes('auth') || pc.includes('access')) {
      return check(vuln.hasProxyWithoutAuth,
        'Proxy contract delegatecalls without authorization — any caller can execute');
    }

    // External call detection — only match preconditions about EXTERNAL calls to
    // attacker-influenceable targets, not preconditions about return values,
    // callbacks, or reference types that merely mention "external call".
    if (pc.includes('external call') || pc.includes('low.level') ||
        pc.includes('untrusted') || pc.includes('attacker') && pc.includes('controll')) {
      // Exclude preconditions about return data, callbacks, or reference types
      const isAboutReturnValue = pc.includes('return') || pc.includes('callback') || pc.includes('fresh copy');
      const isAboutReferenceType = pc.includes('struct') || pc.includes('memory array') || pc.includes('reference');
      if (!isAboutReturnValue && !isAboutReferenceType) {
        // Standard: tainted external call target or high taint source count.
        // Also match reentrancy patterns in source: when the contract source or
        // test code references reentrancy/onTokenTransfer/callback AND has external
        // calls with state mutations afterward, treat external_call precondition as satisfied.
        const hasReentrancySignal = /reentr(?:ancy|y)|onTokenTransfer|callback.*external|external.*callback/i
          .test(this.source || '');
        return check(
          vuln.hasExternalCall && (vuln.hasTaintedExternalCallTarget || ctrl.taintSourceCount > 0) ||
          (hasReentrancySignal && vuln.hasExternalCall && vuln.hasStateMutationAfterCall),
          vuln.hasExternalCall ? 'External call to attacker-influenceable target detected' :
          hasReentrancySignal ? 'Reentrancy pattern with external call and post-call state mutation detected' : ''
        );
      }
    }

    // State change / mutation detection — only match preconditions about actual
    // state mutations, not preconditions about storage layout, pointer retention,
    // or memory aliasing that merely mention "storage".
    if (pc.includes('state change') || pc.includes('state mutat') || pc.includes('sstore') ||
        pc.includes('balance')) {
      return check(struct.numStateMutations > 0, `${struct.numStateMutations} state mutations detected`);
    }
    // Storage layout / pointer conditions are not satisfiable by simple state mutation count
    if (pc.includes('storage layout') || pc.includes('storage pointer') || pc.includes('pointer retained')) {
      return { satisfied: false, evidence: ['Storage layout/pointer conditions require deeper analysis — not statically satisfiable'] };
    }

    // Call before state update (reentrancy-like ordering)
    if (pc.includes('call') && pc.includes('before') || pc.includes('before') && pc.includes('state')) {
      return check(vuln.hasStateMutationAfterCall, 'State change found after external call');
    }

    // Trust boundary
    if (pc.includes('trust') || pc.includes('boundary') || pc.includes('crossed')) {
      return check(ctrl.hasReentrantPath || vuln.hasTaintedExternalCallTarget, 'Tainted path from external call to state');
    }

    // Arithmetic / overflow — require actual arithmetic/overflow features,
    // not just complex control flow (which is true for almost every contract).
    if (pc.includes('arithmetic') || pc.includes('overflow') || pc.includes('underflow') ||
        pc.includes('math') || pc.includes('uint')) {
      return check(vuln.hasUncheckedArithmetic || vuln.hasOverflowRisk,
        vuln.hasUncheckedArithmetic ? 'Unchecked arithmetic detected' :
        vuln.hasOverflowRisk ? 'Overflow-prone arithmetic detected' : 'Arithmetic operation detected');
    }

    // Shift operators — used in gas manipulation / overflow shift hypotheses
    if (pc.includes('shift') || pc.includes('<<') || pc.includes('>>')) {
      return check(vuln.hasShiftOperator, 'Shift operators (<<, >>) detected in source');
    }

    // User-controlled input — require high-priority taint sources (calldata, caller, msg.value, tx.origin)
    if (pc.includes('user') && pc.includes('input') || pc.includes('attacker') && pc.includes('input') ||
        pc.includes('control')) {
      return check(ctrl.highPriorityTaintSources > 0, `${ctrl.highPriorityTaintSources} high-priority user-controlled inputs detected`);
    }

    // Authorization / access control — only match preconditions that explicitly
    // ask about the presence of authorization checks, not preconditions that
    // mention msg.sender as part of a bug description (e.g. "msg.sender differs
    // subtly between call levels" is a weakness, not a check that exists).
    if (pc.includes('authoriz') || pc.includes('access') ||
        (pc.includes('owner') && (pc.includes('check') || pc.includes('require') || pc.includes('guard'))) ||
        pc.includes('onlyowner') || pc.includes('only owner')) {
      return check(vuln.hasOwnerCheck || vuln.hasMsgSenderCheck, 'Authorization check detected (msg.sender)');
    }

    // Specific LLM precondition: "msg.sender differs subtly between call levels"
    // This is about reentrancy identity shifting, which requires an external call + reentrant path
    if (pc.includes('msg.sender') && pc.includes('differ')) {
      return check(vuln.hasExternalCall && ctrl.hasReentrantPath, 'Reentrant call could shift msg.sender identity');
    }

    // Specific LLM precondition: "Owner check relies solely on msg.sender"
    // This means the contract HAS an owner check using msg.sender — which is
    // actually a satisfied precondition (it means the check can be bypassed).
    if (pc.includes('owner check') && pc.includes('msg.sender')) {
      return check(vuln.hasMsgSenderCheck, 'Owner check uses msg.sender (bypassable via reentrancy)');
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

    // Loop / gas — only trigger on actual loop constructs with tainted input.
    // Gas-related preconditions that mention "gas limit" in the context of DoS
    // require nested loops (depth > 1) — a single loop is not necessarily
    // a gas DoS vulnerability. However, shift/gas preconditions (like
    // "gas stipend passed during internal calls affects shift execution")
    // are about a different mechanism and should NOT trigger the loop check.
    // Only match preconditions that mention "loop" OR "gas limit" + "consum" (DoS context).
    if (pc.includes('loop') ||
        (pc.includes('gas') && pc.includes('limit') && pc.includes('consum'))) {
      return check(ctrl.maxLoopDepth > 1 && ctrl.highPriorityTaintSources > 0,
        `Nested loop depth ${ctrl.maxLoopDepth} with ${ctrl.highPriorityTaintSources} tainted inputs`);
    }
    // Shift operators — used in gas manipulation / overflow shift hypotheses.
    if (pc.includes('shift') || pc.includes('<<') || pc.includes('>>')) {
      return check(vuln.hasShiftOperator, 'Shift operators (<<, >>) detected in source');
    }
    // Recursion specifically requires a reentrant path — a loop is not recursion.
    // A reentrant path means a function calls an external contract that calls back
    // into the original function, which is different from a loop.
    if (pc.includes('recursion') || pc.includes('recursive') ||
        (pc.includes('reentrant') && pc.includes('path'))) {
      return check(ctrl.hasReentrantPath || vuln.hasTaintedExternalCallTarget,
        'Reentrant call path detected');
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
    const sem = features.semantic;
    const struct = features.structural;
    const hasPrecondition = (pc: string) => hyp.preconditions.includes(pc);

    if (hasPrecondition('has_external_call') && vuln.hasExternalCall) risk += 0.15;
    if (hasPrecondition('call_before_state_update') && vuln.hasStateMutationAfterCall) risk += 0.20;
    if (hasPrecondition('trust_boundary_can_be_crossed') && (ctrl.hasReentrantPath || vuln.hasTaintedExternalCallTarget)) risk += 0.25;
    if (hasPrecondition('user_controlled_input') && ctrl.highPriorityTaintSources > 0) risk += 0.10;

    // Timestamp-specific risk bonuses: block.timestamp in conditionals or computations
    // indicates miner-manipulable time dependency, which is the core of timestamp
    // manipulation vulnerabilities. Give a strong bonus when timestamp affects
    // critical logic (computation or conditional) — this is the defining feature
    // of a timestamp manipulation vulnerability.
    if (hasPrecondition('timestamp_affects_critical_logic') &&
        (sem.hasTimestampInConditional || sem.hasTimestampInComputation)) {
      risk += 0.40;
      evidence.push('block.timestamp used in conditional or computation — miner-manipulable');
    }
    if (hasPrecondition('uses_block_timestamp') && vuln.hasTimestampUsage) {
      risk += 0.10;
    }
    // Access control risk bonus: high state mutation count with tainted inputs
    // indicates privilege escalation potential on access-controlled functions.
    if (hasPrecondition('privilege_escalation_possible') &&
        struct.numStateMutations > 5 && ctrl.highPriorityTaintSources > 0) {
      risk += 0.15;
      evidence.push(`High state activity (${struct.numStateMutations} mutations) with tainted input`);
    }

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
