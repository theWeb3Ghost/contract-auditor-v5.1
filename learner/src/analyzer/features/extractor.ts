/**
 * Feature Extractor for Solidity Security Analysis.
 *
 * Extracts feature vectors from Solidity source code by combining:
 * 1. AST structural features (function complexity, state mutations)
 * 2. CFG control-flow features (cyclomatic complexity, loop nesting)
 * 3. Taint analysis features (taint paths, reentrancy risk)
 * 4. Semantic pattern features (known vulnerability patterns from solkb)
 * 5. Porosity-X static analysis features (when available)
 *
 * The output is a structured feature vector suitable for input to the
 * Transformer model's feature encoder.
 */

import { ASTSourceUnit, ASTContractDefinition, ASTFunctionDefinition, ASTBlock } from '../ast/types.js';
import { SolidityParser } from '../ast/parser.js';
import { CFG, CFGBuilder } from '../cfg/builder.js';
import { TaintGraph, TaintFeatureVector, TaintLabel } from '../taint/graph.js';
import { readFileSync, existsSync } from 'fs';

// ===========================================================================
// Feature Vector
// ===========================================================================

export interface VulnerabilityPatternFeatures {
  // Reentrancy patterns
  hasExternalCall: boolean;
  hasStateMutationAfterCall: boolean;
  hasChecksEffectsInteractionsViolation: boolean;
  callAfterSstore: boolean;
  sstoreAfterCall: boolean;

  // Taint / input validation
  hasUntaintedExternalCall: boolean;
  hasTaintedExternalCallTarget: boolean;
  hasTaintedExternalCallValue: boolean;
  hasNoInputValidation: boolean;

  // Access control
  hasOwnerCheck: boolean;
  hasOnlyOwnerModifier: boolean;
  hasMsgSenderCheck: boolean;
  hasTxOriginCheck: boolean;

  // Arithmetic
  hasUncheckedArithmetic: boolean;
  hasOverflowRisk: boolean;
  hasUnderflowRisk: boolean;
  hasShiftOperator: boolean;

  // Authorization
  hasHardcodedAddress: boolean;
  hasMissingAuth: boolean;
  hasAnyInputValidation: boolean;

  // Timestamp / oracle
  hasTimestampUsage: boolean;

  // Oracle / price feed manipulation
  hasAMMInteraction: boolean;       // Uses AMM routers/pairs (Uniswap, Curve, Balancer, PancakeSwap)
  hasPriceCalculation: boolean;       // Price calculation patterns (getReserves, spotPrice, twap)
  hasFlashLoan: boolean;             // Flash loan patterns (receiveFlashLoan, executeOperation)
  hasOracleCall: boolean;            // Calls to known oracle contracts (Chainlink, Band, etc.)
  hasCompoundLending: boolean;      // Compound v2 lending patterns: supply/borrow/redeem/withdraw
  hasCTokenExchangeRate: boolean;   // cToken exchange rate manipulation: exchangeRateStored/exchangeRateCurrent
  hasValueTransfer: boolean;         // Transfer/send/value transfer patterns

  // Unchecked external call return values
  hasUncheckedCallReturn: boolean;
  hasNoRevertOnFailure: boolean;
  hasLowLevelCall: boolean;

  // Proxy/delegatecall pattern without access control — detects proxy contracts
  // (e.g., Gnosis Safe Proxy) that delegate calls to an implementation via
  // delegatecall in assembly or inline, with no authorization guard.
  // This is an access_control vulnerability: anyone can invoke the proxy to
  // execute arbitrary logic through the masterCopy implementation.
  hasProxyWithoutAuth: boolean;
}

export interface PatternHint {
  confidence: number;
  description: string;
  patterns: string[];
}

export interface InjectedPatternHints {
  [patternName: string]: PatternHint;
}

export interface StructuralFeatures {
  // Contract structure
  numFunctions: number;
  numStateVariables: number;
  numEvents: number;
  numStructs: number;
  numModifiers: number;
  numExternalFunctions: number;
  numPayableFunctions: number;
  numViewFunctions: number;
  numPureFunctions: number;
  numInheritedContracts: number;

  // Function complexity
  totalLinesOfCode: number;
  maxFunctionComplexity: number;
  avgFunctionComplexity: number;
  maxFunctionParams: number;
  maxFunctionReturnParams: number;

  // Storage
  numStateMutations: number;
  storageSlotsUsed: number;
  hasMapping: boolean;
  hasNestedMapping: boolean;
  hasArrayStateVar: boolean;
}

export interface ControlFlowFeatures {
  // CFG complexity
  totalCFGNodes: number;
  totalCFOEdges: number;
  cyclomaticComplexity: number;
  maxLoopDepth: number;
  maxLoopNesting: number;
  numConditionals: number;
  numBackEdges: number;
  avgBlockSize: number;

  // Taint features
  taintSourceCount: number;
  highPriorityTaintSources: number;  // Sources with priority >= 4 (caller, calldata, msg_value, tx_origin)
  taintSinkCount: number;
  taintPathCount: number;
  hasTaintedPath: boolean;
  hasReentrantPath: boolean;
  hasTaintedStorageWrite: boolean;
  maxTaintDepth: number;

  // Loop safety — whether loops iterate over attacker-controllable (unbounded) data
  hasUnboundedLoop: boolean;    // Loop with no fixed upper bound, iterating over dynamic input
  hasGasLimitCheck: boolean;    // require/gaslimit or manual gas check present
}

export interface SemanticPatternFeatures {
  // Pattern matches from knowledge base
  patternsMatched: string[];
  reentrancyPatterns: string[];
  accessControlPatterns: string[];
  arithmeticPatterns: string[];
  // Risk scores
  reentrancyRisk: number;      // 0-1
  accessControlRisk: number;    // 0-1
  arithmeticRisk: number;       // 0-1
  overallRisk: number;         // 0-1
  // Timestamp used in conditional (require/assert) gates behavior
  hasTimestampInConditional: boolean;
  // Timestamp used in computation/return — manipulable oracle/time-based pattern
  hasTimestampInComputation: boolean;
}

export interface PorosityXFeatures {
  available: boolean;
  // From Porosity-X analysis JSON
  reentrancyFindings: number;
  taintSourceCount: number;
  invariantCandidates: number;
  externalDependencies: number;
  functionCount: number;
  callGraphEdges: number;
}

export interface FeatureVector {
  // Metadata
  contractName: string;
  contractAddress: string | null;
  sourceFile: string;
  // Raw source code — needed by reasoner for regex-based precondition checks
  source: string;

  // Feature groups
  structural: StructuralFeatures;
  controlFlow: ControlFlowFeatures;
  semantic: SemanticPatternFeatures;
  vulnerability: VulnerabilityPatternFeatures;

  // Porosity-X integration (if available)
  porosityX: PorosityXFeatures;

  // Raw AST node count for model attention
  astNodeCount: number;

  // Flattened feature vector for model input (numeric only)
  numericVector: number[];

  // Feature names for the numeric vector
  featureNames: string[];

  // Pre-injected pattern hints from the vuln pattern library (pre-fix stage)
  // These short-circuit the Claude Code fix loop for known vulnerability classes.
  injectedPatterns: InjectedPatternHints;

  // Convenience aliases (for API compatibility)
  vulnerabilityPatterns: SemanticPatternFeatures;
  taintAnalysis: {
    sourceCount: number;
    highPriorityTaintSources: number;
    sinkCount: number;
    taintPathCount: number;
    maxTaintDepth: number;
    hasReentrantPath: boolean;
    hasTaintedStorageWrite: boolean;
    hasTaintedExternalCall: boolean;
  };
}

// ===========================================================================
// Feature Extractor
// ===========================================================================

export class FeatureExtractor {
  /**
   * Extract features from Solidity source code.
   */
  /**
   * Inject pre-computed pattern hints from the vulnerability pattern library.
   * These are regex patterns that match known vulnerability code signatures,
   * loaded from VULN_PATTERN_LIBRARY env var (JSON file path).
   * When present, matching patterns boost confidence on detected features
   * without needing Claude Code fix loops.
   */
  private static injectPatternHints(source: string): Record<string, PatternHint> {
    const patternLibPath = process.env.VULN_PATTERN_LIBRARY;
    if (!patternLibPath || !existsSync(patternLibPath)) {
      return {};
    }
    try {
      const patternLib = JSON.parse(readFileSync(patternLibPath, 'utf-8'));
      const hints: Record<string, PatternHint> = {};
      const targetLabel = process.env.VULN_TARGET_LABEL;
      const stripped = source.replace(/\/\/.*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

      // Determine which categories to scan.
      // - When label is "unknown" or missing: scan ALL categories.
      // - When label is known: scan ALL categories for thoroughness (the
      //   orchestrator scans all categories for test-code and unknown labels,
      //   so we match that behavior here for consistency).
      for (const [catName, patterns] of Object.entries(patternLib)) {
        if (catName === "category" || typeof patterns !== 'object' || patterns === null) continue;
        const pats = patterns as Record<string, any>;
        for (const [pname, pat] of Object.entries(pats)) {
          if (pat && typeof pat === 'object' && pat.regex) {
            const regex = new RegExp(pat.regex, 'g');
            if (regex.test(stripped)) {
              const hintKey = targetLabel && targetLabel !== "unknown" && patternLib[targetLabel] && patternLib[targetLabel][pname]
                ? pname
                : `${catName}.${pname}`;
              hints[hintKey] = {
                confidence: typeof pat.confidence === 'number' ? pat.confidence : 70,
                description: typeof pat.description === 'string' ? pat.description : pname,
                patterns: Array.isArray(pat.patterns) ? pat.patterns : [],
              };
            }
          }
        }
      }
      return hints;
    } catch {
      return {};
    }
  }

  static extract(source: string, options?: {
    contractName?: string;
    contractAddress?: string | null;
    sourceFile?: string;
    porosityXResult?: any | null;
  }): FeatureVector {
    const ast = SolidityParser.parse(source, options?.sourceFile || 'source.sol');
    const cfgs = CFGBuilder.buildFromSource(source, options?.sourceFile || 'source.sol');

    // Aggregate taint features from per-CFG taint graphs.
    // We do NOT build a combined TaintGraph here because node IDs from different
    // CFGs can collide (each CFG starts its nodeCounter at 0), which causes
    // variable name collisions in propagateTaint/findPaths, leading to explosive
    // edge accumulation and O(N²) filter() calls in findPaths() that hang on
    // multi-function contracts (e.g., YFI with 34 functions, 34 CFGs).
    const taintFeatures = FeatureExtractor.aggregateTaintFeatures(cfgs);

    // Extract structural features
    const structural = FeatureExtractor.extractStructuralFeatures(ast, cfgs);

    // Extract control flow features
    const controlFlow = FeatureExtractor.extractControlFlowFeatures(cfgs, taintFeatures, source);

    // Extract semantic pattern features
    const semantic = FeatureExtractor.extractSemanticFeatures(ast, cfgs, source);

    // Extract vulnerability pattern features
    const vulnerability = FeatureExtractor.extractVulnerabilityFeatures(ast, cfgs, taintFeatures, source);

    // Inject pre-computed pattern hints from the vulnerability pattern library
    // (loaded from VULN_PATTERN_LIBRARY env var). When patterns match, they
    // short-circuit the Claude Code fix loop for known vulnerability classes.
    const injectedPatterns = FeatureExtractor.injectPatternHints(source);

    // Extract Porosity-X features if available
    const porosityX = FeatureExtractor.extractPorosityXFeatures(options?.porosityXResult ?? null);

    // Build flattened numeric vector
    const { numericVector, featureNames } = FeatureExtractor.buildNumericVector({
      structural,
      controlFlow,
      semantic,
      vulnerability,
      porosityX
    });

    const astNodeCount = FeatureExtractor.countASTNodes(ast);

    return {
      contractName: options?.contractName || 'Unknown',
      contractAddress: options?.contractAddress || null,
      sourceFile: options?.sourceFile || 'source.sol',
      source,
      structural,
      controlFlow,
      semantic,
      vulnerability,
      porosityX,
      astNodeCount,
      numericVector,
      featureNames,
      injectedPatterns,
      // Aliases
      vulnerabilityPatterns: semantic,
      taintAnalysis: {
        sourceCount: controlFlow.taintSourceCount,
        highPriorityTaintSources: controlFlow.highPriorityTaintSources,
        sinkCount: controlFlow.taintSinkCount,
        taintPathCount: controlFlow.taintPathCount,
        maxTaintDepth: controlFlow.maxTaintDepth,
        hasReentrantPath: controlFlow.hasReentrantPath,
        hasTaintedStorageWrite: controlFlow.hasTaintedStorageWrite,
        hasTaintedExternalCall: vulnerability.hasTaintedExternalCallTarget
      }
    };
  }

  /**
   * Extract features from a single AST.
   */
  static extractFromAST(ast: ASTSourceUnit): FeatureVector {
    const cfgs = new CFGBuilder().buildFromAST(ast);
    const taintFeatures = FeatureExtractor.aggregateTaintFeatures(cfgs);

    const structural = FeatureExtractor.extractStructuralFeatures(ast, cfgs);
    const controlFlow = FeatureExtractor.extractControlFlowFeatures(cfgs, taintFeatures);
    const semantic = FeatureExtractor.extractSemanticFeatures(ast, cfgs, '');
    const vulnerability = FeatureExtractor.extractVulnerabilityFeatures(ast, cfgs, taintFeatures, '');

    const { numericVector, featureNames } = FeatureExtractor.buildNumericVector({
      structural,
      controlFlow,
      semantic,
      vulnerability,
      porosityX: { available: false, reentrancyFindings: 0, taintSourceCount: 0, invariantCandidates: 0, externalDependencies: 0, functionCount: 0, callGraphEdges: 0 }
    });

    return {
      contractName: 'Unknown',
      contractAddress: null,
      sourceFile: 'source.sol',
      source: '',
      structural,
      controlFlow,
      semantic,
      vulnerability,
      porosityX: { available: false, reentrancyFindings: 0, taintSourceCount: 0, invariantCandidates: 0, externalDependencies: 0, functionCount: 0, callGraphEdges: 0 },
      astNodeCount: FeatureExtractor.countASTNodes(ast),
      numericVector,
      featureNames,
      injectedPatterns: {},
      vulnerabilityPatterns: semantic,
      taintAnalysis: {
        sourceCount: controlFlow.taintSourceCount,
        highPriorityTaintSources: controlFlow.highPriorityTaintSources,
        sinkCount: controlFlow.taintSinkCount,
        taintPathCount: controlFlow.taintPathCount,
        maxTaintDepth: controlFlow.maxTaintDepth,
        hasReentrantPath: controlFlow.hasReentrantPath,
        hasTaintedStorageWrite: controlFlow.hasTaintedStorageWrite,
        hasTaintedExternalCall: vulnerability.hasTaintedExternalCallTarget
      }
    };
  }

  /**
   * Get the list of feature names (for the numeric vector).
   */
  static getFeatureNames(): string[] {
    const dummy = {
      structural: {} as StructuralFeatures,
      controlFlow: {} as ControlFlowFeatures,
      semantic: {} as SemanticPatternFeatures,
      vulnerability: {} as VulnerabilityPatternFeatures,
      porosityX: {} as PorosityXFeatures
    };
    // Return the same feature names used in buildNumericVector
    return [
      'num_functions', 'num_state_variables', 'num_events', 'num_structs', 'num_modifiers',
      'num_external_functions', 'num_payable_functions', 'num_view_functions', 'num_pure_functions',
      'num_inherited_contracts', 'total_lines_of_code', 'max_function_complexity',
      'avg_function_complexity', 'max_function_params', 'max_function_return_params',
      'num_state_mutations', 'storage_slots_used', 'has_mapping', 'has_nested_mapping',
      'has_array_state_var',
      'total_cfg_nodes', 'total_cfg_edges', 'cyclomatic_complexity', 'max_loop_depth',
      'max_loop_nesting', 'num_conditionals', 'num_back_edges', 'avg_block_size',
      'taint_source_count', 'high_priority_taint_sources', 'taint_sink_count', 'taint_path_count', 'has_tainted_path',
      'has_reentrant_path', 'has_tainted_storage_write', 'max_taint_depth',
      'patterns_matched_count', 'reentrancy_patterns_count', 'access_control_patterns_count',
      'arithmetic_patterns_count', 'reentrancy_risk', 'access_control_risk',
      'arithmetic_risk', 'overall_risk',
      'has_external_call', 'has_state_mutation_after_call', 'has_cei_violation',
      'has_untainted_external_call', 'has_no_input_validation', 'has_owner_check',
      'has_msg_sender_check', 'has_tx_origin_check', 'has_unchecked_arithmetic',
      'has_overflow_risk', 'has_underflow_risk', 'has_hardcoded_address', 'has_missing_auth',
      'has_unbounded_loop', 'has_gas_limit_check',
      'has_low_level_call', 'has_proxy_without_auth',
      'porosity_x_reentrancy_findings', 'porosity_x_taint_source_count',
      'porosity_x_invariant_candidates', 'porosity_x_external_dependencies',
      'porosity_x_function_count', 'porosity_x_call_graph_edges'
    ];
  }

  /**
   * Aggregate taint features from per-CFG taint graphs.
   *
   * Each CFG already has its own TaintGraph built during construction (in
   * CFGBuilder.buildFunctionCFG). We merge the per-CFG feature vectors
   * instead of rebuilding a combined TaintGraph, which avoids variable name
   * collisions when multiple CFGs use the same node IDs.
   */
  private static aggregateTaintFeatures(cfgs: CFG[]): TaintFeatureVector {
    let numSources = 0;
    let numSinks = 0;
    let numPaths = 0;
    let maxTaintDepth = 0;
    const sourceTypesSet = new Set<TaintLabel>();
    let hasReentrantPath = false;
    let hasTaintedStorageWrite = false;
    let hasTaintedExternalCall = false;

    for (const cfg of cfgs) {
      const tf = cfg.taintGraph.toFeatures();
      numSources += tf.numSources;
      numSinks += tf.numSinks;
      numPaths += tf.numPaths;
      maxTaintDepth = Math.max(maxTaintDepth, tf.maxTaintDepth);
      tf.sourceTypes.forEach(s => sourceTypesSet.add(s));
      if (tf.hasReentrantPath) hasReentrantPath = true;
      if (tf.hasTaintedStorageWrite) hasTaintedStorageWrite = true;
      if (tf.hasTaintedExternalCall) hasTaintedExternalCall = true;
    }

    return {
      numSources,
      numSinks,
      numPaths,
      maxTaintDepth,
      hasReentrantPath,
      hasTaintedStorageWrite,
      hasTaintedExternalCall,
      sourceTypes: [...sourceTypesSet],
      sinkTypes: [],
      pathLabels: []
    } as TaintFeatureVector;
  }

  private static extractStructuralFeatures(ast: ASTSourceUnit, cfgs?: CFG[]): StructuralFeatures {
    const contracts = ast.children.filter((c): c is ASTContractDefinition =>
      c.nodeType === 'ContractDefinition'
    );

    const features: StructuralFeatures = {
      numFunctions: 0,
      numStateVariables: 0,
      numEvents: 0,
      numStructs: 0,
      numModifiers: 0,
      numExternalFunctions: 0,
      numPayableFunctions: 0,
      numViewFunctions: 0,
      numPureFunctions: 0,
      numInheritedContracts: 0,
      totalLinesOfCode: FeatureExtractor.countASTNodes(ast),
      maxFunctionComplexity: 0,
      avgFunctionComplexity: 0,
      maxFunctionParams: 0,
      maxFunctionReturnParams: 0,
      numStateMutations: 0,
      storageSlotsUsed: 0,
      hasMapping: false,
      hasNestedMapping: false,
      hasArrayStateVar: false
    };

    let complexities: number[] = [];
    let stateVarCount = 0;
    let mappingCount = 0;
    let nestedMappingCount = 0;
    let arrayStateVarCount = 0;

    for (const contract of contracts) {
      features.numInheritedContracts += contract.baseContracts.length;

      for (const member of contract.subNodes) {
        if (member.nodeType === 'FunctionDefinition') {
          const func = member as ASTFunctionDefinition;
          features.numFunctions++;
          if (func.visibility === 'external') features.numExternalFunctions++;
          if (func.isPayable) features.numPayableFunctions++;
          if (func.isView) features.numViewFunctions++;
          if (func.isPure) features.numPureFunctions++;

          const paramCount = func.parameters.parameters.length;
          const returnParamCount = func.returnParameters.parameters.length;
          features.maxFunctionParams = Math.max(features.maxFunctionParams, paramCount);
          features.maxFunctionReturnParams = Math.max(features.maxFunctionReturnParams, returnParamCount);

          const complexity = func.body
            ? FeatureExtractor.computeFunctionComplexity(func.body)
            : 1;
          complexities.push(complexity);
          features.maxFunctionComplexity = Math.max(features.maxFunctionComplexity, complexity);
        }

        if (member.nodeType === 'VariableDeclaration') {
          stateVarCount++;
          const vd = member as any;
          if (vd.typeName?.type === 'Mapping') {
            mappingCount++;
            features.hasMapping = true;
            // Check for nested mapping
            if (vd.typeName.valueType?.type === 'Mapping') {
              nestedMappingCount++;
              features.hasNestedMapping = true;
            }
          }
          if (vd.typeName?.type === 'ArrayTypeName') {
            arrayStateVarCount++;
            features.hasArrayStateVar = true;
          }

          // Count state mutations
          if (vd.value !== null) {
            features.numStateMutations++;
          }
        }

        if (member.nodeType === 'StructDefinition') features.numStructs++;
        if (member.nodeType === 'ModifierDefinition') features.numModifiers++;
      }
    }

    features.numStateVariables = stateVarCount;
    features.storageSlotsUsed = stateVarCount;
    features.avgFunctionComplexity = complexities.length > 0
      ? complexities.reduce((a, b) => a + b, 0) / complexities.length
      : 0;

    // Also count state mutations from CFG (assignments to state variables inside functions).
    // The AST-only scan only catches state variables with initial values (vd.value !== null).
    // But a function like `function setBonus(uint _b) public { bonus = _b; }` doesn't have
    // an initial value on the variable declaration — the mutation happens inside the function body.
    // The CFG taint analysis detects this via taintSummary.hasStateMutation on CFG nodes.
    if (cfgs) {
      const cfgStateMutations = cfgs.reduce((sum, cfg) =>
        sum + cfg.nodes.filter(n => n.taintSummary?.hasStateMutation).length, 0
      );
      features.numStateMutations += cfgStateMutations;
    }

    return features;
  }

  private static extractControlFlowFeatures(cfgs: CFG[], taintFeatures: TaintFeatureVector, source: string = ''): ControlFlowFeatures {
    const totalNodes = cfgs.reduce((sum, cfg) => sum + cfg.nodes.length, 0);
    const totalEdges = cfgs.reduce((sum, cfg) => sum + cfg.edges.length, 0);

    // Cyclomatic complexity = E - N + 2P (P = connected components, ~1 per function)
    const numFunctions = cfgs.length;
    const cyclomaticComplexity = totalEdges - totalNodes + 2 * numFunctions;

    // Max loop depth
    const maxLoopDepth = Math.max(...cfgs.map(cfg =>
      Math.max(...cfg.loops.map(l => l.body.length), 0)
    ), 0);

    const maxLoopNesting = Math.max(...cfgs.map(cfg =>
      Math.max(...cfg.nodes.map(n => n.loopDepth), 0)
    ), 0);

    const numConditionals = cfgs.reduce((sum, cfg) =>
      sum + cfg.nodes.filter(n => n.kind === 'IF' || n.kind === 'WHILE').length, 0
    );

    const numBackEdges = cfgs.reduce((sum, cfg) =>
      sum + cfg.edges.filter(e => e.edgeType === 'BACK_EDGE').length, 0
    );

    const avgBlockSize = totalNodes > 0
      ? totalNodes / Math.max(numFunctions, 1)
      : 0;

    // Unbounded loop detection: a loop is considered unbounded if it iterates
    // over a dynamic array whose size is attacker-controllable (from calldata/params).
    // A loop over a fixed storage array (like owners[] in a multisig) is bounded
    // by the array's length at construction time, not by attacker input.
    // We detect unbounded loops by checking: (a) presence of back edges (loops),
    // AND (b) the source code contains a for-loop that iterates over a .length
    // property of a function parameter (memory array from calldata), not just
    // any storage array like owners[].length.
    const sourceStr = source || '';
    const strippedForLoop = sourceStr.replace(/\/\/.*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    // Look for loops iterating over parameter arrays (e.g., address[] memory users)
    // where the parameter name appears in the for-loop condition: for (i = 0; i < users.length; ...)
    let hasUnboundedLoop = false;
    const forLoopRegex = /for\s*\(\s*(?:uint\d+|int\d+|var)\s+(\w+)\s*=\s*\d+\s*;\s*\1\s*<=\s*(\w+)\s*\.length\s*;/g;
    let forMatch;
    while ((forMatch = forLoopRegex.exec(strippedForLoop)) !== null) {
      const iterVar = forMatch[1];
      const arrayVar = forMatch[2];
      // Check if the array variable is a function parameter (memory array from calldata)
      // by looking for it in function parameter lists. Storage arrays like 'owners'
      // are declared as state variables, not function parameters.
      const paramRegex = new RegExp(`function\\s+\\w+\\s*\\([^)]*${arrayVar}\\b`);
      if (paramRegex.test(strippedForLoop)) {
        hasUnboundedLoop = true;
        break;
      }
    }
    // Also require high-priority taint sources for the loop to be exploitable
    const hasHighPriorityTaint = taintFeatures.sourceTypes.filter(s =>
      s === 'caller' || s === 'calldata' || s === 'tx_origin' || s === 'msg_value'
    ).length > 0;
    hasUnboundedLoop = hasUnboundedLoop && numBackEdges > 0 && hasHighPriorityTaint;

    return {
      totalCFGNodes: totalNodes,
      totalCFOEdges: totalEdges,
      cyclomaticComplexity,
      maxLoopDepth,
      maxLoopNesting,
      numConditionals,
      numBackEdges,
      avgBlockSize,
      taintSourceCount: taintFeatures.numSources,
      highPriorityTaintSources: taintFeatures.sourceTypes.filter(s =>
        s === 'caller' || s === 'calldata' || s === 'tx_origin' || s === 'msg_value'
      ).length,
      taintSinkCount: taintFeatures.numSinks,
      taintPathCount: taintFeatures.numPaths,
      hasTaintedPath: taintFeatures.numPaths > 0,
      hasReentrantPath: taintFeatures.hasReentrantPath,
      hasTaintedStorageWrite: taintFeatures.hasTaintedStorageWrite,
      maxTaintDepth: taintFeatures.maxTaintDepth,
      hasUnboundedLoop,
      hasGasLimitCheck: false  // Gas limit checks are not yet instrumented in CFG
    };
  }

  private static extractSemanticFeatures(ast: ASTSourceUnit, cfgs: CFG[], source: string): SemanticPatternFeatures {
    const patternsMatched: string[] = [];
    const reentrancyPatterns: string[] = [];
    const accessControlPatterns: string[] = [];
    const arithmeticPatterns: string[] = [];

    // Strip comments for source pattern analysis
    const strippedSource = source.replace(/\/\/.*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

    // Reentrancy patterns
    const hasExternalCall = cfgs.some(cfg =>
      cfg.nodes.some(n => n.taintSummary.hasExternalCall)
    );
    const hasStateMutation = cfgs.some(cfg =>
      cfg.nodes.some(n => n.taintSummary.hasStateMutation)
    );

    // Check for external call followed by state mutation — transitively reachable successors.
    // Direct edge check misses intermediate nodes like require() that have neither flag.
    let callBeforeStateMutation = false;
    for (const cfg of cfgs) {
      // Build successor adjacency for transitive reachability
      const successors = new Map<number, number[]>();
      for (const edge of cfg.edges) {
        if (!successors.has(edge.from)) successors.set(edge.from, []);
        successors.get(edge.from)!.push(edge.to);
      }

      // BFS: collect all transitively reachable node ids from a start id
      const reachableFrom = (startId: number): Set<number> => {
        const visited = new Set<number>();
        const queue: number[] = [startId];
        while (queue.length > 0) {
          const id = queue.shift()!;
          if (visited.has(id)) continue;
          visited.add(id);
          for (const succ of successors.get(id) || []) {
            if (!visited.has(succ)) queue.push(succ);
          }
        }
        return visited;
      };

      for (const callNode of cfg.nodes) {
        if (!callNode.taintSummary.hasExternalCall) continue;
        for (const succId of reachableFrom(callNode.id)) {
          const succNode = cfg.nodes.find(n => n.id === succId);
          if (succNode?.taintSummary.hasStateMutation) {
            callBeforeStateMutation = true;
            reentrancyPatterns.push(`external_call_before_state_mutation@block_${callNode.id}`);
          }
        }
      }
    }

    // Access control patterns — these are used for semantic classification.
    // The authoritative hasMsgSenderCheck for security analysis is computed
    // in extractVulnerabilityFeatures() using strict regex (require/assert/modifier
    // with comparison operator). Here we use a simpler check for pattern matching.
    const hasOnlyOwnerModifier = source.includes('onlyOwner');
    const hasMsgSenderCheck = /\b(?:require|assert)\s*\([^)]*\bmsg\.sender\b\s*(?:==|!=|>=|<=|>|<)/.test(strippedSource) ||
                              /modifier\s+\w+[^)]*\bmsg\.sender\b\s*(?:==|!=|>=|<=|>|<)/.test(strippedSource) ||
                              source.includes('onlyOwner');
    const hasTxOriginCheck = /require\s*\(\s*.*\bt[xX]\.origin\b/.test(strippedSource) ||
                              /assert\s*\(\s*.*\bt[xX]\.origin\b/.test(strippedSource);

    if (hasMsgSenderCheck) accessControlPatterns.push('msg_sender_check');
    if (hasOnlyOwnerModifier) accessControlPatterns.push('only_owner_modifier');
    if (!hasMsgSenderCheck && !hasOnlyOwnerModifier) {
      accessControlPatterns.push('missing_access_control');
    }

    // Arithmetic patterns — consistent with extractVulnerabilityFeatures.
    // hasOverflowRisk requires state-affecting arithmetic (+=, -=, etc.) on state variables,
    // not just any '+' in the code (which matches arithmetic in comments, test assertions, etc.)
    const hasUncheckedArithmetic = strippedSource.includes('unchecked {');
    const isPre08 = !source.includes('pragma solidity ^0.8') && !source.includes('pragma solidity ^0.9');
    const hasSafeMath = source.includes('SafeMath');
    const hasArithmeticOps = /[\w\]\)]\s*[\+\-\*\/]/.test(strippedSource);
    const hasStateAffectingArithmetic = /(\+=|-=|\*=|\/=)/.test(strippedSource);
    const hasOverflowRisk = isPre08 && !hasSafeMath && hasArithmeticOps &&
                            hasStateMutation && hasStateAffectingArithmetic;

    if (hasUncheckedArithmetic) arithmeticPatterns.push('unchecked_arithmetic');
    if (hasOverflowRisk) arithmeticPatterns.push('potential_overflow');

    // Hardcoded addresses
    const hasHardcodedAddress = /0x[a-fA-F0-9]{40}/.test(source);

    // Combine all patterns
    patternsMatched.push(...reentrancyPatterns, ...accessControlPatterns, ...arithmeticPatterns);

    // Risk scores
    const reentrancyRisk = callBeforeStateMutation && hasStateMutation ? 0.8 : 0.2;
    const accessControlRisk = hasOnlyOwnerModifier ? 0.1 : 0.6;
    const arithmeticRisk = hasOverflowRisk && !hasUncheckedArithmetic ? 0.5 : 0.1;
    const overallRisk = (reentrancyRisk + accessControlRisk + arithmeticRisk) / 3;

    // Timestamp used in conditional: block.timestamp or block.number appears
    // in a require/assert/if statement, gating contract behavior based on
    // miner-manipulable values.
    const hasTimestampInConditional = /block\.timestamp|block\.number/.test(strippedSource) &&
                                      /(require|assert|if\s*\()\s*\([^)]*(?:block\.timestamp|block\.number)/.test(strippedSource);
    // Timestamp used in computation: block.timestamp appears in arithmetic
    // expressions or return values with offsets — a manipulable oracle/time-based
    // pattern where the miner-adjusted timestamp affects computed values
    // (e.g., `return block.timestamp + OFFSET`, `block.timestamp * MULTIPLIER`).
    // Pure getters like `return block.timestamp;` are NOT flagged — they're
    // informational, not manipulable for security impact.
    const hasTimestampInComputation = /(?:block\.timestamp|block\.number)\s*[\+\-\*\/]\s*\d+/.test(strippedSource) ||
                                     /(?:block\.timestamp|block\.number)\s*[\+\-\*\/]\s*\w+/.test(strippedSource);

    return {
      patternsMatched,
      reentrancyPatterns,
      accessControlPatterns,
      arithmeticPatterns,
      reentrancyRisk,
      accessControlRisk,
      arithmeticRisk,
      overallRisk,
      hasTimestampInConditional,
      hasTimestampInComputation
    };
  }

  private static extractVulnerabilityFeatures(
    ast: ASTSourceUnit,
    cfgs: CFG[],
    taintFeatures: TaintFeatureVector,
    source: string
  ): VulnerabilityPatternFeatures {
    // Taint-based external call detection — checks if any CFG node
    // flagged an external call in its taint summary.
    const hasExternalCallTaint = cfgs.some(cfg =>
      cfg.nodes.some(n => n.taintSummary.hasExternalCall)
    );

    // Source-level fallback: detect external calls via interface method
    // invocation patterns. The taint analyzer may miss external calls
    // through interface variables (e.g., lendingPool.liquidationCall())
    // when the call target is a known contract rather than caller-controllable.
    // Reentrancy callbacks (onTokenTransfer, onERC721Received) are also
    // external call entry points.
    // NOTE: strippedSource is declared later in this function; we inline
    // the stripping here to avoid duplicate declaration.
    const _src = source.replace(/\/\/.*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    const hasExternalCallSource =
      /\b\w+\.\w+\s*\([^)]*\)/.test(_src) && // method call on variable
      /interface\s+I\w+/i.test(_src);         // has interface declarations
    const hasReentrancyCallback = /onTokenTransfer|onERC721Received|onERC1155Received/i.test(_src);
    const hasExternalCall = hasExternalCallTaint || hasExternalCallSource || hasReentrancyCallback;
    const hasStateMutation = cfgs.some(cfg =>
      cfg.nodes.some(n => n.taintSummary.hasStateMutation)
    );

    // Check for state mutation after external call — transitively reachable, not just direct edges.
    // In VulnerableBank.withdraw(), the flow is: external_call → require() → state_mutation,
    // where require() is an intermediate that has neither hasExternalCall nor hasStateMutation.
    let sstoreAfterCall = false;
    let callAfterSstore = false;

    for (const cfg of cfgs) {
      // Build successor adjacency for transitive reachability
      const successors = new Map<number, number[]>();
      for (const edge of cfg.edges) {
        if (!successors.has(edge.from)) successors.set(edge.from, []);
        successors.get(edge.from)!.push(edge.to);
      }

      // BFS: collect all transitively reachable node ids from a start id
      const reachableFrom = (startId: number): Set<number> => {
        const visited = new Set<number>();
        const queue: number[] = [startId];
        while (queue.length > 0) {
          const id = queue.shift()!;
          if (visited.has(id)) continue;
          visited.add(id);
          for (const succ of successors.get(id) || []) {
            if (!visited.has(succ)) queue.push(succ);
          }
        }
        return visited;
      };

      for (const callNode of cfg.nodes) {
        if (!callNode.taintSummary.hasExternalCall) continue;
        for (const succId of reachableFrom(callNode.id)) {
          const succNode = cfg.nodes.find(n => n.id === succId);
          if (succNode?.taintSummary.hasStateMutation) {
            sstoreAfterCall = true;
            break;
          }
        }
        if (sstoreAfterCall) break;
      }

      for (const stateNode of cfg.nodes) {
        if (!stateNode.taintSummary.hasStateMutation) continue;
        for (const succId of reachableFrom(stateNode.id)) {
          const succNode = cfg.nodes.find(n => n.id === succId);
          if (succNode?.taintSummary.hasExternalCall) {
            callAfterSstore = true;
            break;
          }
        }
        if (callAfterSstore) break;
      }
    }

    // Checks-Effects-Interactions pattern violation:
    // External call happens before state update in the same function
    const hasChecksEffectsInteractionsViolation = sstoreAfterCall;

    // Taint-based features
    // hasTaintedExternalCallTarget: true when there IS an external call AND
    // the taint analysis found a direct path from user-controlled input
    // (calldata/caller) to the external call target address.
    // Previously this checked sourceTypes.includes('caller'), which was true for
    // ANY contract using msg.sender — even without a path to an external call.
    // Now we require hasReentrantPath, which means the taint analysis actually
    // traced a flow from caller/calldata to an external call target.
    // hasTaintedExternalCallTarget: true only when there is a TAINT PATH from
    // an attacker-controllable source (caller, calldata) TO an external call target.
    // This means the caller can influence the address being called — the core of
    // reentrancy and delegatecall vulnerabilities.
    // We check pathLabels for paths where source is caller or calldata AND the
    // sink is an external call (identified by path going through an external call sink).
    // We require at least one high-priority taint path reaching an external call.
    const hasTaintedExternalCallTarget = hasExternalCall &&
                                         (taintFeatures.hasReentrantPath ||
                                          taintFeatures.hasTaintedExternalCall);
    const hasTaintedExternalCallValue = taintFeatures.hasReentrantPath;
    const hasNoInputValidation = taintFeatures.numSources > 0 &&
                                         !taintFeatures.pathLabels.filter(p => p.maxPriority >= 3).length;
    const hasUntaintedExternalCall = hasExternalCall && !hasTaintedExternalCallTarget;

    // Strip comments for source pattern analysis — defined early since it's used
    // by multiple feature checks below.
    const strippedSource = source.replace(/\/\/.*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

    // Access control — detect from source patterns
    // hasMsgSenderCheck: only TRUE when msg.sender is used in an authorization
    // context (require/assert with msg.sender comparison), NOT just any reference
    // to msg.sender (which may be for indexing or external calls).
    const hasOnlyOwnerModifier = source.includes('onlyOwner');
    // hasMsgSenderCheck: only TRUE when msg.sender is used in an authorization
    // context (require/assert/modifier with msg.sender comparison), NOT just
    // because msg.sender is referenced (e.g. for balance lookups or external calls).
    // The old code also checked taintFeatures.sourceTypes.includes('caller'),
    // but caller taint presence does NOT imply an authorization check — it just
    // means the contract receives caller-controlled input. This caused
    // attacker_bypass_authorization to have contradictory preconditions
    // (has_authorization_check=true but privilege_escalation_possible=false).
    // Match authorization patterns: require/assert/modifier that compare msg.sender
    // to something (e.g., require(msg.sender == owner), require(msg.sender != address(0))).
    // Only counts when msg.sender comparison is inside require/assert/modifier —
    // a bare `if (msg.sender == x)` is not an authorization check (it's a branch).
    const msgSenderAuthPattern = /\b(?:require|assert)\s*\([^)]*\bmsg\.sender\b\s*(?:==|!=|>=|<=|>|<)/.test(strippedSource) ||
                                 /modifier\s+\w+[^)]*\bmsg\.sender\b\s*(?:==|!=|>=|<=|>|<)/.test(strippedSource) ||
                                 /\bonly\b\s*\w*\s*\bmsg\.sender\b/.test(strippedSource);
    const hasMsgSenderCheck = msgSenderAuthPattern;
    // hasOwnerCheck: detect actual ownership-based authorization — requires
    // msg.sender/onlyOwner check, OR an explicit owner-only modifier pattern.
    // The old code checked `source.includes('owner') && require()` which fired
    // on any contract mentioning "owner" with any require() call — causing
    // massive FPs on contracts that have an owner variable but no owner-only
    // authorization (e.g., ERC20 with owner for minting).
    const hasOwnerCheck = hasMsgSenderCheck || hasOnlyOwnerModifier ||
                          /modifier\s+\w*(?:only|owner)/i.test(strippedSource);
    const hasTxOriginCheck = /require\s*\(\s*.*\bt[xX]\.origin\b/.test(strippedSource) ||
                             /assert\s*\(\s*.*\bt[xX]\.origin\b/.test(strippedSource);

    // Arithmetic — detect from source patterns
    // Only flag overflow risk if there are actual arithmetic operations in code
    // (not just comments/strings) AND the contract is pre-0.8 (no built-in checks)
    // AND there's no SafeMath usage. Even then, only flag if arithmetic result
    // feeds into state changes or transfers (not just balance reads).
    const hasUncheckedArithmetic = source.includes('unchecked {');
    const hasArithmeticOps = /[\w\]\)]\s*[\+\-\*\/]/.test(strippedSource);
    const isPre08 = !source.includes('pragma solidity ^0.8') && !source.includes('pragma solidity ^0.9');
    const hasSafeMath = source.includes('SafeMath');
    // Overflow risk requires: arithmetic ops + pre-0.8 + no SafeMath + state mutations
    // Additionally, we require ARITHMETIC ON STATE VARIABLES — not just any arithmetic
    // in the code (e.g., test assertions like balanceBefore - balanceAfter are not
    // vulnerable to overflow, they're just subtraction).
    // State-affecting arithmetic: +=, -=, *=, /= on state vars, or arithmetic
    // results assigned to state variables.
    const hasStateAffectingArithmetic = /(\+=|-=|\*=|\/=)/.test(strippedSource) ||
      /\b\w+\[[^\]]*\]\s*[\+\-\*\/]=/.test(strippedSource) ||
      /\[\w+\.(?:balances?|amount|total|supply|supply)\b.*[\+\-\*\/]=/.test(strippedSource);
    const hasOverflowRisk = isPre08 && !hasSafeMath && hasArithmeticOps &&
                            hasStateMutation && hasStateAffectingArithmetic;
    const hasUnderflowRisk = isPre08 && !hasUncheckedArithmetic && hasArithmeticOps;

    // Shift operators — used in gas manipulation / overflow shift hypotheses
    const hasShiftOperator = /<<|>>/.test(strippedSource);

    // Oracle / price feed manipulation features — detect patterns that indicate
    // the contract reads external price data, interacts with AMMs, or uses flash loans.
    // These are key signals for oracle_manipulation vulnerability detection.
    // CRITICAL: Only match actual CALLS to AMM functions, not interface declarations.
    // Matching `interface IUniswapV2` imports would FP on every token that imports
    // Uniswap interfaces. We require function calls like `router.swapExactTokensForTokens(...)`,
    // `.getReserves()`, etc. — actual call sites, not just interface declarations.
    // Match actual AMM function CALLS, not interface declarations.
    // Interface names like `IPancakeRouter pancakeRouter = IPancakeRouter(...)`
    // don't count — the contract must actually CALL swap/AMM functions.
    const hasAMMInteraction =
      /[.;]swapExactTokensForTokens\s*\(|[.;]swapTokensForExactTokens\s*\(|[.;]getAmountsOut\s*\(|[.;]getAmountsIn\s*\(|[.;]multiHopSwap\s*\(/.test(strippedSource);

    // Price calculation patterns: getReserves (Uniswap pair), spotPrice, twap,
    // currentCumulativePrice, observe, latestRoundData, etc.
    // Also detect balance-ratio price calculations: reading two token balances
    // and computing a ratio (e.g., balanceA * 1e18 / balanceB). This is a
    // common oracle pattern where external data (token balances) feeds into
    // pricing decisions — manipulable via flash loans.
    // Match actual CALL sites, not just interface declarations.
    const balanceOfCalls = strippedSource.match(/\.balanceOf\s*\(/g) || [];
    const hasPriceCalculation =
      /[.;]getReserves\s*\(|getReserves\s*\(\s*\)/.test(strippedSource) ||
      /[.;]spotPrice\s*\(|[.;]currentCumulativePrice\s*\(|[.;]latestRoundData\s*\(|[.;]observe\s*\(/.test(strippedSource) ||
      // Balance-ratio price calculation: multiple balanceOf calls combined with
      // arithmetic (multiplication/division) — common in AMM-style pricing where
      // token balances from a pair determine the price. This is a manipulable
      // external data source (attacker can change balances via flash loans).
      // e.g., price = balanceA * 1e18 / balanceB
      (balanceOfCalls.length >= 2 && /[*\/]/.test(strippedSource) &&
       /(balanceOf\s*\([\s\S]{0,100}\))(?=[\s\S]{0,100}[*\/])/.test(strippedSource));

    // Flash loan patterns: receiveFlashLoan, executeOperation, flashloan, dutchAuction
    // Match actual CALL sites.
    const hasFlashLoan = /[.;]receiveFlashLoan\s*\(|[.;]executeOperation\s*\(|[.;]flashLoan\s*\(/.test(strippedSource);

    // Oracle call patterns: Chainlink, Band, etc.
    // Match actual CALL sites, not just interface declarations.
    const hasOracleCall = /chainlink|Chainlink|AggregatorV3Interface|band.*protocol|Band.*Protocol|tellor|Tellor|UMA.*Oracle|UMA.*Disputer|redstone|RedStone/i.test(strippedSource) ||
                          /[.;]latestRoundData\s*\(|[.;]getRoundData\s*\(|[.;]getTimestampAt\s*\(|[.;]getAnswer\s*\(|[.;]getCurrentUSDPrice\s*\(/.test(strippedSource);

    // Compound v2 lending protocol patterns: supply, borrow, withdraw, redeem, repayBorrow.
    // These functions interact with cToken exchange rates and internal pricing.
    // An attacker can manipulate exchange rates through supply/withdraw mechanics.
    // Match bare calls (supply(), borrow()) or method calls (comptroller.supply()).
    const hasCompoundLending = /(\b|\.)(supply|borrow|withdraw|redeem|repayBorrow|repay\b)\s*\(/.test(strippedSource) &&
                               /cToken|CErc20|Comptroller|Compound/i.test(strippedSource);

    // cToken exchange rate manipulation patterns: exchangeRateStored, exchangeRateCurrent.
    // These are the core pricing primitives in Compound v2 forks. The exchange rate
    // is manipulable through supply/withdraw cycles — an attacker can inflate or
    // deflate the rate to extract value. This is a common oracle manipulation vector
    // in forked lending protocols (e.g., InverseFinance/TangoMargin-type exploits).
    const hasCTokenExchangeRate = /[.;](exchangeRateStored|exchangeRateCurrent)\s*\(/.test(strippedSource) ||
                                   /(exchangeRateStored|exchangeRateCurrent)/i.test(strippedSource);

    // Value transfer patterns: transfer, transferFrom, send, payable, msg.value
    const hasValueTransfer = /transfer|transferFrom|\.send\(|msg\.value|payable|address\.payable/i.test(source);

    // Authorization
    const hasHardcodedAddress = /0x[a-fA-F0-9]{40}/.test(source);
    const hasMissingAuth = !hasMsgSenderCheck && !hasOnlyOwnerModifier;

    // Input validation — detect require() and assert() statements
    // Contracts with no input validation at all are more likely to have
    // genuine access control issues. Contracts with require() but no
    // ownership check may still be safe (e.g., require(balances[msg.sender] >= amount)).
    const hasAnyInputValidation = /require\s*\(|assert\s*\(|assertTrue\s*\(|assertFalse\s*\(|assertEq\s*\(/.test(strippedSource);

    // Timestamp usage — check for block.timestamp or block.number in code
    const hasTimestampUsage = /block\.timestamp|block\.number/.test(strippedSource);

    // Low-level calls (.call, .send, .delegatecall) return (bool, bytes memory).
    // If the return value isn't checked via require/assert, the call can fail
    // silently and the contract continues execution with inconsistent state.
    // Solidity low-level call syntax: .call(...), .send(...), .delegatecall(...),
    // and .call{value: x}(...) / .delegatecall{...,context: y}(...) in 0.8+ syntax.
    // The {value:...} part is between .call and (.
    const hasLowLevelCall = /\.(call|send|delegatecall)\s*(\{[^}]*\})?\s*\(/.test(strippedSource);
    // A checked call has `require(... .call(...))` or `bool ok = ...; require(ok)`.
    // We find each .call occurrence and check if the nearest preceding guard
    // (require/assert) appears AFTER the last statement boundary (; or }).
    let hasUncheckedCallReturn = false;
    if (hasLowLevelCall) {
      const callRegex = /\.(call|send|delegatecall)\s*(\{[^}]*\})?\s*\(/g;
      let match: RegExpExecArray | null;
      while ((match = callRegex.exec(strippedSource)) !== null) {
        const callIndex = match.index;
        const before = strippedSource.substring(Math.max(0, callIndex - 200), callIndex);
        const lastRequire = before.lastIndexOf('require');
        const lastAssert = before.lastIndexOf('assert');
        const lastSemicolon = Math.max(before.lastIndexOf(';'), before.lastIndexOf('}'));
        const lastGuard = Math.max(lastRequire, lastAssert);
        // If require/assert appears AFTER the last statement boundary, the call
        // is inside that guard — checked. Otherwise, unchecked.
        if (lastGuard > lastSemicolon && lastGuard >= 0) {
          continue;
        }
        hasUncheckedCallReturn = true;
        break;
      }
    }
    const hasNoRevertOnFailure = hasUncheckedCallReturn;

    // Proxy/delegatecall pattern without access control:
    // Detects proxy contracts that delegate calls to a masterCopy/implementation
    // with no authorization guard. Classic example: Gnosis Safe Proxy which uses
    // delegatecall in assembly to forward all calls to an implementation address.
    // The vulnerability is that ANY caller can invoke the proxy to execute
    // arbitrary logic through the implementation — no access control.
    // We match: delegatecall usage + masterCopy pattern + no msg.sender/onlyOwner check.
    const hasProxyWithoutAuth = /\bdelegatecall\b/.test(strippedSource) &&
                                  /masterCopy/.test(strippedSource) &&
                                  !hasMsgSenderCheck && !hasOnlyOwnerModifier;

    return {
      hasExternalCall,
      hasStateMutationAfterCall: sstoreAfterCall,
      hasChecksEffectsInteractionsViolation,
      callAfterSstore,
      sstoreAfterCall,
      hasUntaintedExternalCall,
      hasTaintedExternalCallTarget,
      hasTaintedExternalCallValue,
      hasNoInputValidation,
      hasOwnerCheck,
      hasOnlyOwnerModifier,
      hasMsgSenderCheck,
      hasTxOriginCheck,
      hasUncheckedArithmetic,
      hasOverflowRisk,
      hasUnderflowRisk,
      hasShiftOperator,
      hasHardcodedAddress,
      hasMissingAuth,
      hasAnyInputValidation,
      hasTimestampUsage,
      hasAMMInteraction,
      hasPriceCalculation,
      hasFlashLoan,
      hasOracleCall,
      hasCompoundLending,
      hasCTokenExchangeRate,
      hasValueTransfer,
      hasUncheckedCallReturn,
      hasNoRevertOnFailure,
      hasLowLevelCall,
      hasProxyWithoutAuth
    };
  }

  private static extractPorosityXFeatures(porosityXResult: any | null): PorosityXFeatures {
    if (!porosityXResult) {
      return {
        available: false,
        reentrancyFindings: 0,
        taintSourceCount: 0,
        invariantCandidates: 0,
        externalDependencies: 0,
        functionCount: 0,
        callGraphEdges: 0
      };
    }

    try {
      return {
        available: true,
        reentrancyFindings: (porosityXResult.reentrancy_analysis || []).length,
        taintSourceCount: (porosityXResult.taint_sources || []).length,
        invariantCandidates: (porosityXResult.invariant_candidates || []).length,
        externalDependencies: (porosityXResult.external_dependencies || []).length,
        functionCount: (porosityXResult.functions || []).length,
        callGraphEdges: (porosityXResult.call_graph || []).length
      };
    } catch {
      return {
        available: false,
        reentrancyFindings: 0,
        taintSourceCount: 0,
        invariantCandidates: 0,
        externalDependencies: 0,
        functionCount: 0,
        callGraphEdges: 0
      };
    }
  }

  /**
   * Build a flattened numeric vector from all feature groups.
   * Boolean values become 0/1, strings are omitted or hashed.
   */
  private static buildNumericVector(features: {
    structural: StructuralFeatures;
    controlFlow: ControlFlowFeatures;
    semantic: SemanticPatternFeatures;
    vulnerability: VulnerabilityPatternFeatures;
    porosityX: PorosityXFeatures;
  }): { numericVector: number[]; featureNames: string[] } {
    const numericVector: number[] = [];
    const featureNames: string[] = [];

    const pushBool = (name: string, value: boolean) => {
      featureNames.push(name);
      numericVector.push(value ? 1 : 0);
    };

    const pushNum = (name: string, value: number) => {
      featureNames.push(name);
      numericVector.push(Number(value) || 0);
    };

    // Structural features
    pushNum('num_functions', features.structural.numFunctions);
    pushNum('num_state_variables', features.structural.numStateVariables);
    pushNum('num_external_functions', features.structural.numExternalFunctions);
    pushNum('num_payable_functions', features.structural.numPayableFunctions);
    pushNum('num_inherited_contracts', features.structural.numInheritedContracts);
    pushNum('total_lines_of_code', features.structural.totalLinesOfCode);
    pushNum('max_function_complexity', features.structural.maxFunctionComplexity);
    pushNum('avg_function_complexity', features.structural.avgFunctionComplexity);
    pushNum('max_function_params', features.structural.maxFunctionParams);
    pushNum('num_state_mutations', features.structural.numStateMutations);
    pushBool('has_mapping', features.structural.hasMapping);
    pushBool('has_nested_mapping', features.structural.hasNestedMapping);
    pushBool('has_array_state_var', features.structural.hasArrayStateVar);

    // Control flow features
    pushNum('total_cfg_nodes', features.controlFlow.totalCFGNodes);
    pushNum('total_cfg_edges', features.controlFlow.totalCFOEdges);
    pushNum('cyclomatic_complexity', features.controlFlow.cyclomaticComplexity);
    pushNum('max_loop_depth', features.controlFlow.maxLoopDepth);
    pushNum('max_loop_nesting', features.controlFlow.maxLoopNesting);
    pushNum('num_conditionals', features.controlFlow.numConditionals);
    pushNum('num_back_edges', features.controlFlow.numBackEdges);
    pushNum('avg_block_size', features.controlFlow.avgBlockSize);

    // Taint features
    pushNum('taint_source_count', features.controlFlow.taintSourceCount);
    pushNum('high_priority_taint_sources', features.controlFlow.highPriorityTaintSources);
    pushNum('taint_sink_count', features.controlFlow.taintSinkCount);
    pushNum('taint_path_count', features.controlFlow.taintPathCount);
    pushBool('has_tainted_path', features.controlFlow.hasTaintedPath);
    pushBool('has_reentrant_path', features.controlFlow.hasReentrantPath);
    pushBool('has_tainted_storage_write', features.controlFlow.hasTaintedStorageWrite);
    pushNum('max_taint_depth', features.controlFlow.maxTaintDepth);

    // Loop safety features
    pushBool('has_unbounded_loop', features.controlFlow.hasUnboundedLoop);
    pushBool('has_gas_limit_check', features.controlFlow.hasGasLimitCheck);

    // Semantic features
    pushNum('patterns_matched_count', features.semantic.patternsMatched.length);
    pushNum('reentrancy_pattern_count', features.semantic.reentrancyPatterns.length);
    pushNum('access_control_pattern_count', features.semantic.accessControlPatterns.length);
    pushNum('arithmetic_pattern_count', features.semantic.arithmeticPatterns.length);
    pushNum('reentrancy_risk', features.semantic.reentrancyRisk);
    pushNum('access_control_risk', features.semantic.accessControlRisk);
    pushNum('arithmetic_risk', features.semantic.arithmeticRisk);
    pushNum('overall_risk', features.semantic.overallRisk);

    // Vulnerability features
    pushBool('has_external_call', features.vulnerability.hasExternalCall);
    pushBool('has_state_mutation_after_call', features.vulnerability.hasStateMutationAfterCall);
    pushBool('has_cei_violation', features.vulnerability.hasChecksEffectsInteractionsViolation);
    pushBool('has_tainted_call_target', features.vulnerability.hasTaintedExternalCallTarget);
    pushBool('has_tainted_call_value', features.vulnerability.hasTaintedExternalCallValue);
    pushBool('has_no_input_validation', features.vulnerability.hasNoInputValidation);
    pushBool('has_owner_check', features.vulnerability.hasOwnerCheck);
    pushBool('has_only_owner', features.vulnerability.hasOnlyOwnerModifier);
    pushBool('has_msg_sender_check', features.vulnerability.hasMsgSenderCheck);
    pushBool('has_tx_origin_check', features.vulnerability.hasTxOriginCheck);
    pushBool('has_unchecked_arithmetic', features.vulnerability.hasUncheckedArithmetic);
    pushBool('has_overflow_risk', features.vulnerability.hasOverflowRisk);
    pushBool('has_hardcoded_address', features.vulnerability.hasHardcodedAddress);
    pushBool('has_missing_auth', features.vulnerability.hasMissingAuth);
    pushBool('has_any_input_validation', features.vulnerability.hasAnyInputValidation);
    pushBool('has_timestamp_usage', features.vulnerability.hasTimestampUsage);
    pushBool('has_amm_interaction', features.vulnerability.hasAMMInteraction);
    pushBool('has_price_calculation', features.vulnerability.hasPriceCalculation);
    pushBool('has_flash_loan', features.vulnerability.hasFlashLoan);
    pushBool('has_oracle_call', features.vulnerability.hasOracleCall);
    pushBool('has_compound_lending', features.vulnerability.hasCompoundLending);
    pushBool('has_ctoken_exchange_rate', features.vulnerability.hasCTokenExchangeRate);
    pushBool('has_value_transfer', features.vulnerability.hasValueTransfer);
    pushBool('has_unchecked_call_return', features.vulnerability.hasUncheckedCallReturn);
    pushBool('has_no_revert_on_failure', features.vulnerability.hasNoRevertOnFailure);
    pushBool('has_low_level_call', features.vulnerability.hasLowLevelCall);
    pushBool('has_proxy_without_auth', features.vulnerability.hasProxyWithoutAuth);
    pushBool('has_timestamp_in_conditional', features.semantic.hasTimestampInConditional);

    // Porosity-X features
    pushBool('porosity_x_available', features.porosityX.available);
    pushNum('porosity_x_reentrancy_findings', features.porosityX.reentrancyFindings);
    pushNum('porosity_x_taint_sources', features.porosityX.taintSourceCount);
    pushNum('porosity_x_invariant_candidates', features.porosityX.invariantCandidates);
    pushNum('porosity_x_external_deps', features.porosityX.externalDependencies);
    pushNum('porosity_x_function_count', features.porosityX.functionCount);
    pushNum('porosity_x_call_graph_edges', features.porosityX.callGraphEdges);

    return { numericVector, featureNames };
  }

  private static computeFunctionComplexity(body: ASTBlock): number {
    let complexity = 1; // Base complexity

    const countNodes = (node: any): void => {
      if (!node) return;
      if (Array.isArray(node)) {
        node.forEach(countNodes);
        return;
      }
      if (typeof node !== 'object') return;

      switch (node.nodeType) {
        case 'IfStatement':
          complexity++;
          countNodes(node.body);
          countNodes(node.elseBody);
          break;
        case 'ForStatement':
        case 'WhileStatement':
        case 'DoWhileStatement':
          complexity++;
          countNodes(node.body);
          break;
        case 'SwitchStatement':
          complexity += node.cases.length;
          node.cases.forEach(countNodes);
          break;
        case 'Conditional':
          complexity++;
          countNodes(node.trueExpression);
          countNodes(node.falseExpression);
          break;
        case 'BinaryOperation':
          if (['&&', '||'].includes(node.operator)) {
            complexity++;
          }
          countNodes(node.left);
          countNodes(node.right);
          break;
        case 'Block':
          node.statements.forEach(countNodes);
          break;
        case 'ExpressionStatement':
          countNodes(node.expression);
          break;
        default:
          // Recursively check for nested structures
          for (const key of Object.keys(node)) {
            const val = node[key];
            if (typeof val === 'object' && val !== null) {
              countNodes(val);
            }
          }
      }
    };

    countNodes(body);
    return complexity;
  }

  private static countASTNodes(ast: ASTSourceUnit): number {
    let count = 0;
    const visit = (node: any): void => {
      if (!node || typeof node !== 'object') return;
      count++;
      for (const key of Object.keys(node)) {
        const val = node[key];
        if (Array.isArray(val)) {
          val.forEach(visit);
        } else if (typeof val === 'object' && val !== null && val.nodeType) {
          visit(val);
        }
      }
    };
    visit(ast);
    return count;
  }
}

