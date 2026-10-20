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
import { TaintGraph, TaintFeatureVector } from '../taint/graph.js';

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

  // Authorization
  hasHardcodedAddress: boolean;
  hasMissingAuth: boolean;
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
  taintSinkCount: number;
  taintPathCount: number;
  hasTaintedPath: boolean;
  hasReentrantPath: boolean;
  hasTaintedStorageWrite: boolean;
  maxTaintDepth: number;
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

  // Convenience aliases (for API compatibility)
  vulnerabilityPatterns: SemanticPatternFeatures;
  taintAnalysis: {
    sourceCount: number;
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
  static extract(source: string, options?: {
    contractName?: string;
    contractAddress?: string | null;
    sourceFile?: string;
    porosityXResult?: any | null;
  }): FeatureVector {
    const ast = SolidityParser.parse(source, options?.sourceFile || 'source.sol');
    const cfgs = CFGBuilder.buildFromSource(source, options?.sourceFile || 'source.sol');

    // Build combined taint graph from all CFGs
    const allNodes = cfgs.flatMap(cfg => cfg.nodes);
    const allEdges = cfgs.flatMap(cfg => cfg.edges);
    const taintGraph = new TaintGraph(allNodes, allEdges);
    const taintFeatures = taintGraph.toFeatures();

    // Extract structural features
    const structural = FeatureExtractor.extractStructuralFeatures(ast);

    // Extract control flow features
    const controlFlow = FeatureExtractor.extractControlFlowFeatures(cfgs, taintFeatures);

    // Extract semantic pattern features
    const semantic = FeatureExtractor.extractSemanticFeatures(ast, cfgs, source);

    // Extract vulnerability pattern features
    const vulnerability = FeatureExtractor.extractVulnerabilityFeatures(ast, cfgs, taintFeatures, source);

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
      structural,
      controlFlow,
      semantic,
      vulnerability,
      porosityX,
      astNodeCount,
      numericVector,
      featureNames,
      // Aliases
      vulnerabilityPatterns: semantic,
      taintAnalysis: {
        sourceCount: controlFlow.taintSourceCount,
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
    const allNodes = cfgs.flatMap(cfg => cfg.nodes);
    const allEdges = cfgs.flatMap(cfg => cfg.edges);
    const taintGraph = new TaintGraph(allNodes, allEdges);
    const taintFeatures = taintGraph.toFeatures();

    const structural = FeatureExtractor.extractStructuralFeatures(ast);
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
      structural,
      controlFlow,
      semantic,
      vulnerability,
      porosityX: { available: false, reentrancyFindings: 0, taintSourceCount: 0, invariantCandidates: 0, externalDependencies: 0, functionCount: 0, callGraphEdges: 0 },
      astNodeCount: FeatureExtractor.countASTNodes(ast),
      numericVector,
      featureNames,
      vulnerabilityPatterns: semantic,
      taintAnalysis: {
        sourceCount: controlFlow.taintSourceCount,
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
      'taint_source_count', 'taint_sink_count', 'taint_path_count', 'has_tainted_path',
      'has_reentrant_path', 'has_tainted_storage_write', 'max_taint_depth',
      'patterns_matched_count', 'reentrancy_patterns_count', 'access_control_patterns_count',
      'arithmetic_patterns_count', 'reentrancy_risk', 'access_control_risk',
      'arithmetic_risk', 'overall_risk',
      'has_external_call', 'has_state_mutation_after_call', 'has_cei_violation',
      'has_untainted_external_call', 'has_no_input_validation', 'has_owner_check',
      'has_msg_sender_check', 'has_tx_origin_check', 'has_unchecked_arithmetic',
      'has_overflow_risk', 'has_underflow_risk', 'has_hardcoded_address', 'has_missing_auth',
      'porosity_x_reentrancy_findings', 'porosity_x_taint_source_count',
      'porosity_x_invariant_candidates', 'porosity_x_external_dependencies',
      'porosity_x_function_count', 'porosity_x_call_graph_edges'
    ];
  }

  private static extractStructuralFeatures(ast: ASTSourceUnit): StructuralFeatures {
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

    return features;
  }

  private static extractControlFlowFeatures(cfgs: CFG[], taintFeatures: TaintFeatureVector): ControlFlowFeatures {
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
      taintSinkCount: taintFeatures.numSinks,
      taintPathCount: taintFeatures.numPaths,
      hasTaintedPath: taintFeatures.numPaths > 0,
      hasReentrantPath: taintFeatures.hasReentrantPath,
      hasTaintedStorageWrite: taintFeatures.hasTaintedStorageWrite,
      maxTaintDepth: taintFeatures.maxTaintDepth
    };
  }

  private static extractSemanticFeatures(ast: ASTSourceUnit, cfgs: CFG[], source: string): SemanticPatternFeatures {
    const patternsMatched: string[] = [];
    const reentrancyPatterns: string[] = [];
    const accessControlPatterns: string[] = [];
    const arithmeticPatterns: string[] = [];

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

    // Access control patterns
    const hasMsgSenderCheck = source.includes('msg.sender') || source.includes('require(msg.sender');
    const hasOnlyOwnerModifier = source.includes('onlyOwner');
    const hasTxOriginCheck = source.includes('tx.origin') && !hasMsgSenderCheck;

    if (hasMsgSenderCheck) accessControlPatterns.push('msg_sender_check');
    if (hasOnlyOwnerModifier) accessControlPatterns.push('only_owner_modifier');
    if (!hasMsgSenderCheck && !hasOnlyOwnerModifier) {
      accessControlPatterns.push('missing_access_control');
    }

    // Arithmetic patterns
    const hasUncheckedArithmetic = source.includes('unchecked {');
    const hasOverflowRisk = source.includes('+') && !source.includes('require') && !hasUncheckedArithmetic;

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

    return {
      patternsMatched,
      reentrancyPatterns,
      accessControlPatterns,
      arithmeticPatterns,
      reentrancyRisk,
      accessControlRisk,
      arithmeticRisk,
      overallRisk
    };
  }

  private static extractVulnerabilityFeatures(
    ast: ASTSourceUnit,
    cfgs: CFG[],
    taintFeatures: TaintFeatureVector,
    source: string
  ): VulnerabilityPatternFeatures {
    const hasExternalCall = cfgs.some(cfg =>
      cfg.nodes.some(n => n.taintSummary.hasExternalCall)
    );
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
    const hasTaintedExternalCallTarget = taintFeatures.sourceTypes.includes('caller') ||
                                         taintFeatures.sourceTypes.includes('calldata');
    const hasTaintedExternalCallValue = taintFeatures.hasReentrantPath;
    const hasNoInputValidation = taintFeatures.numSources > 0 &&
                                         !taintFeatures.pathLabels.filter(p => p.maxPriority >= 3).length;
    const hasUntaintedExternalCall = hasExternalCall && !hasTaintedExternalCallTarget;

    // Access control — detect from source patterns
    const hasOnlyOwnerModifier = source.includes('onlyOwner');
    const hasMsgSenderCheck = source.includes('msg.sender') || source.includes('require(msg.sender') ||
                              taintFeatures.sourceTypes.includes('caller');
    const hasOwnerCheck = hasMsgSenderCheck || source.includes('owner') && source.includes('require');
    const hasTxOriginCheck = source.includes('tx.origin') && !hasMsgSenderCheck;

    // Arithmetic — detect from source patterns
    // Only flag overflow risk if arithmetic operators appear in actual code
    // (not just comments or strings). We check for +=, +=, +, - in the context
    // of assignment expressions, which is a good proxy for arithmetic operations.
    const hasUncheckedArithmetic = source.includes('unchecked {');
    const hasArithmeticOps = /\+|\*|-|\/|>/.test(source.replace(/\/\/.*/g, '').replace(/\/\*[\s\S]*?\*\//g, ''));
    const hasOverflowRisk = hasArithmeticOps && !source.includes('SafeMath') && !hasUncheckedArithmetic &&
                             !source.includes('pragma solidity ^0.8');
    const hasUnderflowRisk = hasArithmeticOps && !source.includes('require') && !hasUncheckedArithmetic;

    // Authorization
    const hasHardcodedAddress = /0x[a-fA-F0-9]{40}/.test(source);
    const hasMissingAuth = !hasMsgSenderCheck && !hasOnlyOwnerModifier;

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
      hasHardcodedAddress,
      hasMissingAuth
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
    pushNum('taint_sink_count', features.controlFlow.taintSinkCount);
    pushNum('taint_path_count', features.controlFlow.taintPathCount);
    pushBool('has_tainted_path', features.controlFlow.hasTaintedPath);
    pushBool('has_reentrant_path', features.controlFlow.hasReentrantPath);
    pushBool('has_tainted_storage_write', features.controlFlow.hasTaintedStorageWrite);
    pushNum('max_taint_depth', features.controlFlow.maxTaintDepth);

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

