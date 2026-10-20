/**
 * Taint Analysis Graph.
 *
 * Performs symbolic taint tracking over the CFG to determine which values
 * are attacker-controlled (calldata, msg.sender, msg.value, tx.origin).
 *
 * This mirrors the approach in porosity-x's taint.rs but operates at the
 * AST level rather than the bytecode level, feeding into the Transformer model
 * as explicit edge features.
 *
 * Taint sources:
 * - CALLDATALOAD → UserInput (attacker-controlled calldata)
 * - CALLER → UserInputTainted (msg.sender)
 * - CALLVALUE → UserInputTainted (msg.value)
 * - ORIGIN → UserInputTainted (tx.origin)
 * - BLOCKHASH/TIMESTAMP/NUMBER → Environmental
 *
 * Taint propagation rules:
 * - Binary operations: result is tainted if either operand is tainted
 * - Assignments: target inherits taint from source
 * - Function calls: arguments propagate taint to parameters
 * - Return: function returns tainted value if return expression is tainted
 */

import { CFGNode, CFGEdge } from '../cfg/builder.js';

// ===========================================================================
// Taint Types
// ===========================================================================

export type TaintLabel =
  | 'clean'              // No taint
  | 'calldata'           // Caller-supplied calldata (full trust boundary)
  | 'caller'             // msg.sender (full trust boundary)
  | 'msg_value'          // msg.value (full trust boundary)
  | 'tx_origin'          // tx.origin (full trust boundary)
  | 'environmental'      // BLOCKHASH, TIMESTAMP, NUMBER, etc.
  | 'derived_calldata'   // Computed from calldata (tainted)
  | 'derived_caller'     // Computed from msg.sender (tainted)
  | 'reentrancy'         // Value that could be manipulated via reentrant call
  | 'storage_tainted'    // Storage value that was written from tainted input;

// Priority: higher number = more severe trust boundary
export const TAINT_PRIORITY: Record<TaintLabel, number> = {
  clean: 0,
  environmental: 1,
  storage_tainted: 2,
  derived_calldata: 3,
  derived_caller: 3,
  calldata: 4,
  caller: 4,
  msg_value: 4,
  tx_origin: 4,
  reentrancy: 5
};

// ===========================================================================
// Taint Variables (symbolic registers)
// ===========================================================================

export interface TaintVariable {
  name: string;           // Variable/expression name
  label: TaintLabel;      // Current taint label
  source: string;         // Where this variable came from
  pc: number;             // Program counter position
  nodeId: number;         // CFG node where this variable was defined
  expression: string;     // Pseudocode representation
}

export interface TaintEdge {
  from: string;           // Source variable name
  to: string;             // Destination variable name
  edgeType: 'assignment' | 'argument' | 'return' | 'propagation' | 'call_result' | 'storage_load' | 'storage_store' | 'direct';
  condition?: string;     // Conditional taint propagation
  nodeId: number;         // CFG node where this edge was created
}

export interface TaintPath {
  source: TaintVariable;
  sink: TaintVariable;
  path: TaintEdge[];
  fullChain: boolean;     // Whether the entire chain is tainted
  maxPriority: number;    // Highest taint priority along the path
}

// ===========================================================================
// Taint Graph
// ===========================================================================

export class TaintGraph {
  /** All taint variables (symbolic registers) */
  public variables: Map<string, TaintVariable> = new Map();

  /** Taint edges (propagation relationships) */
  public edges: TaintEdge[] = [];

  /** Taint sources identified during analysis */
  public sources: TaintVariable[] = [];

  /** Taint sinks (external calls, state mutations with tainted data) */
  public sinks: TaintVariable[] = [];

  /** All taint paths from sources to sinks */
  public paths: TaintPath[] = [];

  /** CFG nodes with taint info */
  private nodes: CFGNode[];
  private cfgEdges: CFGEdge[];

  constructor(nodes: CFGNode[], cfgEdges: CFGEdge[]) {
    this.nodes = nodes;
    this.cfgEdges = cfgEdges;
    this.analyze();
  }

  /**
   * Run the full taint analysis over all CFG nodes.
   */
  private analyze(): void {
    // First pass: identify taint sources
    this.identifySources();

    // Second pass: propagate taint through CFG edges
    this.propagateTaint();

    // Third pass: find paths from sources to sinks
    this.findPaths();
  }

  /**
   * Identify initial taint sources in CFG nodes.
   */
  private identifySources(): void {
    for (const node of this.nodes) {
      if (node.taintSummary.hasTaintedInput) {
        // This node likely contains calldata or msg.sender references
        const source: TaintVariable = {
          name: `source_${node.id}`,
          label: this.classifyTaintSource(node),
          source: 'ast_analysis',
          pc: node.id,
          nodeId: node.id,
          expression: `tainted_input@block_${node.id}`
        };
        this.variables.set(source.name, source);
        this.sources.push(source);
      }

      if (node.taintSummary.hasExternalCall && node.call) {
        // Record external calls as potential sinks
        const sink: TaintVariable = {
          name: `sink_${node.id}`,
          label: node.call.targetTainted ? 'reentrancy' : 'derived_calldata',
          source: `external_call_${node.call.name}`,
          pc: node.id,
          nodeId: node.id,
          expression: `${node.call.name}(...)`
        };
        this.variables.set(sink.name, sink);
        if (node.call.targetTainted || node.call.valueTainted) {
          this.sinks.push(sink);
          // If this node ALSO has tainted input, create a direct source→sink
          // edge — the taint flows within the same statement (e.g., msg.sender.call(...)).
          if (node.taintSummary.hasTaintedInput) {
            const sourceVar = this.variables.get(`source_${node.id}`);
            if (sourceVar) {
              this.addEdge(sourceVar.name, sink.name, 'direct', undefined, node.id);
            }
          }
        }
      }

      if (node.taintSummary.hasStateMutation) {
        // Storage writes — potential sinks
        for (const slot of node.taintSummary.storageSlotsWritten) {
          const sink: TaintVariable = {
            name: `storage_sink_${node.id}_${slot}`,
            label: node.taintSummary.hasTaintedInput ? 'storage_tainted' : 'clean',
            source: 'sstore',
            pc: node.id,
            nodeId: node.id,
            expression: `SSTORE(${slot})`
          };
          this.variables.set(sink.name, sink);
          if (node.taintSummary.hasTaintedInput) {
            this.sinks.push(sink);
          }
        }
      }
    }
  }

  private classifyTaintSource(node: CFGNode): TaintLabel {
    // Check statements for specific taint indicators
    for (const stmt of node.statements) {
      const stmtStr = JSON.stringify(stmt);
      if (stmtStr.includes('"isMsgSender":true') || stmtStr.includes('"isMsgValue":true')) {
        return 'caller';
      }
      if (stmtStr.includes('"isTxOrigin":true')) {
        return 'tx_origin';
      }
      if (stmtStr.includes('"isBlockTimestamp":true') || stmtStr.includes('"isBlockNumber":true')) {
        return 'environmental';
      }
      if (stmtStr.includes('"isMsgValue":true')) {
        return 'msg_value';
      }
    }
    return 'calldata';
  }

  /**
   * Propagate taint through the CFG using worklist algorithm.
   * Creates edges from source variables → propagation variables → sink variables
   * so that findPaths() can discover paths from attacker input to vulnerable sinks.
   */
  private propagateTaint(): void {
    // Build adjacency for CFG
    const successors = new Map<number, number[]>();
    for (const edge of this.cfgEdges) {
      if (!successors.has(edge.from)) {
        successors.set(edge.from, []);
      }
      successors.get(edge.from)!.push(edge.to);
    }

    // Track the "current taint variable" at each node — this is the variable
    // that carries taint as it propagates through the CFG.
    const nodeTaintVar: Map<number, string> = new Map();

    // Worklist: process nodes that may carry taint
    const worklist: number[] = [...this.sources.map(s => s.nodeId)];
    const inWorklist = new Set(worklist);

    // Initialize source nodes: their current taint variable is their source variable
    for (const source of this.sources) {
      nodeTaintVar.set(source.nodeId, source.name);
    }

    while (worklist.length > 0) {
      const nodeId = worklist.shift()!;
      inWorklist.delete(nodeId);

      const node = this.nodes.find(n => n.id === nodeId);
      if (!node) continue;

      const currentVar = nodeTaintVar.get(nodeId);
      if (!currentVar) continue; // No taint at this node

      const succs = successors.get(nodeId) || [];
      for (const succId of succs) {
        const succNode = this.nodes.find(n => n.id === succId);
        if (!succNode) continue;

        // Create propagation variable for this CFG edge
        const varName = `propagate_${nodeId}_to_${succId}`;
        this.variables.set(varName, {
          name: varName,
          label: 'derived_calldata',
          source: `propagation_edge_${nodeId}`,
          pc: succId,
          nodeId: succId,
          expression: `propagate:${node.label} → ${succNode.label}`
        });

        // Create edge from current taint variable to propagation variable
        this.addEdge(currentVar, varName, 'propagation', undefined, succId);

        // If successor has sinks (external calls or state mutations), create edges
        // from the propagation variable to each sink variable
        if (succNode.taintSummary.hasExternalCall) {
          const sinkName = `sink_${succId}`;
          if (this.variables.has(sinkName)) {
            this.addEdge(varName, sinkName, 'argument');
          }
        }
        if (succNode.taintSummary.hasStateMutation) {
          for (const slot of succNode.taintSummary.storageSlotsWritten) {
            const sinkName = `storage_sink_${succId}_${slot}`;
            if (this.variables.has(sinkName)) {
              this.addEdge(varName, sinkName, 'storage_store');
            }
          }
        }

        // Propagate taint to successor: set the current taint variable to be
        // the propagation variable we just created
        const prevVar = nodeTaintVar.get(succId);
        if (!prevVar) {
          nodeTaintVar.set(succId, varName);
          if (!inWorklist.has(succId)) {
            worklist.push(succId);
            inWorklist.add(succId);
          }
        }
      }
    }
  }

  private addEdge(from: string, to: string, edgeType: TaintEdge['edgeType'], condition?: string, nodeId?: number): void {
    this.edges.push({ from, to, edgeType, condition, nodeId: nodeId ?? 0 });
  }

  /**
   * Find all taint paths from sources to sinks.
   */
  private findPaths(): void {
    // Build variable adjacency from edges
    const varAdj = new Map<string, string[]>();
    for (const edge of this.edges) {
      if (!varAdj.has(edge.from)) {
        varAdj.set(edge.from, []);
      }
      varAdj.get(edge.from)!.push(edge.to);
    }

    // BFS from each source to find paths to sinks
    const sinkNames = new Set(this.sinks.map(s => s.name));

    for (const source of this.sources) {
      const visited = new Set<string>();
      const queue: { var: string; path: TaintEdge[] }[] = [{ var: source.name, path: [] }];

      while (queue.length > 0) {
        const { var: current, path } = queue.shift()!;

        if (visited.has(current)) continue;
        visited.add(current);

        if (sinkNames.has(current) && path.length > 0) {
          // Found a path
          const sink = this.variables.get(current)!;
          const maxPriority = Math.max(
            TAINT_PRIORITY[source.label],
            TAINT_PRIORITY[sink.label],
            ...path.map(e => {
              const v = this.variables.get(e.to);
              return v ? TAINT_PRIORITY[v.label] : 0;
            })
          );

          this.paths.push({
            source,
            sink,
            path,
            fullChain: maxPriority >= TAINT_PRIORITY['derived_calldata'],
            maxPriority
          });
          continue; // Don't continue past sinks
        }

        const succs = varAdj.get(current) || [];
        for (const succ of succs) {
          const edges = this.edges.filter(e => e.from === current && e.to === succ);
          for (const edge of edges) {
            queue.push({ var: succ, path: [...path, edge] });
          }
        }
      }
    }
  }

  /**
   * Get a summary of the taint analysis results.
   */
  getSummary(): TaintAnalysisSummary {
    return {
      sourceCount: this.sources.length,
      sinkCount: this.sinks.length,
      pathCount: this.paths.length,
      maxTaintDepth: this.computeMaxTaintDepth(),
      reentrantPaths: this.paths.filter(p => p.source.label === 'caller' ||
                                             p.sink.label === 'reentrancy' ||
                                             p.sink.source.includes('external_call')),
      taintedStorageWrites: this.paths.filter(p => p.sink.expression.includes('SSTORE')),
      highPriorityPaths: this.paths.filter(p => p.maxPriority >= TAINT_PRIORITY['derived_calldata']),
    };
  }

  private computeMaxTaintDepth(): number {
    let maxDepth = 0;
    for (const path of this.paths) {
      maxDepth = Math.max(maxDepth, path.path.length);
    }
    return maxDepth;
  }

  /**
   * Export the taint graph as a serializable format for model input.
   */
  toFeatures(): TaintFeatureVector {
    return {
      numSources: this.sources.length,
      numSinks: this.sinks.length,
      numPaths: this.paths.length,
      maxTaintDepth: this.computeMaxTaintDepth(),
      // hasReentrantPath: true when there's a taint path from a HIGH-PRIORITY
      // source (caller/msg.sender, calldata, msg.value, tx.origin) to an
      // external call sink. This means the caller can influence what address
      // is called — the essence of reentrancy/delegatecall vulnerabilities.
      hasReentrantPath: this.paths.some(p =>
        (p.source.label === 'caller' || p.source.label === 'calldata' ||
         p.source.label === 'msg_value' || p.source.label === 'tx_origin') &&
        p.sink.source.includes('external_call')
      ),
      hasTaintedStorageWrite: this.paths.some(p => p.sink.expression.includes('SSTORE')),
      // hasTaintedExternalCall: true when there's a taint path from ANY source
      // to an external call, AND the source is at least 'derived_calldata' (priority >= 3).
      // This filters out paths from environmental sources (block.timestamp, etc.)
      // that don't represent attacker-controllable call targets.
      hasTaintedExternalCall: this.paths.some(p =>
        p.sink.source.includes('external_call') &&
        p.maxPriority >= TAINT_PRIORITY['derived_calldata']
      ),
      sourceTypes: [...new Set(this.sources.map(s => s.label))],
      sinkTypes: [...new Set(this.sinks.map(s => s.label))],
      pathLabels: this.paths.map(p => ({
        sourceLabel: p.source.label,
        sinkLabel: p.sink.label,
        depth: p.path.length,
        fullChain: p.fullChain,
        maxPriority: p.maxPriority
      }))
    };
  }
}

// ===========================================================================
// Feature Vector Types
// ===========================================================================

export interface TaintAnalysisSummary {
  sourceCount: number;
  sinkCount: number;
  pathCount: number;
  maxTaintDepth: number;
  reentrantPaths: TaintPath[];
  taintedStorageWrites: TaintPath[];
  highPriorityPaths: TaintPath[];
}

export interface TaintFeatureVector {
  numSources: number;
  numSinks: number;
  numPaths: number;
  maxTaintDepth: number;
  hasReentrantPath: boolean;
  hasTaintedStorageWrite: boolean;
  hasTaintedExternalCall: boolean;
  sourceTypes: TaintLabel[];
  sinkTypes: TaintLabel[];
  pathLabels: Array<{
    sourceLabel: TaintLabel;
    sinkLabel: TaintLabel;
    depth: number;
    fullChain: boolean;
    maxPriority: number;
  }>;
}
