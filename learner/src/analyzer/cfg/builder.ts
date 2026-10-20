/**
 * Control Flow Graph (CFG) Builder.
 *
 * Converts a Solidity AST into a Control Flow Graph with:
 * - Basic blocks (sequences of statements with single entry/exit)
 * - Control flow edges (unconditional, conditional, back-edges for loops)
 * - Entry and exit nodes
 * - Dominator tree
 * - Loop nesting detection
 *
 * The CFG is the "G" in the AST+CFG Transformer. Each node represents
 * a program point; edges represent possible control flow.
 * Data flow information (taint, storage writes, external calls) is
 * attached as node-level summaries.
 */

import {
  ASTNode,
  ASTSourceUnit,
  ASTContractDefinition,
  ASTFunctionDefinition,
  ASTBlock,
  ASTIfStatement,
  ASTForStatement,
  ASTWhileStatement,
  ASTDoWhileStatement,
  ASTSwitchStatement,
  ASTReturn,
  ASTBreak,
  ASTContinue,
  ASTThrow,
  ASTEmitStatement,
  ASTTryCatch,
  ASTExpressionStatement,
  ASTRevertStatement,
  isExpression,
  isStatement,
} from '../ast/types.js';
import { SolidityParser } from '../ast/parser.js';
import { TaintGraph, TaintEdge } from '../taint/graph.js';

// ===========================================================================
// CFG Node and Edge Types
// ===========================================================================

export type CFGNodeKind =
  | 'ENTRY'
  | 'EXIT'
  | 'BLOCK'        // Basic block with statements
  | 'IF'           // If statement condition
  | 'WHILE'        // While loop condition
  | 'FOR_INIT'     // For loop init
  | 'FOR_COND'     // For loop condition
  | 'FOR_UPDATE'   // For loop update expression
  | 'BREAK'        | 'CONTINUE'
  | 'RETURN'       | 'REVERT' | 'THROW'
  | 'SWITCH'       // Switch statement
  | 'CASE'         // Switch case
  | 'TRY'          // Try block
  | 'CATCH'        // Catch block
  | 'CALL'         // Function call (external)
  | 'JOIN';        // Control flow join point

export interface CFGNode {
  id: number;
  kind: CFGNodeKind;
  label: string;
  // Statements contained in this node (for BLOCK, IF, etc.)
  statements: (ASTNode | any)[];
  // Function call info if this is a CALL node
  call?: {
    name: string;
    isExternal: boolean;
    isLowLevel: boolean;
    arguments: number;
    targetTainted: boolean;
    valueTainted: boolean;
  };
  // Condition expression (for IF, WHILE)
  condition?: string;
  // Storage mutations in this block
  stateMutations: StateMutation[];
  // Taint summary
  taintSummary: TaintSummary;
  // Loop info
  inLoop: boolean;
  loopDepth: number;
}

export interface CFGEdge {
  from: number;
  to: number;
  edgeType: 'UNCONDITIONAL' | 'CONDITIONAL_TRUE' | 'CONDITIONAL_FALSE' | 'BACK_EDGE' | 'EXCEPTION';
  label?: string;
  condition?: string;
}

export interface StateMutation {
  slot: string;        // Storage slot or variable name
  isTainted: boolean;  // Whether the written value is attacker-controlled
  sourceExpr: string;  // Pseudocode of what's being written
  pc: number;          // Approximate program position
}

export interface TaintSummary {
  hasTaintedInput: boolean;       // CALLDATALOAD / msg.sender / msg.value in this block
  hasExternalCall: boolean;       // CALL/DELEGATECALL/STATICCALL
  hasStateMutation: boolean;      // SSTORE equivalent
  externalCalls: ExternalCallInfo[];
  storageSlotsWritten: string[];
}

export interface ExternalCallInfo {
  target: string;           // Who's being called
  isTainted: boolean;       // Target is attacker-controlled
  value: string;            // Call value expression
  valueTainted: boolean;    // Value is attacker-controlled
  callType: 'low-level' | 'high-level';
  reentrancyRisk: 'none' | 'check'; // Whether this call is followed by a state mutation
}

export interface CFG {
  /** Ordered list of nodes */
  nodes: CFGNode[];
  /** Edges forming the control flow */
  edges: CFGEdge[];
  /** Node ID of the entry node */
  entry: number;
  /** Node ID of the exit node */
  exit: number;
  /** Map from AST node ID to CFG node IDs where it appears */
  astNodeMap: Map<number, number[]>;
  /** Function-level metadata */
  functionInfo: {
    name: string | null;
    selector: string;
    isPayable: boolean;
    isView: boolean;
    isPure: boolean;
    visibility: string;
    parameters: string[];
    returnParameters: string[];
  };
  /** Dominators for each node ID */
  dominators: Map<number, Set<number>>;
  /** Loop info: back-edges and loop bodies */
  loops: LoopInfo[];
  /** Taint graph for this CFG */
  taintGraph: TaintGraph;
}

export interface LoopInfo {
  header: number;          // Loop header node ID
  body: number[];         // Body node IDs
  exits: number[];        // Exit node IDs
  backEdge: { from: number; to: number };
}

// ===========================================================================
// CFG Builder
// ===========================================================================

export class CFGBuilder {
  private nodeCounter: number = 0;
  private edges: CFGEdge[] = [];
  private nodes: CFGNode[] = [];
  private astNodeMap: Map<number, number[]> = new Map();
  private breakTargets: number[] = [];
  private continueTargets: number[] = [];
  private currentLoopDepth: number = 0;
  private currentFunctionInfo: CFG['functionInfo'] | null = null;

  /**
   * Build a CFG from Solidity source code.
   */
  static buildFromSource(source: string, sourcePath: string = 'source.sol'): CFG[] {
    const ast = SolidityParser.parse(source, sourcePath);
    const builder = new CFGBuilder();
    return builder.buildFromAST(ast);
  }

  /**
   * Build CFGs from a parsed AST.
   * Returns one CFG per function in each contract.
   */
  buildFromAST(ast: ASTSourceUnit): CFG[] {
    const cfgs: CFG[] = [];

    for (const child of ast.children) {
      if (child.nodeType === 'ContractDefinition') {
        const contract = child as ASTContractDefinition;
        for (const member of contract.subNodes) {
          if (member.nodeType === 'FunctionDefinition') {
            const func = member as ASTFunctionDefinition;
            if (func.implemented && func.body) {
              const cfg = this.buildFunctionCFG(func);
              if (cfg) cfgs.push(cfg);
            }
          }
        }
      }
    }

    return cfgs;
  }

  private buildFunctionCFG(func: ASTFunctionDefinition): CFG | null {
    this.nodeCounter = 0;
    this.edges = [];
    this.nodes = [];
    this.astNodeMap = new Map();
    this.breakTargets = [];
    this.continueTargets = [];
    this.currentLoopDepth = 0;

    const params = func.parameters.parameters.map(p => `${p.name || 'arg'}: ${p.typeName?.type || 'unknown'}`);
    const retParams = func.returnParameters.parameters.map(p => `${p.name || 'ret'}: ${p.typeName?.type || 'unknown'}`);

    const functionInfo = {
      name: func.name,
      selector: this.computeSelector(func),
      isPayable: func.isPayable,
      isView: func.isView,
      isPure: func.isPure,
      visibility: func.visibility,
      parameters: params,
      returnParameters: retParams
    };

    // Store function info so buildStatement can access parameters for taint analysis
    this.currentFunctionInfo = functionInfo;

    // Create entry and exit nodes
    const entryId = this.createNode('ENTRY', 'function entry', [], functionInfo);
    const exitId = this.createNode('EXIT', 'function exit', [], functionInfo);

    // Track break/continue targets for this function
    const funcBreakTargets: number[] = [];
    const funcContinueTargets: number[] = [];

    // Build CFG from function body
    if (func.body) {
      const bodyNodes = this.buildStatements(func.body.statements, entryId);
      if (bodyNodes.length > 0) {
        // Connect last body node to exit
        for (const lastNode of bodyNodes) {
          this.addEdge(lastNode, exitId, 'UNCONDITIONAL');
        }
      } else {
        this.addEdge(entryId, exitId, 'UNCONDITIONAL');
      }
    } else {
      // No body (abstract function) — connect directly
      this.addEdge(entryId, exitId, 'UNCONDITIONAL');
    }

    // Connect any leftover break/continue targets to exit
    for (const target of funcBreakTargets) {
      this.addEdge(target, exitId, 'UNCONDITIONAL');
    }

    // Compute dominators
    const dominators = this.computeDominators();

    // Detect loops
    const loops = this.detectLoops();

    // Build taint graph
    const taintGraph = new TaintGraph(this.nodes, this.edges);

    return {
      nodes: this.nodes,
      edges: this.edges,
      entry: entryId,
      exit: exitId,
      astNodeMap: this.astNodeMap,
      functionInfo,
      dominators,
      loops,
      taintGraph
    };
  }

  private createNode(
    kind: CFGNodeKind,
    label: string,
    statements: (ASTNode | any)[],
    functionInfo?: CFG['functionInfo']
  ): number {
    const id = this.nodeCounter++;
    const stateMutations: StateMutation[] = statements
      .filter(s => 'expression' in s && (s as any).expression?.type === 'Assignment')
      .map(s => this.extractStateMutation((s as any).expression));

    // Fall back to current function's info for taint analysis
    const effectiveFunctionInfo = functionInfo || this.currentFunctionInfo ||
      { name: '', selector: '', isPayable: false, isView: false, isPure: false,
        visibility: 'public', parameters: [], returnParameters: [] };
    const taintSummary = this.computeTaintSummary(statements, effectiveFunctionInfo);
    const callInfo = this.extractCallInfo(statements, effectiveFunctionInfo);

    const node: CFGNode = {
      id,
      kind,
      label,
      statements,
      call: callInfo,
      stateMutations,
      taintSummary,
      inLoop: false,
      loopDepth: 0
    };

    this.nodes.push(node);
    return id;
  }

  private addEdge(from: number, to: number, edgeType: CFGEdge['edgeType'], condition?: string, label?: string): void {
    this.edges.push({
      from,
      to,
      edgeType,
      condition,
      label
    });
  }

  private buildStatements(
    statements: (ASTNode | any)[],
    prevNodeId: number
  ): number[] {
    let currentIds: number[] = [prevNodeId];

    for (const stmt of statements) {
      const result = this.buildStatement(stmt, currentIds);
      currentIds = result.length > 0 ? result : currentIds;
    }

    return currentIds;
  }

  private buildStatement(stmt: ASTNode, predecessors: number[]): number[] {
    if (!stmt) {
      return predecessors;
    }

    // Map AST node for reference
    const astId = this.astNodeMap.size + 1;
    this.astNodeMap.set(astId, []);

    switch (stmt.nodeType) {
      case 'Block': {
        const block = stmt as ASTBlock;
        const newIds = this.buildStatements(block.statements, ...(predecessors as [number]));
        this.astNodeMap.get(astId)!.push(...newIds.map(n => n));
        return newIds;
      }

      case 'ExpressionStatement': {
        const exprStmt = stmt as ASTExpressionStatement;
        const nodeId = this.createNode('BLOCK', `expr: ${exprStmt.expression.type}`, [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL');
        }
        this.astNodeMap.get(astId)!.push(nodeId);
        return [nodeId];
      }

      case 'IfStatement': {
        const ifStmt = stmt as ASTIfStatement;
        return this.buildIfStatement(ifStmt, predecessors);
      }

      case 'ForStatement': {
        const forStmt = stmt as ASTForStatement;
        return this.buildForStatement(forStmt, predecessors);
      }

      case 'WhileStatement': {
        const whileStmt = stmt as ASTWhileStatement;
        return this.buildWhileStatement(whileStmt, predecessors);
      }

      case 'DoWhileStatement': {
        const doWhileStmt = stmt as ASTDoWhileStatement;
        return this.buildDoWhileStatement(doWhileStmt, predecessors);
      }

      case 'SwitchStatement': {
        const switchStmt = stmt as ASTSwitchStatement;
        return this.buildSwitchStatement(switchStmt, predecessors);
      }

      case 'Return': {
        const returnStmt = stmt as ASTReturn;
        const nodeId = this.createNode('RETURN', 'return', [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL', undefined, 'return');
        }
        this.astNodeMap.get(astId)!.push(nodeId);
        return []; // Return is a terminator
      }

      case 'Break': {
        const nodeId = this.createNode('BREAK', 'break', [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL');
        }
        if (this.breakTargets.length > 0) {
          const target = this.breakTargets[this.breakTargets.length - 1];
          this.addEdge(nodeId, target, 'UNCONDITIONAL');
        }
        return [];
      }

      case 'Continue': {
        const nodeId = this.createNode('CONTINUE', 'continue', [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL');
        }
        if (this.continueTargets.length > 0) {
          const target = this.continueTargets[this.continueTargets.length - 1];
          this.addEdge(nodeId, target, 'UNCONDITIONAL');
        }
        return [];
      }

      case 'RevertStatement': {
        const revertStmt = stmt as ASTRevertStatement;
        const nodeId = this.createNode('REVERT', 'revert', [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL');
        }
        return [];
      }

      case 'Throw': {
        const nodeId = this.createNode('THROW', 'throw', [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL');
        }
        return [];
      }

      case 'EmitStatement': {
        const emitStmt = stmt as any;
        const nodeId = this.createNode('BLOCK', `emit: ${emitStmt.eventCall?.name || emitStmt.name || 'unknown'}`, [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL');
        }
        this.astNodeMap.get(astId)!.push(nodeId);
        return [nodeId];
      }

      case 'TryCatch': {
        return this.buildTryCatch(stmt as ASTTryCatch, predecessors);
      }

      default:
        // If it's not a recognized statement, treat as a block
        const nodeId = this.createNode('BLOCK', `stmt: ${stmt.nodeType}`, [stmt]);
        for (const pred of predecessors) {
          this.addEdge(pred, nodeId, 'UNCONDITIONAL');
        }
        this.astNodeMap.get(astId)!.push(nodeId);
        return [nodeId];
    }
  }

  private buildIfStatement(ifStmt: ASTIfStatement, predecessors: number[]): number[] {
    const astId = this.astNodeMap.size + 1;
    const condLabel = this.expressionToString(ifStmt.condition);

    // Condition node
    const condNodeId = this.createNode('IF', `if(${condLabel})`, []);
    for (const pred of predecessors) {
      this.addEdge(pred, condNodeId, 'UNCONDITIONAL');
    }
    this.astNodeMap.set(astId, [condNodeId]);

    // Then body
    let thenIds: number[] = [];
    if (ifStmt.body.nodeType === 'Block') {
      thenIds = this.buildStatements((ifStmt.body as ASTBlock).statements, condNodeId);
    } else if (ifStmt.body) {
      thenIds = this.buildStatement(ifStmt.body, [condNodeId]);
    }

    // Else body
    let elseIds: number[] = [];
    if (ifStmt.elseBody) {
      if (ifStmt.elseBody.nodeType === 'Block') {
        elseIds = this.buildStatements((ifStmt.elseBody as ASTBlock).statements, condNodeId);
      } else if (ifStmt.elseBody.nodeType === 'IfStatement') {
        // else if — chain directly
        elseIds = this.buildStatement(ifStmt.elseBody, [condNodeId]);
      } else {
        elseIds = this.buildStatement(ifStmt.elseBody, [condNodeId]);
      }
    }

    // Create join node
    const joinId = this.createNode('JOIN', 'if-join', []);

    // Connect then-branch to join (true edge)
    for (const thenNode of thenIds) {
      this.addEdge(thenNode, joinId, 'UNCONDITIONAL', undefined, 'then');
    }
    if (thenIds.length === 0) {
      this.addEdge(condNodeId, joinId, 'CONDITIONAL_TRUE');
    }

    // Connect else-branch to join (false edge)
    for (const elseNode of elseIds) {
      this.addEdge(elseNode, joinId, 'UNCONDITIONAL', undefined, 'else');
    }
    if (elseIds.length === 0) {
      this.addEdge(condNodeId, joinId, 'CONDITIONAL_FALSE');
    }

    return [joinId];
  }

  private buildForStatement(forStmt: ASTForStatement, predecessors: number[]): number[] {
    const astId = this.astNodeMap.size + 1;

    // Init expression node
    let initIds: number[] = predecessors;
    if (forStmt.initExpression) {
      const initNodeId = this.createNode('FOR_INIT', `for-init: ${this.expressionToString(forStmt.initExpression)}`, []);
      for (const pred of predecessors) {
        this.addEdge(pred, initNodeId, 'UNCONDITIONAL');
      }
      initIds = [initNodeId];
    }

    // Condition node
    const condLabel = forStmt.condition
      ? this.expressionToString(forStmt.condition)
      : 'true';
    const condNodeId = this.createNode('FOR_COND', `for-cond: ${condLabel}`, []);

    for (const initId of initIds) {
      this.addEdge(initId, condNodeId, 'UNCONDITIONAL');
    }

    // Set up break/continue targets
    const loopBreak: number[] = [];
    const loopContinue: number[] = [];

    // Continue target is the condition node (or update node if present)
    const continueTarget = forStmt.loopExpression ? null : condNodeId;

    // Build body
    this.currentLoopDepth++;
    this.breakTargets.push(condNodeId); // Break exits the loop

    let bodyIds: number[] = [];
    if (forStmt.body.nodeType === 'Block') {
      bodyIds = this.buildStatements((forStmt.body as ASTBlock).statements, condNodeId);
    } else if (forStmt.body) {
      bodyIds = this.buildStatement(forStmt.body, [condNodeId]);
    }

    this.breakTargets.pop();
    this.currentLoopDepth--;

    // Loop update node
    let updateIds: number[] = bodyIds;
    if (forStmt.loopExpression) {
      const updateNodeId = this.createNode('FOR_UPDATE', `for-update: ${this.expressionToString(forStmt.loopExpression)}`, []);
      for (const bodyId of bodyIds) {
        this.addEdge(bodyId, updateNodeId, 'UNCONDITIONAL');
      }
      // Also connect continue to update
      updateIds = [updateNodeId];
    }

    // Back edge: update → condition
    for (const updId of updateIds) {
      this.addEdge(updId, condNodeId, 'BACK_EDGE');
    }

    // Join node after loop
    const joinId = this.createNode('JOIN', 'for-join', []);

    // Exit edge from condition (false branch)
    this.addEdge(condNodeId, joinId, 'CONDITIONAL_FALSE');

    return [joinId];
  }

  private buildWhileStatement(whileStmt: ASTWhileStatement, predecessors: number[]): number[] {
    const condLabel = this.expressionToString(whileStmt.condition);
    const condNodeId = this.createNode('WHILE', `while(${condLabel})`, []);

    for (const pred of predecessors) {
      this.addEdge(pred, condNodeId, 'UNCONDITIONAL');
    }

    this.currentLoopDepth++;
    this.breakTargets.push(condNodeId);
    this.continueTargets.push(condNodeId);

    // Body
    let bodyIds: number[] = [];
    if (whileStmt.body.nodeType === 'Block') {
      bodyIds = this.buildStatements((whileStmt.body as ASTBlock).statements, condNodeId);
    } else if (whileStmt.body) {
      bodyIds = this.buildStatement(whileStmt.body, [condNodeId]);
    }

    this.breakTargets.pop();
    this.continueTargets.pop();
    this.currentLoopDepth--;

    // Back edge: body → condition
    for (const bodyId of bodyIds) {
      this.addEdge(bodyId, condNodeId, 'BACK_EDGE', undefined, 'loop');
    }

    // Join node
    const joinId = this.createNode('JOIN', 'while-join', []);

    this.addEdge(condNodeId, joinId, 'CONDITIONAL_FALSE');

    return [joinId];
  }

  private buildDoWhileStatement(doWhileStmt: ASTDoWhileStatement, predecessors: number[]): number[] {
    // Body first, then condition
    this.currentLoopDepth++;
    this.breakTargets.push(-1); // Will be updated after condition node is created
    this.continueTargets.push(-1);

    let bodyIds: number[] = [];
    if (doWhileStmt.body.nodeType === 'Block') {
      bodyIds = this.buildStatements((doWhileStmt.body as ASTBlock).statements, ...(predecessors as [number]));
    } else if (doWhileStmt.body) {
      bodyIds = this.buildStatement(doWhileStmt.body, predecessors);
    }

    // Condition node
    const condLabel = this.expressionToString(doWhileStmt.condition);
    const condNodeId = this.createNode('WHILE', `while(${condLabel})`, []);

    // Connect body to condition
    for (const bodyId of bodyIds) {
      this.addEdge(bodyId, condNodeId, 'UNCONDITIONAL');
    }

    // Update break/continue targets
    this.breakTargets[this.breakTargets.length - 1] = condNodeId;
    this.continueTargets[this.continueTargets.length - 1] = condNodeId;

    // Back edge: condition → body (if true)
    this.addEdge(condNodeId, bodyIds[0] || condNodeId, 'BACK_EDGE', 'while condition true');

    this.breakTargets.pop();
    this.continueTargets.pop();
    this.currentLoopDepth--;

    // Join node
    const joinId = this.createNode('JOIN', 'dowhile-join', []);

    // Exit: condition false
    this.addEdge(condNodeId, joinId, 'CONDITIONAL_FALSE');

    return [joinId];
  }

  private buildSwitchStatement(switchStmt: ASTSwitchStatement, predecessors: number[]): number[] {
    const exprLabel = this.expressionToString(switchStmt.expression);
    const switchNodeId = this.createNode('SWITCH', `switch(${exprLabel})`, []);

    for (const pred of predecessors) {
      this.addEdge(pred, switchNodeId, 'UNCONDITIONAL');
    }

    const joinId = this.createNode('JOIN', 'switch-join', []);

    for (const caseItem of switchStmt.cases) {
      const caseNodeId = this.createNode('CASE', caseItem.expression
        ? `case: ${this.expressionToString(caseItem.expression)}`
        : 'default', caseItem.statements);

      this.addEdge(switchNodeId, caseNodeId, 'UNCONDITIONAL', caseItem.expression
        ? this.expressionToString(caseItem.expression)
        : 'default');

      const caseBodyIds = this.buildStatements(caseItem.statements, caseNodeId);
      for (const caseBodyId of caseBodyIds) {
        this.addEdge(caseBodyId, joinId, 'UNCONDITIONAL', caseItem.expression
          ? this.expressionToString(caseItem.expression)
          : 'default', 'falls through');
      }
    }

    return [joinId];
  }

  private buildTryCatch(tryCatchStmt: ASTTryCatch, predecessors: number[]): number[] {
    const tryNodeId = this.createNode('TRY', 'try', [tryCatchStmt.tryCall]);

    for (const pred of predecessors) {
      this.addEdge(pred, tryNodeId, 'UNCONDITIONAL');
    }

    const joinId = this.createNode('JOIN', 'try-catch-join', []);

    // Try body
    if (tryCatchStmt.tryCall) {
      // Parse try call body
      const tryCallStr = this.expressionToString(tryCatchStmt.tryCall);
      const tryBodyNodeId = this.createNode('BLOCK', `try-call: ${tryCallStr}`, [tryCatchStmt.tryCall]);
      this.addEdge(tryNodeId, tryBodyNodeId, 'UNCONDITIONAL', 'try body');
      this.addEdge(tryBodyNodeId, joinId, 'UNCONDITIONAL');
    }

    // Catch blocks
    for (const catchBlock of tryCatchStmt.catchBlocks) {
      const catchNodeId = this.createNode('CATCH', `catch: ${catchBlock.catchKind}`, catchBlock.block.statements);
      this.addEdge(tryNodeId, catchNodeId, 'EXCEPTION', undefined, `catch(${catchBlock.catchKind})`);
      const catchBodyIds = this.buildStatements(catchBlock.block.statements, catchNodeId);
      for (const catchBodyId of catchBodyIds) {
        this.addEdge(catchBodyId, joinId, 'UNCONDITIONAL');
      }
    }

    return [joinId];
  }

  // ===========================================================================
  // Helper methods
  // ===========================================================================

  private extractStateMutation(expr: any): StateMutation {
    if (expr.type === 'Assignment' && expr.left) {
      return {
        slot: this.expressionToString(expr.left),
        isTainted: this.isTaintedExpression(expr.right),
        sourceExpr: this.expressionToString(expr.right),
        pc: 0
      };
    }
    return {
      slot: 'unknown',
      isTainted: false,
      sourceExpr: '',
      pc: 0
    };
  }

  private isTaintedExpression(expr: any): boolean {
    if (!expr) return false;
    if (expr.isTainted) return true;
    if (expr.type === 'MemberAccess') {
      return expr.isMsgSender || expr.isMsgValue || expr.isTxOrigin || expr.isTainted;
    }
    if (expr.type === 'BinaryOperation') {
      return this.isTaintedExpression(expr.left) || this.isTaintedExpression(expr.right);
    }
    if (expr.type === 'FunctionCall') {
      return expr.arguments?.some((a: any) => this.isTaintedExpression(a)) ||
             (expr.expression ? this.isTaintedExpression(expr.expression) : false);
    }
    if (expr.type === 'Identifier') {
      return expr.isTainted;
    }
    return false;
  }

  private extractCallInfo(statements: (ASTNode | any)[], functionInfo: any): CFGNode['call'] | undefined {
    for (const stmt of statements) {
      if (stmt.nodeType === 'ExpressionStatement') {
        const expr = (stmt as ASTExpressionStatement).expression;
        if (expr.type === 'FunctionCall') {
          const call = expr as any;
          return {
            name: call.expression?.name || call.expression?.value || 'unknown',
            isExternal: call.isExternalCall || false,
            isLowLevel: call.isLowLevelCall || false,
            arguments: (call.arguments || []).length,
            targetTainted: call.targetTainted || false,
            valueTainted: call.valueTainted || false
          };
        }
      }
    }
    return undefined;
  }

  private computeTaintSummary(statements: (ASTNode | any)[], functionInfo?: CFG['functionInfo']): TaintSummary {
    const summary: TaintSummary = {
      hasTaintedInput: false,
      hasExternalCall: false,
      hasStateMutation: false,
      externalCalls: [],
      storageSlotsWritten: []
    };

    // Extract parameter names from functionInfo — parameters from calldata are
    // attacker-controlled inputs even without explicit msg.sender/tx.origin.
    // The functionInfo.parameters array contains strings like "_bonus: uint256".
    const paramNames: string[] = [];
    if (functionInfo && functionInfo.parameters) {
      for (const p of functionInfo.parameters) {
        // Extract just the name part (before ": type")
        const namePart = p.split(':')[0]?.trim();
        if (namePart && namePart !== 'arg' && namePart.length > 1) {
          paramNames.push(namePart);
        }
      }
    }
    const hasParams = paramNames.length > 0;

    for (const stmt of statements) {
      const stmtStr = JSON.stringify(stmt);

      // Check for tainted inputs — includes msg.sender, msg.value, tx.origin,
      // AND function parameters (calldata) which are also attacker-controlled.
      // Previously, only explicit msg.sender/tx.origin references were tracked,
      // which meant contracts with missing access control (no msg.sender check,
      // just a state write from a function parameter) were not flagged.
      if (stmtStr.includes('"isMsgSender":true') || stmtStr.includes('"isMsgValue":true') ||
          stmtStr.includes('"isTxOrigin":true') || stmtStr.includes('"isTainted":true')) {
        summary.hasTaintedInput = true;
      }

      // Also check for taint from function parameters — if this function has
      // parameters (calldata inputs) and they appear in a statement, the input
      // is attacker-controlled.
      if (!summary.hasTaintedInput && hasParams) {
        for (const param of paramNames) {
          if (stmtStr.includes(param)) {
            summary.hasTaintedInput = true;
            break;
          }
        }
      }

      // Check for external calls
      if (stmtStr.includes('"isExternalCall":true') || stmtStr.includes('"isLowLevelCall":true')) {
        summary.hasExternalCall = true;
      }

      // Check for state mutations (assignments)
      if (stmtStr.includes('"type":"Assignment"')) {
        summary.hasStateMutation = true;
        summary.storageSlotsWritten.push('assignment_detected');
      }
    }

    return summary;
  }

  private expressionToString(expr: any): string {
    if (!expr) return 'undefined';

    switch (expr.type) {
      case 'Identifier':
        return expr.name;
      case 'Literal':
        return String(expr.value);
      case 'MemberAccess':
        return `${this.expressionToString(expr.expression)}.${expr.name}`;
      case 'BinaryOperation':
        return `${this.expressionToString(expr.left)} ${expr.operator} ${this.expressionToString(expr.right)}`;
      case 'FunctionCall':
        return `${this.expressionToString(expr.expression)}(${expr.arguments?.map((a: any) => this.expressionToString(a)).join(', ') || ''})`;
      case 'UnaryOperation':
        return expr.prefix
          ? `${expr.operator}${this.expressionToString(expr.subExpression)}`
          : `${this.expressionToString(expr.subExpression)}${expr.operator}`;
      case 'Assignment':
        return `${this.expressionToString(expr.left)} = ${this.expressionToString(expr.right)}`;
      case 'IndexAccess':
        return `${this.expressionToString(expr.baseExpression)}[${this.expressionToString(expr.indexExpression)}]`;
      default:
        return expr.type || 'expr';
    }
  }

  private computeSelector(func: ASTFunctionDefinition): string {
    if (!func.name) return '0x00000000';

    // Compute keccak256 of function signature and take first 4 bytes
    const paramTypes = func.parameters.parameters
      .map(p => this.typeNameToString(p.typeName))
      .filter(t => t !== null);
    const signature = `${func.name}(${paramTypes.join(',')})`;

    // Simple hash for now (will be replaced with proper keccak256)
    let hash = 0;
    for (let i = 0; i < signature.length; i++) {
      hash = ((hash << 5) - hash) + signature.charCodeAt(i);
      hash |= 0;
    }

    return `0x${(hash & 0xFFFFFFFF).toString(16).padStart(8, '0')}`;
  }

  private typeNameToString(typeName: any): string | null {
    if (!typeName) return null;
    switch (typeName.type) {
      case 'ElementaryTypeName':
        return typeName.name.replace(' payable', '');
      case 'UserDefinedTypeName':
        return typeName.name;
      case 'ArrayTypeName':
        return `${this.typeNameToString(typeName.baseType)}[]`;
      case 'Mapping':
        return 'mapping';
      default:
        return typeName.name || null;
    }
  }

  /**
   * Compute dominator sets using iterative algorithm.
   */
  private computeDominators(): Map<number, Set<number>> {
    const dominators = new Map<number, Set<number>>();

    // Initialize: entry dominates only itself, all other nodes dominated by everything
    for (const node of this.nodes) {
      dominators.set(node.id, new Set());
    }

    // Find entry node
    const entryNodeId = this.nodes.find(n => n.kind === 'ENTRY')?.id ?? 0;
    const entryDom = dominators.get(entryNodeId)!;
    entryDom.add(entryNodeId);

    // Iteratively compute dominators
    let changed = true;
    while (changed) {
      changed = false;
      for (const node of this.nodes) {
        if (node.id === entryNodeId) continue;

        // dom(n) = ∩ dom(p) for all predecessors p, plus n
        const preds = this.getPredecessors(node.id);
        if (preds.length === 0) continue;

        const newDom = new Set<number>();
        const firstPredDom = dominators.get(preds[0]?.id ?? -1);
        if (!firstPredDom) continue;

        newDom.add(node.id);

        // Intersect all predecessor dominator sets
        let first = true;
        for (const pred of preds) {
          const predDom = dominators.get(pred.id);
          if (!predDom) continue;

          if (first) {
            for (const d of predDom) newDom.add(d);
            first = false;
          } else {
            for (const d of newDom) {
              if (!predDom.has(d)) {
                newDom.delete(d);
              }
            }
          }
        }

        const oldDom = dominators.get(node.id)!;
        if (newDom.size !== oldDom.size ||
            ![...newDom].every(d => oldDom.has(d))) {
          dominators.set(node.id, newDom);
          changed = true;
        }
      }
    }

    return dominators;
  }

  private getPredecessors(nodeId: number): CFGNode[] {
    return this.nodes.filter(n =>
      this.edges.some(e => e.from === n.id && e.to === nodeId)
    );
  }

  /**
   * Detect loops via back-edges (edges from a node to its ancestor).
   */
  private detectLoops(): LoopInfo[] {
    const loops: LoopInfo[] = [];
    const backEdges = this.edges.filter(e => e.edgeType === 'BACK_EDGE');

    for (const backEdge of backEdges) {
      const headerId = backEdge.to;
      const body = this.findReachableFrom(headerId, backEdge.from);
      const exits: number[] = [];

      // Find exit nodes (nodes in body that have edges to outside)
      for (const bodyId of body) {
        const nodeEdges = this.edges.filter(e => e.from === bodyId);
        for (const edge of nodeEdges) {
          if (!body.includes(edge.to) && edge.to !== headerId) {
            exits.push(edge.to);
          }
        }
      }

      loops.push({
        header: headerId,
        body,
        exits,
        backEdge: { from: backEdge.from, to: backEdge.to }
      });
    }

    // Mark nodes as in-loop
    for (const loop of loops) {
      for (const bodyId of loop.body) {
        const node = this.nodes.find(n => n.id === bodyId);
        if (node) {
          node.inLoop = true;
          node.loopDepth++;
        }
      }
    }

    return loops;
  }

  private findReachableFrom(start: number, exclude: number): number[] {
    const visited = new Set<number>();
    const queue: number[] = [start];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      const successors = this.edges
        .filter(e => e.from === current && e.to !== exclude)
        .map(e => e.to);

      for (const succ of successors) {
        if (!visited.has(succ)) {
          queue.push(succ);
        }
      }
    }

    return [...visited];
  }
}

// ===========================================================================
// Standalone function: Build CFG from Solidity source
// ===========================================================================

export function buildCFG(source: string, sourcePath: string = 'source.sol'): CFG[] {
  return CFGBuilder.buildFromSource(source, sourcePath);
}

export function parseAndBuild(source: string, sourcePath: string = 'source.sol'): {
  ast: ASTSourceUnit;
  cfgs: CFG[];
} {
  const ast = SolidityParser.parse(source, sourcePath);
  const cfgs = CFGBuilder.buildFromSource(source, sourcePath);
  return { ast, cfgs };
}
