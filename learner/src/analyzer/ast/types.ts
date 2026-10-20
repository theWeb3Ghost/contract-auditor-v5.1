/**
 * Solidity AST node types.
 *
 * This is a lightweight AST that captures the structures we need for
 * security analysis: contract layout, function signatures, state variables,
 * control flow (if/else, for, while, revert, etc.), and expressions.
 *
 * We don't implement the full Solidity grammar — we cover the subset that
 * matters for vulnerability detection (external calls, state mutations,
 * arithmetic, conditionals, inheritance).
 */

// ---------------------------------------------------------------------------
// Source unit — top-level container
// ---------------------------------------------------------------------------

export interface ASTSourceUnit {
  type: 'SourceUnit';
  nodeType: 'SourceUnit';
  children: ASTNode[];
  sourcePaths: string[];
}

export type ASTNode =
  | ASTContractDefinition
  | ASTFunctionDefinition
  | ASTVariableDeclaration
  | ASTStructDefinition
  | ASTEnumDefinition
  | ASTModifierDefinition
  | ASTImportDirective
  | ASTUsingForDeclaration
  | ASTExpressionStatement
  | ASTIfStatement
  | ASTForStatement
  | ASTWhileStatement
  | ASTDoWhileStatement
  | ASTSwitchStatement
  | ASTBlock
  | ASTReturn
  | ASTRevertStatement
  | ASTBreak
  | ASTContinue
  | ASTThrow
  | ASTEmitStatement
  | ASTTryCatch
  | ASTDelete
  | ASTPragmaDirective;

// ---------------------------------------------------------------------------
// Contract definitions
// ---------------------------------------------------------------------------

export interface ASTContractDefinition {
  type: 'ContractDefinition';
  nodeType: 'ContractDefinition';
  scope: number;
  name: string | null;
  baseContracts: ASTBaseContract[];
  subNodes: ASTNode[];
  kind: 'contract' | 'interface' | 'library' | 'abstract';
  isFinal: boolean;
  isShadowing: boolean;
  contractDependencies: number[];
}

export interface ASTBaseContract {
  basePath: ASTExpression;
  arguments: ASTExpression[];
}

// ---------------------------------------------------------------------------
// Function definitions
// ---------------------------------------------------------------------------

export interface ASTFunctionDefinition {
  type: 'FunctionDefinition';
  nodeType: 'FunctionDefinition';
  scope: number;
  name: string | null;
  parameters: ASTParameterList;
  returnParameters: ASTParameterList;
  modifiers: ASTModifierInvocation[];
  body: ASTBlock | null;
  functionKind: 'constructor' | 'function' | 'fallback' | 'receive' | 'freeFunction';
  visibility: 'public' | 'internal' | 'private' | 'external';
  stateMutability: 'nonpayable' | 'payable' | 'view' | 'pure' | 'immutable';
  isConstructor: boolean;
  isPayable: boolean;
  isView: boolean;
  isPure: boolean;
  overrides: string[];
  implemented: boolean;
}

export interface ASTParameterList {
  type: 'ParameterList';
  nodeType: 'ParameterList';
  parameters: ASTVariableDeclaration[];
}

export interface ASTModifierInvocation {
  type: 'ModifierInvocation';
  name: string;
  arguments: ASTExpression[];
}

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

export type SolidityType = string;

export interface ASTVariableDeclaration {
  type: 'VariableDeclaration';
  nodeType: 'VariableDeclaration';
  scope: number;
  declared: number;
  isStateVar: boolean;
  isIndexed: boolean;
  isVisibleInStruct: boolean;
  isConstant: boolean;
  isImmutable: boolean;
  name: string;
  typeName: ASTTypeName | null;
  value: ASTExpression | null;
  storageLocation: 'default' | 'storage' | 'memory' | 'calldata';
  stateVariableVisibility: 'public' | 'internal' | 'private' | 'default';
  functionVisibility: 'public' | 'internal' | 'private' | 'external';
  // For analysis
  slot: number | null;
  offset: number | null;
}

export type ASTTypeName =
  | ASTElementaryTypeName
  | ASTUserDefinedTypeName
  | ASTMapping
  | ASTArrayTypeName
  | ASTFunctionTypeName;

export interface ASTElementaryTypeName {
  type: 'ElementaryTypeName';
  nodeType: 'ElementaryTypeName';
  name: string;
  typeBytes?: number;
  state: SolidityType;
}

export interface ASTUserDefinedTypeName {
  type: 'UserDefinedTypeName';
  nodeType: 'UserDefinedTypeName';
  name: string;
  path: string[];
  referencedDeclaration: number;
}

export interface ASTMapping {
  type: 'Mapping';
  nodeType: 'Mapping';
  keyType: ASTTypeName;
  keyName: string;
  valueType: ASTTypeName;
  valueName: string;
}

export interface ASTArrayTypeName {
  type: 'ArrayTypeName';
  nodeType: 'ArrayTypeName';
  baseType: ASTTypeName;
  length: ASTExpression | null;
}

export interface ASTFunctionTypeName {
  type: 'FunctionTypeName';
  nodeType: 'FunctionTypeName';
  parameterTypes: ASTParameterList;
  returnParameterTypes: ASTParameterList;
  visibility: 'public' | 'internal' | 'private' | 'external';
  stateMutability: 'nonpayable' | 'payable' | 'view' | 'pure';
}

// ---------------------------------------------------------------------------
// Struct / Enum definitions
// ---------------------------------------------------------------------------

export interface ASTStructDefinition {
  type: 'StructDefinition';
  nodeType: 'StructDefinition';
  scope: number;
  name: string;
  members: ASTVariableDeclaration[];
  kind: 'struct' | 'enum' | 'error';
  linearizable: boolean;
}

export interface ASTEnumDefinition {
  type: 'EnumDefinition';
  nodeType: 'EnumDefinition';
  name: string;
  members: ASTEnumValue[];
  linearization: string[];
}

export interface ASTEnumValue {
  type: 'EnumValue';
  nodeType: 'EnumValue';
  name: string;
  value: number;
}

// ---------------------------------------------------------------------------
// Modifiers
// ---------------------------------------------------------------------------

export interface ASTModifierDefinition {
  type: 'ModifierDefinition';
  nodeType: 'ModifierDefinition';
  scope: number;
  name: string;
  parameters: ASTParameterList;
  body: ASTBlock | null;
  isVirtual: boolean;
}

// ---------------------------------------------------------------------------
// Import directives
// ---------------------------------------------------------------------------

export interface ASTImportDirective {
  type: 'ImportDirective';
  nodeType: 'ImportDirective';
  symbolAliases: ASTSymbolAlias[];
  path: string;
}

export interface ASTSymbolAlias {
  from: string;
  to: string;
}

export interface ASTUsingForDeclaration {
  type: 'UsingForDeclaration';
  nodeType: 'UsingForDeclaration';
  typeName: ASTTypeName | null;
  functions: string[];
  isGlobal?: boolean;
}

export interface ASTPragmaDirective {
  type: 'PragmaDirective';
  nodeType: 'PragmaDirective';
  name: string;
  value: string;
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

export interface ASTBlock {
  type: 'Block';
  nodeType: 'Block';
  statements: ASTNode[];
  // Analysis metadata
  tryCallCount: number;
  tryDelegatecallCount: number;
  hasStateMutation: boolean;
}

export interface ASTExpressionStatement {
  type: 'ExpressionStatement';
  nodeType: 'ExpressionStatement';
  expression: ASTExpression;
}

export interface ASTIfStatement {
  type: 'IfStatement';
  nodeType: 'IfStatement';
  condition: ASTExpression;
  body: ASTNode; // Block
  elseBody: ASTNode | null;
  // Analysis metadata: is condition based on calldata/tainted input
  conditionTainted: boolean;
}

export interface ASTForStatement {
  type: 'ForStatement';
  nodeType: 'ForStatement';
  condition: ASTExpression | null;
  body: ASTNode; // Block
  initExpression: ASTExpression | null;
  loopExpression: ASTExpression | null;
  // Analysis: is the loop bounded by user input
  userControlledBound: boolean;
}

export interface ASTWhileStatement {
  type: 'WhileStatement';
  nodeType: 'WhileStatement';
  condition: ASTExpression;
  body: ASTNode; // Block
}

export interface ASTDoWhileStatement {
  type: 'DoWhileStatement';
  nodeType: 'DoWhileStatement';
  condition: ASTExpression;
  body: ASTNode; // Block
}

export interface ASTSwitchStatement {
  type: 'SwitchStatement';
  nodeType: 'SwitchStatement';
  expression: ASTExpression;
  cases: ASTSwitchCase[];
}

export interface ASTSwitchCase {
  type: 'SwitchCase';
  nodeType: 'SwitchCase';
  expression: ASTExpression | null; // null = default
  statements: ASTNode[];
}

export interface ASTReturn {
  type: 'Return';
  nodeType: 'Return';
  expression: ASTExpression | null;
}

export interface ASTRevertStatement {
  type: 'RevertStatement';
  nodeType: 'RevertStatement';
  Expression: ASTExpression | null; // revert() or revert("msg") or revert CustomError()
  arguments: ASTExpression[];
}

export interface ASTTryCatch {
  type: 'TryCatch';
  nodeType: 'TryCatch';
  tryCall: ASTFunctionCall;
  returnParameters: ASTParameterList;
  catchBlocks: ASTCatchBlock[];
}

export interface ASTCatchBlock {
  type: 'CatchBlock';
  nodeType: 'CatchBlock';
  arguments: ASTParameterList;
  block: ASTBlock;
  catchKind: 'default' | 'error' | 'panic' | 'revert';
}

export interface ASTBreak {
  type: 'Break';
  nodeType: 'Break';
}

export interface ASTContinue {
  type: 'Continue';
  nodeType: 'Continue';
}

export interface ASTThrow {
  type: 'Throw';
  nodeType: 'Throw';
}

export interface ASTEmitStatement {
  type: 'EmitStatement';
  nodeType: 'EmitStatement';
  eventCall: ASTFunctionCall;
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

export type ASTExpression =
  | ASTAssignment
  | ASTBinaryOperation
  | ASTFunctionCall
  | ASTIdentifier
  | ASTLiteral
  | ASTMemberAccess
  | ASTIndexAccess
  | ASTTupleExpression
  | ASTUnaryOperation
  | ASTConditional
  | ASTNewExpression
  | ASTDelete
  | ASTElementaryTypeNameExpression;

export interface ASTAssignment {
  type: 'Assignment';
  nodeType: 'Assignment';
  operator: '=' | '+=' | '-=' | '*=' | '/=' | '%=' | '<<=' | '>>=' | '&=' | '^=' | '|=';
  left: ASTExpression;
  right: ASTExpression;
  // Analysis: is the assigned value tainted
  rightTainted: boolean;
  // Analysis: is the assigned storage slot part of a co-write invariant
  storageSlotInvariant: boolean;
}

export interface ASTBinaryOperation {
  type: 'BinaryOperation';
  nodeType: 'BinaryOperation';
  operator: '==' | '!=' | '<' | '<=' | '>' | '>=' | '+' | '-' | '*' | '/' | '%' | '&&' | '||' | '&' | '|' | '^' | '<<' | '>>' | '**';
  left: ASTExpression;
  right: ASTExpression;
  // Analysis: overflow/underflow risk
  overflowRisk: 'none' | 'unchecked' | 'checked';
}

export interface ASTFunctionCall {
  type: 'FunctionCall';
  nodeType: 'FunctionCall';
  names: string[];
  arguments: ASTExpression[];
  expression: ASTExpression; // What's being called (function name, member access, etc.)
  kind: 'functionCall' | 'typeConversion' | 'superConstructor' | 'structConstructor';
  // Analysis
  isExternalCall: boolean; // .call{value:}(), .delegatecall(), .staticcall()
  isLowLevelCall: boolean; // .call, .delegatecall, .staticcall
  isHighLevelCall: boolean; // direct function call on contract
  // Low-level call info
  callValue: ASTExpression | null; // {value: ...} option
  callGas: ASTExpression | null;   // {gas: ...} option
  isPayable: boolean;
  // Taint analysis
  targetTainted: boolean;
  valueTainted: boolean;
}

export interface ASTIdentifier {
  type: 'Identifier';
  nodeType: 'Identifier';
  name: string;
  referencedDeclaration: number | null;
  // Analysis: is this a tainted variable
  isTainted: boolean;
  // Analysis: is this a constant
  isConstant: boolean;
}

export interface ASTLiteral {
  type: 'Literal';
  nodeType: 'Literal';
  value: string | number | boolean | null;
  valueType: 'string' | 'number' | 'bool' | 'address' | 'hex' | null;
  hexValue: string | null;
}

export interface ASTMemberAccess {
  type: 'MemberAccess';
  nodeType: 'MemberAccess';
  name: string;
  referencedDeclaration: number | null;
  expression: ASTExpression;
  // Analysis
  isMsgSender: boolean;
  isMsgValue: boolean;
  isTxOrigin: boolean;
  isBlockTimestamp: boolean;
  isBlockNumber: boolean;
  isThis: boolean;
  isTainted: boolean;
}

export interface ASTIndexAccess {
  type: 'IndexAccess';
  nodeType: 'IndexAccess';
  baseExpression: ASTExpression;
  indexExpression: ASTExpression;
  isTainted: boolean;
}

export interface ASTTupleExpression {
  type: 'TupleExpression';
  nodeType: 'TupleExpression';
  components: ASTExpression[];
}

export interface ASTUnaryOperation {
  type: 'UnaryOperation';
  nodeType: 'UnaryOperation';
  operator: '++' | '--' | '-' | '!' | '~' | 'delete';
  subExpression: ASTExpression;
  prefix: boolean;
}

export interface ASTConditional {
  type: 'Conditional';
  nodeType: 'Conditional';
  condition: ASTExpression;
  trueExpression: ASTExpression;
  falseExpression: ASTExpression | null;
}

export interface ASTNewExpression {
  type: 'NewExpression';
  nodeType: 'NewExpression';
  typeName: ASTTypeName;
}

export interface ASTDelete {
  type: 'Delete';
  nodeType: 'Delete';
  variable: ASTExpression;
}

export interface ASTElementaryTypeNameExpression {
  type: 'ElementaryTypeNameExpression';
  nodeType: 'ElementaryTypeNameExpression';
  typeName: string;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** All statement node types */
export type ASTStatement =
  | ASTExpressionStatement
  | ASTIfStatement
  | ASTForStatement
  | ASTWhileStatement
  | ASTDoWhileStatement
  | ASTSwitchStatement
  | ASTReturn
  | ASTRevertStatement
  | ASTBreak
  | ASTContinue
  | ASTThrow
  | ASTEmitStatement
  | ASTTryCatch
  | ASTDelete
  | ASTBlock;

/** Check if a node is a statement */
export function isStatement(node: ASTNode): node is ASTStatement {
  return 'nodeType' in node && [
    'ExpressionStatement', 'IfStatement', 'ForStatement', 'WhileStatement',
    'DoWhileStatement', 'SwitchStatement', 'Return', 'RevertStatement',
    'Break', 'Continue', 'Throw', 'EmitStatement', 'TryCatch', 'Block'
  ].includes(node.nodeType);
}

/** Check if a node is an expression */
export function isExpression(node: any): node is ASTExpression {
  return 'nodeType' in node && [
    'Assignment', 'BinaryOperation', 'FunctionCall', 'Identifier', 'Literal',
    'MemberAccess', 'IndexAccess', 'TupleExpression', 'UnaryOperation',
    'Conditional', 'NewExpression', 'Delete', 'ElementaryTypeNameExpression'
  ].includes(node.nodeType);
}

/** Check if a node is a declaration */
export function isDeclaration(node: ASTNode): boolean {
  return 'nodeType' in node && [
    'ContractDefinition', 'FunctionDefinition', 'VariableDeclaration',
    'StructDefinition', 'EnumDefinition', 'ModifierDefinition',
    'ImportDirective', 'UsingForDeclaration', 'PragmaDirective'
  ].includes(node.nodeType);
}
