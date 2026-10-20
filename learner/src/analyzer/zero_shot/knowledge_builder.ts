/**
 * Knowledge Graph Builder.
 *
 * Builds a knowledge graph from embedded documentation facts extracted from
 * Solidity docs, EVM docs, and Ethereum Yellow Paper concepts.
 *
 * In a full deployment, this would be populated by ingest_documentation.ts
 * downloading real docs. Here we embed the most critical security facts
 * directly, so the system works without network access.
 */
import { Logger } from '../../lib/logger.js';
import { KnowledgeGraphImpl, KnowledgeRelation, KnowledgeFact } from '../knowledge/docs_processor.js';

const log = new Logger('kg-builder');

export class KnowledgeGraphBuilder {
  private graph: KnowledgeGraphImpl;
  private factCounter: number = 0;

  constructor() {
    this.graph = new KnowledgeGraphImpl();
  }

  build(): KnowledgeGraphImpl {
    log.info('Building knowledge graph from documentation facts...');

    // =========================================================================
    // From Solidity Documentation: Security Considerations
    // https://docs.soliditylang.org/en/latest/security-considerations.html
    // =========================================================================

    this.addFact('msg.sender', 'RISKS', 'reentrancy', 0.9,
      'msg.sender can be manipulated in reentrant calls — the caller changes on each reentry',
      'solidity-docs:security-considerations');

    this.addFact('external_call', 'CAUSES', 'reentrancy_if_state_updated_after', 0.95,
      'External calls to untrusted contracts can call back into the calling contract before state updates complete',
      'solidity-docs:security-considerations');

    this.addFact('state_change', 'CONSTRAINT', 'must_happen_before_external_call', 0.85,
      'State changes to balances and counters should happen BEFORE external calls (checks-effects-interactions pattern)',
      'solidity-docs:security-considerations');

    this.addFact('tx.origin', 'CAN_BE_MANIPULATED_BY', 'phishing_attack', 0.9,
      'tx.origin can be manipulated via phishing — a malicious contract can be in the call chain and tx.origin will point to the original sender',
      'solidity-docs:security-considerations');

    this.addFact('tx.origin', 'EXPLOIT_PATTERN', 'authorization_bypass', 0.85,
      'Using tx.origin for authorization allows attackers to bypass auth by tricking the owner into calling a malicious contract',
      'solidity-docs:security-considerations');

    this.addFact('uint256', 'CAUSES', 'overflow_in_solidity_lt_0.8', 0.75,
      'Unsigned integers can overflow and wrap around in Solidity versions before 0.8',
      'solidity-docs:types');

    this.addFact('arithmetic', 'CONSTRAINT', 'use_safe_math_or_solidity_0.8', 0.8,
      'Arithmetic operations should use SafeMath library or Solidity >=0.8 which has built-in overflow checks',
      'solidity-docs:security-considerations');

    this.addFact('gas', 'CONSTRAINT', 'loops_must_be_bounded', 0.9,
      'Loops have a gas limit and can fail if they process too many elements — loops should be bounded or use pull patterns',
      'solidity-docs:security-considerations');

    this.addFact('block.timestamp', 'CAN_BE_MANIPULATED_BY', 'miner_within_15s', 0.75,
      'block.timestamp can be manipulated by miners within a ~15 second window',
      'solidity-docs:security-considerations');

    this.addFact('block.timestamp', 'RISKS', 'time_dependency_manipulation', 0.8,
      'Using block.timestamp for critical decisions is risky because miners can adjust it',
      'solidity-docs:security-considerations');

    this.addFact('mapping', 'HAS_INVARIANT', 'no_length_or_iteration', 0.9,
      'Mappings do not have length or iteration capability — cannot use .length or for loops directly',
      'solidity-docs:mapping-type');

    this.addFact('external_function', 'LEADS_TO', 'attacker_controlled_code_execution', 0.85,
      'Calling an external address means the called contract code is executed, which could be attacker-controlled',
      'solidity-docs:function-calls');

    this.addFact('call_method', 'CAN_BE_MANIPULATED_BY', 'gas_limit_reduction', 0.7,
      '.call() allows specifying custom gas — if gas is limited, the callee may behave differently',
      'solidity-docs:function-calls');

    // =========================================================================
    // From EVM Documentation: Opcode Semantics
    // https://www.evm.codes/
    // =========================================================================

    this.addFact('CALL', 'OPCODE_SEMANTICS',
      'External call to address — callee code runs with caller as context if value > 0, reentrancy risk',
      0.9, '', 'evm-docs:call');

    this.addFact('DELEGATECALL', 'OPCODE_SEMANTICS',
      'Delegate call to address — code of target runs in caller storage context, can modify caller state',
      0.95, '', 'evm-docs:delegatecall');

    this.addFact('STATICCALL', 'OPCODE_SEMANTICS',
      'Static call — read-only, reverts on state modification, safe from reentrancy',
      0.9, '', 'evm-docs:staticcall');

    this.addFact('SSTORE', 'OPCODE_SEMANTICS',
      'Store value to storage — costs 20000 gas if slot was 0, 5000 if overwriting; triggers on storage change',
      0.9, '', 'evm-docs:sstore');

    this.addFact('SLOAD', 'OPCODE_SEMANTICS',
      'Load value from storage — can return stale data in reentrant calls if state not yet updated',
      0.85, '', 'evm-docs:sload');

    this.addFact('CALLVALUE', 'OPCODE_SEMANTICS',
      'Value sent to contract — attacker-controlled in payable functions',
      0.95, '', 'evm-docs:callvalue');

    this.addFact('CALLER', 'OPCODE_SEMANTICS',
      'msg.sender — changes to the caller address in reentrant calls, can be exploited',
      0.9, '', 'evm-docs:caller');

    this.addFact('ORIGIN', 'OPCODE_SEMANTICS',
      'tx.origin — top-level caller, does NOT change in reentrant calls, can be phished',
      0.95, '', 'evm-docs:origin');

    this.addFact('TIMESTAMP', 'OPCODE_SEMANTICS',
      'block.timestamp — miner-adjustable within ~15 seconds, do not use for randomization',
      0.85, '', 'evm-docs:timestamp');

    this.addFact('NUMBER', 'OPCODE_SEMANTICS',
      'block.number — can only increase, miner-influenced by up to 1 block',
      0.8, '', 'evm-docs:number');

    this.addFact('GAS', 'OPCODE_SEMANTICS',
      'Remaining gas — can be reduced by the caller to limit callee behavior',
      0.8, '', 'evm-docs:gas');

    this.addFact('BALANCE', 'OPCODE_SEMANTICS',
      'Account balance — can change between balance check and actual transfer due to external calls',
      0.85, '', 'evm-docs:balance');

    this.addFact('SELFDESTRUCT', 'OPCODE_SEMANTICS',
      'Delete contract and send remaining balance to target — permanently removes contract state',
      0.9, '', 'evm-docs:selfdestruct');

    this.addFact('CREATE', 'OPCODE_SEMANTICS',
      'Create new contract — init code runs, can fail or reenter if not handled carefully',
      0.8, '', 'evm-docs:create');

    this.addFact('CREATE2', 'OPCODE_SEMANTICS',
      'Deterministic contract creation — address can be precomputed, can be used for phishing',
      0.85, '', 'evm-docs:create2');

    // =========================================================================
    // From Ethereum Yellow Paper: Contract Semantics
    // =========================================================================

    this.addFact('state', 'CONSTRAINT',
      'All state must be finalized before any external call returns — partial state changes are risky',
      0.8, '', 'yellow-paper:state-semantics');

    this.addFact('transaction', 'HAS_INVARIANT',
      'A transaction is atomic — either all state changes happen or none do (unless using low-level calls)',
      0.95, '', 'yellow-paper:transaction-semantics');

    this.addFact('storage', 'CONSTRAINT',
      'Storage is a persistent key-value map — modifications are immediately visible to all callers',
      0.85, '', 'yellow-paper:storage');

    this.addFact('nonce', 'HAS_INVARIANT',
      'Contracts have a nonce that increments on each successful call — can be used for replay protection',
      0.7, '', 'yellow-paper:nonce');

    // =========================================================================
    // From Smart Contract Best Practices
    // =========================================================================

    this.addFact('checks_effects_interactions', 'DEFENSE_MECHANISM',
      'Checks-Effects-Interactions pattern — validate inputs (checks), update state (effects), then make external calls (interactions)',
      0.95, '', 'best-practices:patterns');

    this.addFact('pull_over_push', 'DEFENSE_MECHANISM',
      'Pull over push — prefer withdraw pattern over send pattern for payments',
      0.9, '', 'best-practices:pull-over-push');

    this.addFact('withdrawal_pattern', 'DEFENSE_MECHANISM',
      'Withdrawal pattern — store balances, let users withdraw; prevents reentrancy and DoS',
      0.95, '', 'best-practices:withdrawal');

    this.addFact('ownership', 'HAS_INVARIANT',
      'Critical functions should have proper access control via onlyOwner or similar modifiers',
      0.9, '', 'best-practices:access-control');

    this.addFact('input_validation', 'DEFENSE_MECHANISM',
      'All external inputs must be validated against expected ranges and formats before use',
      0.85, '', 'best-practices:input-validation');

    this.addFact('upgradability', 'RISKS',
      'Proxy contracts and delegatecall can introduce unexpected storage layout issues',
      0.8, '', 'best-practices:upgradability');

    // =========================================================================
    // From EIPs: Key Security Considerations
    // =========================================================================

    this.addFact('EIP-712', 'CONSTRAINT',
      'Typed structured data signing should validate the structure — partial signatures are dangerous',
      0.8, '', 'eips:eip-712');

    this.addFact('EIP-2929', 'SEMANTIC_RULE',
      'Gas cost changes for certain opcodes make previously affordable calls expensive — affects gas estimation',
      0.75, '', 'eips:eip-2929');

    this.addFact('EIP-2930', 'SEMANTIC_RULE',
      'Access lists can optimize gas but accessing unauthorized storage slots causes gas penalties',
      0.7, '', 'eips:eip-2930');

    this.addFact('EIP-1654', 'CONSTRAINT',
      'Smart contract operations should include proper error handling for partial failures',
      0.7, '', 'eips:smart-contract-best-practices');

    // =========================================================================
    // EVM Gas and Security
    // =========================================================================

    this.addFact('FORWARDSIZE', 'OPCODE_SEMANTICS',
      'Forwarded gas — when calling a contract, the callee gets 63/64 of remaining gas',
      0.8, '', 'evm-docs:gas-rules');

    this.addFact('REVERT', 'OPCODE_SEMANTICS',
      'Revert rolls back all state changes — but gas is still consumed, and nested reverts may leave partial state',
      0.85, '', 'evm-docs:revert');

    this.addFact('INVALID', 'OPCODE_SEMANTICS',
      'Invalid opcode consumes all remaining gas and immediately terminates — does not trigger on-chain revert',
      0.9, '', 'evm-docs:invalid');

    // =========================================================================
    // Language Gotchas from Solidity Docs
    // =========================================================================

    this.addFact('function_selector', 'LANGUAGE_GOTCHA',
      'Function selectors are the first 4 bytes of keccak256 of the signature — collisions possible but rare',
      0.8, '', 'solidity-docs:function-selector');

    this.addFact('fallback', 'LANGUAGE_GOTCHA',
      'Fallback functions execute on receive() and can be reentrant — use reentrancy guards',
      0.9, '', 'solidity-docs:fallback');

    this.addFact('constructor', 'LANGUAGE_GOTCHA',
      'Constructor code only runs once at deployment — cannot be called again after',
      0.7, '', 'solidity-docs:constructor');

    this.addFact('this_address', 'LANGUAGE_GOTCHA',
      'this.address is the contract address, not msg.sender — external calls via this use the contract balance',
      0.8, '', 'solidity-docs:this');

    // =========================================================================
    // Cross-document Correlations
    // =========================================================================

    this.addFact('external_call', 'RISKS',
      'External calls are dangerous because the callee is not controlled and may reenter before state is finalized',
      0.95, '', 'cross-document:reentrancy');

    this.addFact('state_change', 'DEPENDS_ON',
      'External calls — must complete all state changes before and after to maintain integrity',
      0.9, '', 'cross-document:checks-effects');

    this.addFact('owner', 'TRUST_SOURCE',
      'msg.sender as owner check is only safe if no external calls precede it in the same function',
      0.85, '', 'cross-document:access-control');

    this.addFact('balance', 'DEPENDS_ON',
      'External calls — balance changes must be tracked atomically or use withdrawal pattern',
      0.9, '', 'cross-document:balances');

    log.info(`Knowledge graph built: ${this.graph.size()} facts`);

    // Print distribution
    const relations = new Map<string, number>();
    for (const fact of this.graph.facts.values()) {
      const key = fact.relation;
      relations.set(key, (relations.get(key) || 0) + 1);
    }

    log.info('Fact distribution by relation type:');
    for (const [rel, count] of Array.from(relations.entries()).sort((a, b) => (b[1] || 0) - (a[1] || 0))) {
      log.info(`  ${rel}: ${count}`);
    }

    return this.graph;
  }

  private addFact(
    subject: string,
    relation: KnowledgeRelation,
    object: string,
    confidence: number,
    context: string,
    source: string
  ): void {
    const id = `fact_${this.factCounter++}`;
    this.graph.add({
      id,
      subject,
      relation,
      object,
      confidence,
      source,
      context,
      tags: [this.extractTag(source)]
    });
  }

  private extractTag(source: string): string {
    return source.split(':')[0] || 'unknown';
  }
}

/**
 * Create a knowledge graph pre-populated with embedded security facts.
 */
export function createDefaultKnowledgeGraph(): KnowledgeGraphImpl {
  const builder = new KnowledgeGraphBuilder();
  return builder.build();
}
