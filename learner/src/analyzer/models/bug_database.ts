/**
 * Bug Database — Structured representation of known Solidity vulnerability patterns.
 *
 * Each bug entry encodes:
 * - Canonical pattern name and ID
 * - Vulnerable code snippet
 * - Correct fix
 * - Pattern tags (for matching)
 * - Exploit chain (step-by-step attack flow)
 * - Impact classification
 * - Difficulty rating
 *
 * This database serves as the ground truth for training the Transformer model
 * and provides the feedback loop for the reward mechanism.
 */

// ===========================================================================
// Bug Entry Schema
// ===========================================================================

export type VulnerabilityPattern =
  | 'reentrancy'
  | 'reentrancy_unrestricted'
  | 'reentrancy_cross_contract'
  | 'reentrancy_no_checksum'
  | 'integer_overflow'
  | 'integer_underflow'
  | 'arithmetic'
  | 'unchecked_arithmetic'
  | 'access_control'
  | 'owner_only'
  | 'tx_origin'
  | 'front_running'
  | 'timestamp_dependence'
  | 'block_gas_limit'
  | 'delegatecall'
  | 'delegatecall_dangerous'
  | 'flash_loan'
  | 'flash_loan_price_manipulation'
  | 'oracle_manipulation'
  | 'oracle_decentralization'
  | 'race_condition'
  | 'short_address'
  | 'randomness'
  | 'signature_replay'
  | 'permit_replay'
  | 'nonce_replay'
  | 'replay_attack'
  | 'unchecked_send'
  | 'unchecked_return_value'
  | 'gas_optimization'
  | 'dos_gas_limit'
  | 'dos_block_gas_limit'
  | 'authorization'
  | 'missing_zero_address_check'
  | 'missing_sender_auth'
  | 'incorrect_abi_encoding'
  | 'type_precision'
  | 'uninitialized_storage_pointer'
  | 'uninitialized_local_var'
  | 'uninitialized_struct'
  | 'inheritance_shadowing'
  | 'multiple_inheritance_diamond'
  | 'function_clash'
  | 'selector_clash'
  | 'abi_encoder_v2'
  | 'out_of_gas'
  | 'unbounded_loops'
  | 'unbounded_keccak'
  | 'state_change_in_loop'
  | 'storage_slot_collision'
  | 'storage_layout'
  | 'external_contract'
  | 'synchronization'
  | 'hidden_transfer'
  | 'hidden_transfer_erc777'
  | 'transfer_hook'
  | 'fee_model';

export type ExploitStep = {
  step: string;
  function?: string;
  entry?: string;
  condition?: string;
};

export type ImpactLevel = 'funds_drained' | 'access_bypassed' | 'data_corrupted' | 'service_denied' | 'governance_compromised';

export type Difficulty = 'trivial' | 'easy' | 'medium' | 'hard' | 'expert';

export interface BugEntry {
  id: string;
  title: string;
  code: string;              // Vulnerable Solidity snippet
  fix: string;               // Corrected version
  pattern: VulnerabilityPattern[];
  exploitChain: ExploitStep[];
  impact: ImpactLevel | ImpactLevel[];
  difficulty: Difficulty;
  description: string;
  cwe: string;               // CWE classification
  severity: 'low' | 'medium' | 'high' | 'critical';
  // Metadata for model training
  source: 'manual' | 'immunefi' | 'audit' | 'cve' | 'github';
  sourceReference?: string;
  lastSeen?: string;
  verified: boolean;
  detectionFeatures: string[];  // Feature names that detect this pattern
  falsePositivePatterns: string[]; // Patterns that trigger false positives
}

export interface BugDatabase {
  /** All known bugs, keyed by ID */
  bugs: Map<string, BugEntry>;

  /** Bugs indexed by pattern tag */
  byPattern: Map<VulnerabilityPattern, BugEntry[]>;

  /** Bugs indexed by impact level */
  byImpact: Map<ImpactLevel, BugEntry[]>;

  /** Bugs indexed by difficulty */
  byDifficulty: Map<Difficulty, BugEntry[]>;

  /** Total count */
  size: number;

  /** Add a bug entry */
  add(entry: BugEntry): void;

  /** Search bugs by pattern */
  searchByPattern(pattern: VulnerabilityPattern): BugEntry[];

  /** Search bugs by keyword in title or description */
  search(keyword: string): BugEntry[];

  /** Get all bugs for a given vulnerability class */
  getByImpact(impact: ImpactLevel): BugEntry[];
}

// ===========================================================================
// Bug Database Implementation
// ===========================================================================

export class SolidityBugDatabase implements BugDatabase {
  public bugs: Map<string, BugEntry> = new Map();
  public byPattern: Map<VulnerabilityPattern, BugEntry[]> = new Map();
  public byImpact: Map<ImpactLevel, BugEntry[]> = new Map();
  public byDifficulty: Map<Difficulty, BugEntry[]> = new Map();
  public size: number = 0;

  private initialized: boolean = false;

  constructor() {
    this.initializeBuiltinBugs();
  }

  add(entry: BugEntry): void {
    this.bugs.set(entry.id, entry);
    this.size++;

    for (const pattern of entry.pattern) {
      if (!this.byPattern.has(pattern)) {
        this.byPattern.set(pattern, []);
      }
      this.byPattern.get(pattern)!.push(entry);
    }

    const impacts = Array.isArray(entry.impact) ? entry.impact : [entry.impact];
    for (const impact of impacts) {
      if (!this.byImpact.has(impact)) {
        this.byImpact.set(impact, []);
      }
      this.byImpact.get(impact)!.push(entry);
    }

    if (!this.byDifficulty.has(entry.difficulty)) {
      this.byDifficulty.set(entry.difficulty, []);
    }
    this.byDifficulty.get(entry.difficulty)!.push(entry);
  }

  searchByPattern(pattern: VulnerabilityPattern): BugEntry[] {
    return this.byPattern.get(pattern) || [];
  }

  search(keyword: string): BugEntry[] {
    const lower = keyword.toLowerCase();
    const results: BugEntry[] = [];

    for (const bug of this.bugs.values()) {
      if (
        bug.title.toLowerCase().includes(lower) ||
        bug.description.toLowerCase().includes(lower) ||
        bug.pattern.some(p => p.toLowerCase().includes(lower))
      ) {
        results.push(bug);
      }
    }

    return results;
  }

  getByImpact(impact: ImpactLevel): BugEntry[] {
    return this.byImpact.get(impact) || [];
  }

  /**
   * Load bugs from a JSON data file.
   */
  loadFromFile(filePath: string): number {
    // Would use fs.readFileSync in actual implementation
    // For now, just return the count of loaded bugs
    return this.size;
  }

  /**
   * Export all bugs as JSON.
   */
  toJSON(): BugEntry[] {
    return Array.from(this.bugs.values());
  }

  private initializeBuiltinBugs(): void {
    // Reentrancy — the classicDAO bug
    this.add({
      id: 'reentrancy_001',
      title: 'Classic Reentrancy (DAO)',
      code: `contract Victim {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0);
        msg.sender.call{value: msg.value}("");  // external call
        balances[msg.sender] = 0;  // state change AFTER call — vulnerable!
    }
}`,
      fix: `contract Victim {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0);
        balances[msg.sender] = 0;  // state change BEFORE call — checks-effects-interactions
        msg.sender.call{value: amount}("");
    }
}`,
      pattern: ['reentrancy', 'access_control'],
      exploitChain: [
        { step: 'Attacker deposits tokens', function: 'deposit()' },
        { step: 'Attacker calls withdraw()', entry: 'withdraw()' },
        { step: 'External call to attacker contract re-enters withdraw()', entry: 'receive()' },
        { step: 'State not yet updated, allows repeated withdrawals', function: 'withdraw()' },
        { step: 'Drains all funds from contract', function: 'withdraw()' }
      ],
      impact: 'funds_drained',
      difficulty: 'easy',
      description: 'The classic reentrancy vulnerability — state is updated after an external call, allowing an attacker contract to recursively call back into the vulnerable function before the state change takes effect.',
      cwe: 'CWE-362',
      severity: 'critical',
      source: 'manual',
      verified: true,
      detectionFeatures: [
        'has_external_call',
        'has_state_mutation_after_call',
        'has_cei_violation',
        'sstore_after_call'
      ],
      falsePositivePatterns: ['has_owner_check']
    });

    // Integer overflow (pre-Solidity 0.8)
    this.add({
      id: 'integer_overflow_001',
      title: 'Integer Overflow (pre-Solidity 0.8)',
      code: `contract Victim {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;  // overflow if balances[to] + amount > 2^256-1
    }
}`,
      fix: `pragma solidity ^0.8.0;

contract Victim {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;  // Solidity 0.8+ has built-in overflow checks
    }
}`,
      pattern: ['integer_overflow', 'arithmetic', 'unchecked_arithmetic'],
      exploitChain: [
        { step: 'Attacker has small balance', function: 'transfer()' },
        { step: 'Craft transfer to make recipient balance overflow to small value', function: 'transfer()' },
        { step: 'Attacker now has a "large" balance due to overflow', condition: 'balances[to] wraps to small number' },
        { step: 'Withdraw or transfer the "large" balance', function: 'transfer()' }
      ],
      impact: 'funds_drained',
      difficulty: 'easy',
      description: 'Unsigned integer overflow in Solidity <0.8.0 allows balance manipulation when addition wraps around the maximum uint256 value.',
      cwe: 'CWE-190',
      severity: 'high',
      source: 'manual',
      verified: true,
      detectionFeatures: [
        'has_overflow_risk',
        'has_unchecked_arithmetic',
        'has_arithmetic_risk'
      ],
      falsePositivePatterns: ['has_overflow_risk']
    });

    // Access control — missing onlyOwner
    this.add({
      id: 'access_control_001',
      title: 'Missing Access Control',
      code: `contract Victim {
    address public owner;
    uint256 public bonus;

    function setBonus(uint256 _bonus) public {
        bonus = _bonus;  // anyone can call
    }
}`,
      fix: `contract Victim {
    address public owner;
    uint256 public bonus;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function setBonus(uint256 _bonus) public onlyOwner {
        bonus = _bonus;
    }
}`,
      pattern: ['access_control', 'owner_only', 'missing_sender_auth'],
      exploitChain: [
        { step: 'Attacker identifies unprotected setter function', function: 'setBonus()' },
        { step: 'Attacker calls setBonus() with malicious value', function: 'setBonus()' },
        { step: 'Contract state is modified by non-owner', condition: 'no access control' }
      ],
      impact: 'access_bypassed',
      difficulty: 'trivial',
      description: 'Functions that modify critical state lack access control, allowing any caller to invoke them.',
      cwe: 'CWE-284',
      severity: 'high',
      source: 'manual',
      verified: true,
      detectionFeatures: [
        'has_missing_auth',
        'has_no_input_validation'
      ],
      falsePositivePatterns: ['has_msg_sender_check']
    });

    // tx.origin phishing
    this.add({
      id: 'tx_origin_001',
      title: 'tx.origin Authentication',
      code: `contract Victim {
    address public owner;

    function transferOwnership(address newOwner) public {
        require(tx.origin == owner);  // vulnerable!
        owner = newOwner;
    }
}`,
      fix: `contract Victim {
    address public owner;

    function transferOwnership(address newOwner) public {
        require(msg.sender == owner);  // safe
        owner = newOwner;
    }
}`,
      pattern: ['tx_origin', 'access_control'],
      exploitChain: [
        { step: 'Attacker creates malicious contract with tx.origin check', function: 'attack()' },
        { step: 'Owner interacts with attacker contract (e.g., clicks link)', entry: 'malicious function call' },
        { step: 'tx.origin is still owner, so check passes', condition: 'tx.origin == owner' },
        { step: 'Attacker calls transferOwnership, owner is stolen', function: 'transferOwnership()' }
      ],
      impact: 'access_bypassed',
      difficulty: 'easy',
      description: 'Using tx.origin for authorization allows phishing attacks — if the owner is tricked into calling a malicious contract, the attacker can execute unauthorized operations.',
      cwe: 'CWE-290',
      severity: 'high',
      source: 'manual',
      verified: true,
      detectionFeatures: [
        'has_tx_origin_check'
      ],
      falsePositivePatterns: ['has_msg_sender_check']
    });

    // Timestamp dependence
    this.add({
      id: 'timestamp_dependence_001',
      title: 'Block Timestamp Dependence',
      code: `contract Victim {
    uint256 public betAmount;
    bool public resolved;
    address public winner;

    function bet() public payable {
        betAmount = msg.value;
    }

    function resolve() public {
        require(block.timestamp % 2 == 0);  // vulnerable!
        winner = msg.sender;
        resolved = true;
    }
}`,
      fix: `contract Victim {
    uint256 public betAmount;
    bool public resolved;
    address public winner;

    function resolve() public {
        uint256 seed = uint256(keccak256(abi.encodePacked(
            block.difficulty,
            block.number
        )));
        require(seed % 2 == 0);  // not miner-manipulable
        winner = msg.sender;
        resolved = true;
    }
}`,
      pattern: ['timestamp_dependence', 'randomness', 'front_running'],
      exploitChain: [
        { step: 'Attacker mines/validates the block', condition: 'miner controls block.timestamp' },
        { step: 'Attacker adjusts timestamp to satisfy or fail the condition', entry: 'block.timestamp manipulation' },
        { step: 'Attacker wins the bet or causes desired outcome', function: 'resolve()' }
      ],
      impact: 'funds_drained',
      difficulty: 'medium',
      description: 'Using block.timestamp for randomness or conditional logic allows miners to manipulate outcomes within a ~15 second window.',
      cwe: 'CWE-330',
      severity: 'medium',
      source: 'manual',
      verified: true,
      detectionFeatures: [
        'has_overflow_risk',
        'arithmetic_risk'
      ],
      falsePositivePatterns: []
    });

    // Uninitialized storage pointer (storage collision)
    this.add({
      id: 'storage_collision_001',
      title: 'Storage Layout Collision',
      code: `contract Victim {
    address public owner;
    uint256 private _initialized;

    constructor() {
        owner = msg.sender;
        _initialized = 1;
    }
}`,
      fix: `contract Victim {
    address public owner;
    uint256 private _initialized;

    constructor() {
        // Use constructor for initialization — no proxy pattern issue
        owner = msg.sender;
    }

    // If using a proxy pattern:
    // function initialize() public {
    //     require(_initialized == 0);
    //     _initialized = 1;
    //     owner = msg.sender;
    // }
}`,
      pattern: ['storage_layout', 'state_change_in_loop', 'uninitialized_struct'],
      exploitChain: [
        { step: 'Attacker deploys upgradeable proxy pointing to Victim implementation', entry: 'proxy deployment' },
        { step: 'If initializer not called, slots may overlap with attacker-controlled data', condition: 'storage collision' },
        { step: 'Attacker manipulates storage slots to change owner', function: 'arbitrary_storage_write' }
      ],
      impact: 'access_bypassed',
      difficulty: 'hard',
      description: 'Incorrect storage layout in upgradeable contracts leads to storage slot collisions, allowing attackers to overwrite critical variables like the owner address.',
      cwe: 'CWE-664',
      severity: 'critical',
      source: 'manual',
      verified: true,
      detectionFeatures: [],
      falsePositivePatterns: []
    });

    // Unchecked external call return value
    this.add({
      id: 'unchecked_send_001',
      title: 'Unchecked low-level .call() return value',
      code: `contract Victim {
    function withdraw() public {
        msg.sender.call{value: address(this).balance}("");  // no return value check
    }
}`,
      fix: `contract Victim {
    function withdraw() public {
        require(msg.sender.call{value: address(this).balance}(""));
    }
}`,
      pattern: ['unchecked_send', 'unchecked_return_value', 'reentrancy'],
      exploitChain: [
        { step: 'External call to attacker contract fails silently', condition: '.call returns false' },
        { step: 'Function continues as if call succeeded', function: 'withdraw()' },
        { step: 'State updated despite failed ETH transfer', condition: 'no revert on failure' }
      ],
      impact: 'funds_drained',
      difficulty: 'easy',
      description: 'Low-level .call() without checking the return value can lead to silent failures and inconsistent state.',
      cwe: 'CWE-754',
      severity: 'medium',
      source: 'manual',
      verified: true,
      detectionFeatures: [
        'has_external_call',
        'has_state_mutation_after_call'
      ],
      falsePositivePatterns: ['has_cei_violation']
    });

    // Denial of Service with (Unexpected) revert in fallback
    this.add({
      id: 'dos_001',
      title: 'Denial of Service via revert in loop',
      code: `contract Victim {
    address[] public payees = [0xa..., 0xb..., 0xc...];

    function distribute() public {
        for (uint i = 0; i < payees.length; i++) {
            payees[i].call{value: 1 ether}("");  // reverts if one address fails
        }
    }
}`,
      fix: `contract Victim {
    address[] public payees = [0xa..., 0xb..., 0xc...];

    function distribute() public {
        uint remaining = address(this).balance;
        for (uint i = 0; i < payees.length; i++) {
            uint amount = remaining / (payees.length - i);
            (bool success, ) = payees[i].call{value: amount}("");
            if (success) {
                remaining -= amount;
            }
        }
    }
}`,
      pattern: ['dos_gas_limit', 'dos_block_gas_limit', 'unbounded_loops', 'unchecked_return_value'],
      exploitChain: [
        { step: "Attacker's address is in payees array", function: 'become payee' },
        { step: "Attacker's fallback reverts on incoming ETH", entry: 'receive() → revert' },
        { step: 'Loop stops, other payees never receive funds', condition: 'first call fails' },
        { step: 'Denial of service for all subsequent distributions', function: 'distribute()' }
      ],
      impact: 'service_denied',
      difficulty: 'medium',
      description: 'A single failing external call within a loop can DOS all subsequent operations, affecting all users beyond the attacker.',
      cwe: 'CWE-400',
      severity: 'high',
      source: 'manual',
      verified: true,
      detectionFeatures: [
        'has_external_call',
        'unbounded_loops'
      ],
      falsePositivePatterns: []
    });
  }
}

// ===========================================================================
// Singleton instance for easy access
// ===========================================================================

export const bugDatabase = new SolidityBugDatabase();
