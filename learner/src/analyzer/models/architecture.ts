/**
 * Transformer Model Architecture for Solidity Security Analysis.
 *
 * Architecture: Dual-Input Transformer with Cross-Attention
 *
 * The model processes two parallel representations of Solidity code:
 *
 * 1. AST Token Stream (AST attention path):
 *    - Tokenizes the Solidity source using a CodeBERT-style tokenizer
 *    - Embeds tokens into a learned embedding space
 *    - Self-attention over the token sequence captures semantic patterns
 *
 * 2. CFG Node Sequence (CFG attention path):
 *    - Linearizes the CFG into node sequences (DFS/BFS order)
 *    - Each node carries features: type, statements, state mutations, taint info
 *    - Self-attention over CFG nodes captures control-flow-dependent vulnerabilities
 *
 * 3. Cross-Attention (AST ↔ CFG):
 *    - The AST path and CFG path exchange information via cross-attention
 *    - This allows the model to correlate syntactic patterns with control flow
 *
 * 4. Porosity-X Feature Encoder:
 *    - Static analysis features (taint sources, reentrancy patterns, storage)
 *    - Injected at the bottleneck layer
 *
 * 5. Output Heads:
 *    - Vulnerability classification (multi-label)
 *    - Novel pattern detection (contrastive)
 *    - Confidence calibration
 *
 * Reward Mechanism:
 * - +1: Correctly identifies known bug pattern
 * - -1: False positive on clean code
 * - +2: Finds novel variant of known pattern
 * - -0.5: Misses a pattern present in database
 */

// ===========================================================================
// Model Configuration
// ===========================================================================

export interface ModelConfig {
  // Architecture
  dModel: number;          // Embedding dimension (default: 768)
  nhead: number;           // Number of attention heads (default: 12)
  numLayersAST: number;    // Transformer layers for AST path (default: 6)
  numLayersCFG: number;    // Transformer layers for CFG path (default: 4)
  numCrossLayers: number;  // Cross-attention layers (default: 2)
  dimFeedforward: number;  // Feedforward dimension (default: 3072)
  dropout: number;         // Dropout rate (default: 0.1)

  // Vocab
  vocabSize: number;       // AST token vocabulary size (default: 30522)
  cfgVocabSize: number;    // CFG node type vocabulary size
  maxASTLen: number;       // Max AST sequence length (default: 1024)
  maxCFGSize: number;      // Max CFG node count per function (default: 256)

  // Porosity-X features
  porosityXFeatureDim: number; // Dimension of Porosity-X features

  // Classification
  numVulnerabilityClasses: number; // Number of vulnerability types to classify

  // Training
  learningRate: number;    // AdamW learning rate
  weightDecay: number;     // Weight decay
  warmupSteps: number;     // Warmup steps
  maxSteps: number;        // Maximum training steps
  batchSize: number;       // Batch size
}

export const DEFAULT_CONFIG: ModelConfig = {
  dModel: 768,
  nhead: 12,
  numLayersAST: 6,
  numLayersCFG: 4,
  numCrossLayers: 2,
  dimFeedforward: 3072,
  dropout: 0.1,
  vocabSize: 30522,
  cfgVocabSize: 50,
  maxASTLen: 1024,
  maxCFGSize: 256,
  porosityXFeatureDim: 128,
  numVulnerabilityClasses: 64,
  learningRate: 2e-4,
  weightDecay: 0.01,
  warmupSteps: 1000,
  maxSteps: 100000,
  batchSize: 8
};

// ===========================================================================
// AST Tokenization
// ===========================================================================

export interface ASTToken {
  id: number;           // Token ID
  type: string;         // 'keyword', 'identifier', 'operator', 'literal', 'punctuator'
  value: string;        // Token text
  nodeType: string;     // AST node type this token belongs to
  depth: number;        // Nesting depth in the AST
  position: number;     // Position in the original source
}

export interface ASTTokenBatch {
  tokens: ASTToken[];
  attentionMask: number[];  // 1 for real tokens, 0 for padding
  tokenTypeIds: number[];   // Segment IDs (0=AST, 1=CFG context)
}

// ===========================================================================
// CFG Representation
// ===========================================================================

export interface CFGNodeRepresentation {
  nodeId: number;
  nodeType: string;
  label: string;
  statements: string[];     // Serialized statements
  stateMutations: number;   // Count of state mutations
  hasExternalCall: boolean;
  hasTaintedInput: boolean;
  hasStateMutation: boolean;
  taintSourceCount: number;
  taintSinkCount: number;
  positionInCFG: number;    // Linear position for attention
}

export interface CFGRepresentation {
  nodes: CFGNodeRepresentation[];
  adjacencyMatrix: number[][]; // Dense adjacency (could be sparse for large graphs)
  attentionMask: number[];
}

// ===========================================================================
// Model Output
// ===========================================================================

export interface ModelPrediction {
  // Multi-label vulnerability classification
  vulnerabilityScores: Record<string, number>; // pattern -> score (0-1)

  // Risk score for this contract
  riskScore: number;

  // Confidence in predictions
  confidence: number;

  // Novel pattern detection
  isNovel: boolean;
  noveltyScore: number;

  // Explainability: which parts of the code contributed most
  attentionWeights: {
    astAttention: number[][];      // [layer, head] -> [n_tokens, n_tokens]
    cfgAttention: number[][];
    crossAttention: number[][];
  };

  // Top contributing tokens (for explainability)
  topContributingTokens: Array<{
    token: string;
    score: number;
    vulnerability: string;
  }>;

  // Top contributing CFG nodes
  topContributingNodes: Array<{
    nodeLabel: string;
    score: number;
    vulnerability: string;
  }>;
}

// ===========================================================================
// Training Data Sample
// ===========================================================================

export interface TrainingSample {
  id: string;
  contractName: string;
  sourceCode: string;
  astTokens: ASTToken[];
  cfg: CFGRepresentation;
  features: number[];              // Flattened numeric feature vector
  featureNames: string[];
  porosityXFeatures: number[];     // Porosity-X output features
  labels: string[];                // Bug IDs present in this contract
  reward: number;                  // Reward signal for this sample
  timestamp: number;               // For walk-forward splitting
  difficulty: number;              // 0-1 difficulty of finding bugs
}

// ===========================================================================
// Model Interface (to be implemented in Python)
// ===========================================================================

export interface SecurityTransformer {
  /**
   * Initialize the model with configuration.
   */
  initialize(config: ModelConfig): Promise<void>;

  /**
   * Save model to disk.
   */
  save(path: string): Promise<void>;

  /**
   * Load model from disk.
   */
  load(path: string): Promise<void>;

  /**
   * Run inference on a single sample.
   */
  predict(sample: TrainingSample): Promise<ModelPrediction>;

  /**
   * Train on a batch of samples.
   */
  trainBatch(samples: TrainingSample[]): Promise<TrainingLosses>;

  /**
   * Evaluate on a dataset.
   */
  evaluate(samples: TrainingSample[]): Promise<EvaluationMetrics>;

  /**
   * Fine-tune with LoRA or similar adapter.
   */
  fineTune(adapterConfig: AdapterConfig): Promise<void>;
}

export interface TrainingLosses {
  total: number;
  vulnerabilityClassification: number;
  noveltyDetection: number;
  rewardWeighted: number;
  accuracy: number;
}

export interface EvaluationMetrics {
  accuracy: number;
  precision: Record<string, number>;
  recall: Record<string, number>;
  f1: Record<string, number>;
  auc: number;
  falsePositiveRate: number;
  averagePrecision: number;
  calibrationError: number;
}

export interface AdapterConfig {
  method: 'lora' | 'adapter' | 'prefix';
  rank: number;          // LoRA rank
  alpha: number;         // LoRA scaling
  targetModules: string[]; // Which layers to adapt
  learningRate: number;
}
