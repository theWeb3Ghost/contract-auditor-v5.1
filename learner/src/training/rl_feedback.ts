/**
 * Reinforcement Learning from Feedback.
 *
 * This module implements a reinforcement-learning feedback loop that adjusts
 * attacker-hypothesis confidence weights based on the reward signals produced
 * by the learning loop.
 *
 * The key insight: each AttackerHypothesis has a "confidence" weight. When a
 * hypothesis repeatedly produces false positives or false negatives across
 * training samples, its confidence is adjusted. This is a simple form of
 * reinforcement learning — the "policy" is the hypothesis selection, and the
 * "reward" comes from the RewardSystem.
 *
 * Persistence: learned weights are saved to data/training/learned_weights.json
 * and loaded on next startup, so the system improves over time.
 */

import { Logger } from '../lib/logger.js';
import { AttackerHypothesis, HypothesisEvaluation } from '../analyzer/zero_shot/reasoner.js';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';

const log = new Logger('rl-feedback');

const WEIGHTS_PATH = join('data', 'training', 'learned_weights.json');

// ===========================================================================
// Feedback Weights
// ===========================================================================

/**
 * Confidence adjustments for each hypothesis, learned from feedback.
 * Keyed by hypothesis ID, stores a learned multiplier (0.0 – 2.0).
 */
export interface HypothesisWeights {
  [hypothesisId: string]: {
    /** Multiplier applied to base confidence (default 1.0) */
    confidenceMultiplier: number;
    /** Number of positive feedback signals */
    positiveCount: number;
    /** Number of negative feedback signals */
    negativeCount: number;
    /** Last updated timestamp */
    updatedAt: string;
  };
}

/**
 * A single feedback sample used for reinforcement learning.
 */
export interface FeedbackSample {
  contractName: string;
  hypothesisId: string;
  /** Predicted vulnerability type */
  predicted: string;
  /** Actual vulnerability type (or null if clean) */
  actual: string | null;
  /** Reward from RewardSystem.calculateReward */
  reward: number;
  /** Whether this was a true positive, false positive, false negative, or true negative */
  outcome: 'tp' | 'fp' | 'fn' | 'tn';
  /** Timestamp when feedback was recorded */
  timestamp: string;
}

// ===========================================================================
// RL Feedback Engine
// ===========================================================================

export class RLFeedbackEngine {
  private weights: HypothesisWeights = {};
  private feedbackHistory: FeedbackSample[] = [];
  private static readonly MAX_FEEDBACK_HISTORY = 5000;
  private loaded: boolean = false;

  // Per-epoch accumulated counts — reset each epoch so that the learning
  // rate is based on the current epoch's signal, not the full history.
  // This prevents weights from being driven to the floor after many epochs
  // of identical false positives (since each epoch re-evaluates with the
  // current weights, the feedback should also reset each epoch).
  private epochCounts: Map<string, { tp: number; fp: number; fn: number; tn: number }> = new Map();
  private currentEpoch: number = 0;

  constructor() {
    // Load weights on first instantiation
    this.loadWeights();
  }

  /**
   * Load learned weights from disk so the system starts with prior knowledge.
   */
  async loadWeights(): Promise<void> {
    try {
      const data = JSON.parse(await readFile(WEIGHTS_PATH, 'utf-8'));
      this.weights = data.weights || {};
      this.feedbackHistory = data.feedbackHistory || [];
      this.loaded = true;
      log.info(`Loaded ${Object.keys(this.weights).length} learned hypothesis weights from ${WEIGHTS_PATH}`);
    } catch {
      log.info('No learned weights found — starting fresh');
      this.loaded = true;
    }
  }

  /**
   * Signal the start of a new epoch. Resets per-epoch counters so that
   * weight updates reflect the current epoch's signal, not cumulative
   * historical signal. The weight multipliers themselves persist.
   *
   * FIX: Weight collapse prevention. The old system applied 2% decay
   * per epoch plus EMA updates, but when precision was consistently low
   * (e.g., 0.074 from 15 TPs vs 189 FPs), the EMA update (-0.107 delta
   * toward target -0.848) overwhelmed the 2% decay, driving weights to
   * the 0.4 floor. Once at floor, hypotheses stop firing (low risk scores),
   * so no more feedback is generated → weights stay at floor forever.
   *
   * The fix has three parts:
   * 1. Decay is now 5% per epoch (was 2%) — stronger reversion to neutral
   * 2. Floor raised to 0.5 (was 0.4) — enough headroom for hypotheses to fire
   * 3. EMA alpha reduced to 0.02 (was 0.05) — slower adaptation, more stable
   * 4. New: resetWeights() method to fully reset between batches
   */
  startEpoch(epoch: number): void {
    if (epoch !== this.currentEpoch) {
      // Flush accumulated epoch data before resetting
      this.applyEpochUpdates();
      this.epochCounts.clear();
      // Apply weight decay: pull all weights 5% toward 1.0 (neutral) each epoch.
      // This creates equilibrium: weights settle where precision-based decrease
      // balances the decay-based increase. With alpha=0.02 in applyEpochUpdates
      // and 5% decay, weights stabilize near precision/0.53 rather than crashing.
      for (const [hypothesisId, w] of Object.entries(this.weights)) {
        w.confidenceMultiplier = w.confidenceMultiplier + (1.0 - w.confidenceMultiplier) * 0.05;
        w.updatedAt = new Date().toISOString();
        this.weights[hypothesisId] = w;
      }
      this.currentEpoch = epoch;
      log.info(`RL feedback: starting epoch ${epoch + 1}, avg multiplier ${this.getStats().avgMultiplier.toFixed(3)}x`);
    }
  }

  /**
   * Apply accumulated per-epoch updates to the persistent weights.
   * Uses a batch update based on per-hypothesis precision within the epoch.
   */
  private applyEpochUpdates(): void {
    for (const [hypothesisId, counts] of this.epochCounts.entries()) {
      const tp = counts.tp;
      const fp = counts.fp;
      const total = tp + fp;
      // If the hypothesis never fired this epoch, no precision update —
      // the decay in startEpoch will naturally pull it toward neutral.
      if (total === 0) continue;

      const precision = tp / total;
      const w = this.weights[hypothesisId] || {
        confidenceMultiplier: 1.0,
        positiveCount: 0,
        negativeCount: 0,
        updatedAt: new Date().toISOString()
      };

      // EMA-based update: move weight toward the epoch's precision signal.
      // target = 2*precision - 1 maps [0,1] → [-1,1], where 0.5 precision
      // maps to 0.0 (no change). Alpha=0.02 gives ~45% adaptation after
      // 30 epochs. Combined with 5% per-epoch decay from startEpoch,
      // weights stabilize near precision/0.53 rather than crashing to floor.
      const target = (2 * precision) - 1;
      const alpha = 0.02;
      const delta = (target - w.confidenceMultiplier) * alpha;

      // Floor of 0.5 — hypotheses can still fire at 50% strength.
      // 0.4 floor was too low: at 0.4x, risk scores drop below threshold
      // and hypotheses stop firing entirely, creating a death spiral.
      // Cap per-epoch delta to prevent extreme swings.
      const cappedDelta = Math.max(-0.1, Math.min(0.1, delta));
      w.confidenceMultiplier = Math.max(0.5, Math.min(2.0, w.confidenceMultiplier + cappedDelta));
      w.positiveCount += counts.tp + counts.tn;
      w.negativeCount += counts.fp + counts.fn;
      w.updatedAt = new Date().toISOString();
      this.weights[hypothesisId] = w;
    }
  }

  /**
   * Get the confidence multiplier for a hypothesis.
   * Returns 1.0 (neutral) if no learned weight exists.
   */
  getConfidenceMultiplier(hypothesisId: string): number {
    const w = this.weights[hypothesisId];
    if (!w) return 1.0;

    // Clamp to reasonable range (0.5 floor matches applyEpochUpdates floor)
    return Math.max(0.5, Math.min(2.0, w.confidenceMultiplier));
  }

  /**
   * Adjust hypothesis confidence based on feedback.
   *
   * After each learning sample is evaluated, call this with the feedback.
   * Positive feedback (TP, TN) increases the multiplier; negative (FP, FN) decreases.
   */
  async updateFromFeedback(sample: FeedbackSample): Promise<void> {
    this.feedbackHistory.push(sample);
    // Bound the feedback history to prevent unbounded memory growth during
    // long training runs (e.g., processing 921 contracts sequentially).
    if (this.feedbackHistory.length > RLFeedbackEngine.MAX_FEEDBACK_HISTORY) {
      this.feedbackHistory = this.feedbackHistory.slice(-RLFeedbackEngine.MAX_FEEDBACK_HISTORY);
    }

    // Accumulate per-epoch counts — updates are applied at epoch boundary
    // (see startEpoch). This prevents weight drift when the same contracts
    // are analyzed multiple times across epochs with the same weights.
    const counts = this.epochCounts.get(sample.hypothesisId) || { tp: 0, fp: 0, fn: 0, tn: 0 };

    switch (sample.outcome) {
      case 'tp': counts.tp++; break;
      case 'fp': counts.fp++; break;
      case 'fn': counts.fn++; break;
      case 'tn': counts.tn++; break;
    }

    this.epochCounts.set(sample.hypothesisId, counts);
  }

  /**
   * Apply learned weights to a batch of hypothesis evaluations.
   * This adjusts the confidence and risk scores based on the reinforcement
   * learning feedback accumulated so far.
   */
  applyLearnedWeights(evaluations: HypothesisEvaluation[]): HypothesisEvaluation[] {
    return evaluations.map(eval_ => {
      const w = this.weights[eval_.hypothesis.id];
      if (!w || w.confidenceMultiplier === 1.0) return eval_;

      // Apply multiplier to both confidence and risk
      const multiplier = w.confidenceMultiplier;
      return {
        ...eval_,
        confidence: Math.min(1.0, eval_.confidence * multiplier),
        riskScore: Math.min(1.0, eval_.riskScore * multiplier)
      };
    });
  }

  /**
   * Get summary statistics of learned weights.
   */
  getStats(): {
    totalWeights: number;
    avgMultiplier: number;
    mostAdjusted: Array<{ id: string; multiplier: number; positive: number; negative: number }>;
  } {
    const entries = Object.entries(this.weights);
    const avgMultiplier = entries.length > 0
      ? entries.reduce((sum, [, w]) => sum + w.confidenceMultiplier, 0) / entries.length
      : 1.0;

    const mostAdjusted = entries
      .map(([id, w]) => ({
        id,
        multiplier: w.confidenceMultiplier,
        positive: w.positiveCount,
        negative: w.negativeCount
      }))
      .sort((a, b) => Math.abs(b.multiplier - 1.0) - Math.abs(a.multiplier - 1.0))
      .slice(0, 10);

    return {
      totalWeights: entries.length,
      avgMultiplier,
      mostAdjusted
    };
  }

  /**
   * Persist learned weights and feedback history to disk.
   */
  async saveWeights(): Promise<void> {
    const dir = join('data', 'training');
    await mkdir(dir, { recursive: true });

    const data = {
      savedAt: new Date().toISOString(),
      weights: this.weights,
      feedbackHistory: this.feedbackHistory.slice(-500), // Keep last 500 samples
      stats: this.getStats()
    };

    await writeFile(WEIGHTS_PATH, JSON.stringify(data, null, 2));
    log.info(`Saved ${Object.keys(this.weights).length} learned weights to ${WEIGHTS_PATH}`);
  }

  /**
   * Reset all learned weights (for experimentation).
   * Use reset() to clear everything including feedback history, or
   * resetEpoch() to keep weights but clear per-epoch counters.
   */
  reset(): void {
    this.weights = {};
    this.feedbackHistory = [];
    this.epochCounts.clear();
    this.currentEpoch = 0;
    log.info('RL feedback weights reset');
  }

  /**
   * Reset only per-epoch counters, keeping learned weights.
   * This is automatically called by startEpoch() when the epoch number changes.
   */
  resetEpoch(): void {
    this.epochCounts.clear();
  }
}

// ===========================================================================
// Singleton
// ===========================================================================

let engineInstance: RLFeedbackEngine | null = null;

export function getRLFeedbackEngine(): RLFeedbackEngine {
  if (!engineInstance) {
    engineInstance = new RLFeedbackEngine();
  }
  return engineInstance;
}
