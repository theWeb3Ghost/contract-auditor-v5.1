// RL feedback engine (stub — safe no-op passthrough).
// In a full deployment this would connect to a reinforcement-learning
// feedback store. Here it just lets the analyzer load + run offline.

export function getRLFeedbackEngine() {
  return {
    isConfigured: () => false,
    getFeedback: () => null,
    recordFeedback: () => {},
    // Returns 1.0 (no penalty) — reasoner.ts and zero_shot/reasoner.ts call
    // this to scale thresholds per-hypothesis. Without it, the analyzer throws
    // a TypeError (object has no method 'getConfidenceMultiplier') and crashes.
    getConfidenceMultiplier: () => 1.0,
  };
}
