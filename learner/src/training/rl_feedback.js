// RL feedback engine (stub — safe no-op passthrough).
// In a full deployment this would connect to a reinforcement-learning
// feedback store. Here it just lets the analyzer load + run offline.

export function getRLFeedbackEngine() {
  return {
    isConfigured: () => false,
    getFeedback: () => null,
    recordFeedback: () => {},
    // Returns 1.0 (no penalty) when RL is not configured.
    // reasoner.ts and zero_shot/reasoner.ts call this to scale thresholds
    // per-hypothesis: 1.0 means "no penalty, use base thresholds". Without
    // this method, the analyzer throws a TypeError and crashes.
    // In a full deployment, this would read from the RL feedback store
    // keyed by hypothesis id.
    getConfidenceMultiplier: (_hypothesisId: string) => 1.0,
  };
}
