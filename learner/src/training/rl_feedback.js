// RL feedback engine (stub — safe no-op passthrough).
// In a full deployment this would connect to a reinforcement-learning
// feedback store. Here it just lets the analyzer load + run offline.

export function getRLFeedbackEngine() {
  return {
    isConfigured: () => false,
    getFeedback: () => null,
    recordFeedback: () => {},
  };
}
