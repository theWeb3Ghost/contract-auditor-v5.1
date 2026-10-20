/**
 * Zero-Shot Learning Module Entry Point.
 *
 * Exports the zero-shot vulnerability discovery system.
 */

export { KnowledgeGraphImpl, DEFAULT_DOCUMENT_SOURCES } from '../knowledge/docs_processor.js';
export type { KnowledgeFact, KnowledgeRelation, KnowledgeGraph, DocumentSource, ProcessedDocument, DocumentSection } from '../knowledge/docs_processor.js';
export { SemanticReasoner } from './reasoner.js';
export type { AttackerHypothesis, HypothesisEvaluation } from './reasoner.js';
export { ZeroShotVulnerabilityPredictor, createZeroShotPredictor } from './predictor.js';
export type { ZeroShotAnalysisResult, DiscoveredVulnerability } from './predictor.js';
