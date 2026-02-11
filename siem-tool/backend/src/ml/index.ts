// ML Module - Main Entry Point
// Exports all ML functionality for log correlation and anomaly detection

export * from './types';
export { extractFeatures, buildBaseline, extractAdvancedFeatures, detectAttackPatterns } from './feature-extractor';
export { classifyAttack, getMitreTactics, getMitreTechniques } from './classifier';
export { correlateMultipleLogs } from './correlator';
export {
  detectEntryAttack,
  detectAttacksInEntries,
  enrichEntryWithAttackDetection,
  enrichEntriesWithAttacks,
  getAttackTypesForLogType,
  isAttackTypeApplicable,
  getLogTypeCategory,
  type EntryAttackDetection,
  type LogTypeCategory,
} from './entry-classifier';
export {
  extractFeatures as extractMLFeatures,
  classifyAttack as classifyMLAttack,
  detectMLAttacks,
  type MLPrediction,
} from './ml-classifier';
export {
  detectAnomaly,
  detectAnomaliesForAllTypes,
  extractFeaturesByLogType,
  getLogTypeFromEntries,
  mapLogTypeToModel,
  registerModels,
  clearModelCache,
  type TrainedModel,
  type LogTypePrediction,
} from './multi-log-anomaly';
