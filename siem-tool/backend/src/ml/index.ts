// ML Module - Main Entry Point
// Exports all ML functionality for log correlation and anomaly detection

export * from './types';
export { extractFeatures, buildBaseline } from './feature-extractor';
export { classifyAttack, getMitreTactics, getMitreTechniques } from './classifier';
export { correlateMultipleLogs } from './correlator';
export {
  detectEntryAttack,
  detectAttacksInEntries,
  enrichEntryWithAttackDetection,
  enrichEntriesWithAttacks,
  type EntryAttackDetection,
} from './entry-classifier';
