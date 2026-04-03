/**
 * Rich TypeScript types for sh-guard analysis results.
 *
 * The auto-generated index.d.ts uses `any` for classify/classifyBatch return types
 * because they return serde_json::Value. Import these types for full type safety:
 *
 *   import { classify } from 'sh-guard';
 *   import type { AnalysisResult, ClassifyContext } from 'sh-guard/types';
 *   const result = classify("ls -la") as AnalysisResult;
 */

export interface ClassifyContext {
  cwd?: string;
  projectRoot?: string;
  homeDir?: string;
  protectedPaths?: string[];
  shell?: 'bash' | 'zsh';
}

export interface AnalysisResult {
  command: string;
  score: number;
  level: 'safe' | 'caution' | 'danger' | 'critical';
  quick_decision: 'safe' | 'risky' | 'blocked';
  reason: string;
  risk_factors: string[];
  sub_commands: CommandAnalysis[];
  pipeline_flow: PipelineFlow | null;
  mitre_mappings: MitreMapping[];
  parse_confidence: 'full' | 'partial' | 'fallback';
}

export interface CommandAnalysis {
  command: string;
  executable: string | null;
  intent: string[];
  targets: Target[];
  flags: FlagAnalysis[];
  score: number;
  risk_factors: string[];
  reversibility: 'reversible' | 'hard_to_reverse' | 'irreversible';
  capabilities: string[];
}

export interface Target {
  path: string | null;
  scope: string;
  sensitivity: string;
}

export interface FlagAnalysis {
  flag: string;
  modifier: number;
  risk_factor: string;
  description: string;
}

export interface PipelineFlow {
  flow_type: string;
  taint_flows: TaintFlow[];
  composite_score: number;
}

export interface TaintFlow {
  source: object;
  propagators: object[];
  sink: object;
  escalation: number;
  escalation_reason: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
}
