export type Sample = {
  id: string;
  name: string;
  sha256: string;
  size: number;
  architecture: string;
  status: "queued" | "analyzing" | "ready" | "partial" | "failed" | "cancelled";
  created_at: string;
  error?: string | null;
  function_count: number;
  analysis_revision: number;
};
export type FunctionSummary = {
  address: string;
  name: string;
  size: number;
  signature?: string;
};
export type FunctionDetail = FunctionSummary & {
  signature: string;
  decompiled: string | null;
  decompile_error?: string;
  decompiled_truncated?: boolean;
  disassembly: {
    address: string;
    bytes: string;
    mnemonic: string;
    operands: string;
  }[];
  callers: { address: string; name: string }[];
  callees: { address: string; name: string }[];
  comment?: string | null;
};
export type Analysis = {
  sample_id: string;
  revision: number;
  image_base: string;
  entry_point: string;
  architecture: string;
  format: string;
  engine: string | Record<string, unknown>;
  functions?: FunctionSummary[];
  imports: { address: string; name: string; library?: string }[];
  exports: { address: string; name: string }[];
  strings: { address: string; value: string }[];
  sections: {
    name: string;
    address: string;
    size: number;
    permissions: string;
  }[];
  warnings: string[];
  preprocessing?: {
    status: "unpacked" | "not_detected";
    original_sha256: string;
    original_size: number;
    analyzed_sha256: string;
    analyzed_size: number;
    tool_version?: string;
  };
};
export type Provider = {
  id: "ollama" | "openrouter";
  configured: boolean;
  model: string;
  base_url: string;
};
export type Evidence = {
  id: string;
  address?: string;
  tool: string;
  summary: string;
  revision?: number;
};
export type Run = {
  id: string;
  sample_id: string;
  question: string;
  provider: string;
  model: string;
  mode?: "investigation" | "pseudocode";
  analysis_revision?: number;
  function_address?: string | null;
  pseudocode_coverage?: { scope: "function" | "program_sketch"; addresses: string[]; total_functions: number; truncated: boolean };
  budget?: "standard" | "extended" | "deep";
  limits?: { total_tokens: number; model_turns: number; tool_calls: number; seconds: number };
  limit_reason?: string;
  answer_kind?: "model" | "evidence_index";
  status: "queued" | "running" | "complete" | "partial" | "failed" | "cancelled";
  answer?: string | null;
  error?: string | null;
  events: {
    type: string;
    message: string;
    tool?: string;
    arguments?: unknown;
    evidence_id?: string;
  }[];
  created_at: string;
  evidence: Evidence[];
  usage?: { input_tokens: number; output_tokens: number };
};
export type Annotation = {
  id: string;
  sample_id: string;
  address: string;
  kind: "rename" | "comment";
  value: string;
  old_value: string | null;
  status: "proposed" | "applied";
  created_at: string;
};
export type Health = {
  status: string;
  ghidra_available: boolean;
  ghidra_version: string;
  active_jobs: number;
};
export type MainTab =
  | "overview"
  | "workflow"
  | "pseudocode"
  | "decompiler"
  | "disassembly"
  | "strings"
  | "imports"
  | "graph"
  | "annotations";

export type WorkflowJob = {
  id: string;
  sample_id: string;
  status: string;
  stage: string;
  provider: string;
  model: string;
  analysis_revision: number;
  error?: string | null;
  token_limit: number;
  budget_used: number;
  tokens_reported: number;
  discovery_id?: string | null;
  functions: { address: string; name: string; reason: string; status: string; run_id?: string | null; error?: string }[];
  run_ids: string[];
};

export type RequestedPrompt = {
  text: string;
  nonce: number;
  sampleId: string;
  mode: "investigation" | "pseudocode";
  scope: "function" | "program";
};
export type Ask = (text: string, mode?: "investigation" | "pseudocode", scope?: "function" | "program") => void;
export type PseudocodeJob = {
  sample_id: string;
  analysis_revision: number;
  status: "queued" | "running" | "complete" | "partial" | "failed" | "cancelled" | "interrupted";
  total: number;
  processed: number;
  recovered: number;
  failed: number;
  truncated: number;
  source_partial: boolean;
  error?: string | null;
  functions: { address: string; name: string; available: boolean; truncated: boolean; error?: string | null }[];
};
