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
  status: "queued" | "running" | "complete" | "failed" | "cancelled";
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
  | "decompiler"
  | "disassembly"
  | "strings"
  | "imports"
  | "graph"
  | "annotations";
