import { useMemo, useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Binary,
  BookOpen,
  Check,
  ChevronRight,
  Clipboard,
  Code2,
  FileCode2,
  FileSearch,
  GitBranch,
  Hash,
  Layers3,
  List,
  MessageSquarePlus,
  PencilLine,
  Search,
  ShieldCheck,
  Terminal,
  Upload,
  WandSparkles,
} from "lucide-react";
import { sizeLabel } from "./api";
import type {
  Analysis,
  Ask,
  Annotation,
  FunctionDetail,
  MainTab,
  Provider,
  Sample,
} from "./types";
import { CodeView, Empty, Notice, Spinner, Status } from "./ui";
import PseudocodePanel from "./PseudocodePanel";
import WorkflowPanel from "./WorkflowPanel";

const tabs: { id: MainTab; title: string; icon: typeof Code2 }[] = [
  { id: "overview", title: "Overview", icon: Layers3 },
  { id: "workflow", title: "Analyze & rewrite", icon: WandSparkles },
  { id: "decompiler", title: "Decompiler", icon: Code2 },
  { id: "pseudocode", title: "Pseudocode", icon: FileCode2 },
  { id: "disassembly", title: "Assembly", icon: Terminal },
  { id: "strings", title: "Strings", icon: List },
  { id: "imports", title: "Imports", icon: ArrowDownToLine },
  { id: "graph", title: "Call graph", icon: GitBranch },
  { id: "annotations", title: "Changes", icon: PencilLine },
];

type Props = {
  providers: Provider[];
  onSettings: () => void;
  sample?: Sample;
  analysis: Analysis | null;
  func: FunctionDetail | null;
  loading: boolean;
  functionLoading: boolean;
  tab: MainTab;
  setTab: (tab: MainTab) => void;
  annotations: Annotation[];
  onNavigate: (address: string) => void;
  onUpload: () => void;
  onRetry: () => void;
  onCancel: () => void;
  onAnnotate: (kind: "rename" | "comment") => void;
  onApply: (annotation: Annotation) => void;
  applying: string;
  onAsk: Ask;
  onSelectFunction: (address: string) => void;
};

export default function WorkSurface(props: Props) {
  const { sample, analysis, func, tab, setTab, loading, onUpload } = props;
  if (!sample)
    return (
      <section className="work-surface welcome-surface">
        <Welcome onUpload={onUpload} />
      </section>
    );
  return (
    <section className="work-surface">
      <div className="document-heading">
        <div className="document-title">
          <FileCode2 size={17} />
          <span>{sample.name}</span>
          <span className="document-separator">/</span>
          <span className="document-context">
            {func && tab !== "overview" ? func.name : "Program analysis"}
          </span>
        </div>
        <span className="revision">rev {sample.analysis_revision || "—"}</span>
      </div>
      <nav className="workspace-tabs" aria-label="Analysis views">
        {tabs.map((item) => (
          <button
            key={item.id}
            className={tab === item.id ? "active" : ""}
            onClick={() => setTab(item.id)}
          >
            <item.icon size={14} />
            {item.title}
            {item.id === "annotations" &&
              props.annotations.some((a) => a.status === "proposed") && (
                <span className="tab-count">
                  {
                    props.annotations.filter((a) => a.status === "proposed")
                      .length
                  }
                </span>
              )}
          </button>
        ))}
      </nav>
      {tab === "workflow" ? <WorkflowPanel key={sample.id} sample={sample} providers={props.providers} onSettings={props.onSettings} /> : sample.status === "queued" || sample.status === "analyzing" ? (
        <div className="analysis-progress">
          <div className="progress-top">
            <div>
              <span className="eyebrow">ANALYSIS IN PROGRESS</span>
              <h2>
                {sample.status === "queued"
                  ? "Waiting for an analysis worker"
                  : "Understanding your executable"}
              </h2>
              <p>
                Checking for UPX packing, then using Ghidra to identify functions,
                references, and program structure. Larger binaries may take a few minutes.
              </p>
            </div>
            <div className="processing-glyph">
              <Binary size={32} />
            </div>
          </div>
          <div className="indeterminate-progress" />
          <div className="progress-bottom">
            <Spinner
              label={
                sample.status === "queued"
                  ? "Queued"
                  : "Running static analysis"
              }
            />
            <button className="button secondary small" onClick={props.onCancel}>
              Cancel analysis
            </button>
          </div>
        </div>
      ) : sample.status === "failed" || sample.status === "cancelled" ? (
        <Empty
          icon={<FileSearch size={28} />}
          title={
            sample.status === "failed"
              ? "Analysis could not finish"
              : "Analysis cancelled"
          }
        >
          <p>
            {sample.error ||
              "The original file is saved. You can start a fresh analysis whenever you are ready."}
          </p>
          <button className="button primary" onClick={props.onRetry}>
            Retry analysis
            <ArrowRight size={15} />
          </button>
        </Empty>
      ) : loading && !analysis ? (
        <Spinner label="Loading analysis…" />
      ) : !analysis ? (
        <Empty icon={<FileSearch size={28} />} title="No analysis available">
          <p>Start an analysis to explore this executable.</p>
          <button className="button primary" onClick={props.onRetry}>
            Analyze executable
          </button>
        </Empty>
      ) : (
        <>
          {sample.status === "partial" && (
            <div className="surface-notice">
              <Notice tone="warning">
                This analysis is partial. Review the warnings before drawing
                conclusions.
              </Notice>
            </div>
          )}
          {tab === "overview" && (
            <Overview
              sample={sample}
              analysis={analysis}
              onNavigate={props.onNavigate}
              onAsk={props.onAsk}
              onRetry={props.onRetry}
            />
          )}
          {tab === "pseudocode" && (
            <PseudocodePanel key={sample.id} sample={sample} analysis={analysis} func={func}
              loading={props.functionLoading} onSelect={props.onSelectFunction} onAsk={props.onAsk} />
          )}
          {(tab === "decompiler" || tab === "disassembly" || tab === "graph") &&
            (props.functionLoading ? (
              <Spinner label="Loading function details from Ghidra…" />
            ) : !func ? (
              <Empty icon={<Code2 size={26} />} title="Choose a function">
                <p>
                  Select a function from the program explorer to inspect its
                  code and relationships.
                </p>
              </Empty>
            ) : (
              <>
                <div className="function-toolbar">
                  <div>
                    <code>{func.address}</code>
                    <span className="toolbar-divider" />
                    <span>{sizeLabel(func.size)}</span>
                  </div>
                  <div className="toolbar-actions">
                    <button
                      className="text-button"
                      onClick={() => props.onAnnotate("rename")}
                    >
                      <PencilLine size={13} />
                      Rename
                    </button>
                    <button
                      className="text-button"
                      onClick={() => props.onAnnotate("comment")}
                    >
                      <MessageSquarePlus size={14} />
                      Comment
                    </button>
                    <button
                      className="text-button accent"
                      onClick={() =>
                        props.onAsk(
                          `Explain ${func.name} at ${func.address}, including its callers and any important side effects. Cite the evidence.`,
                        )
                      }
                    >
                      <WandSparkles size={14} />
                      Explain
                    </button>
                  </div>
                </div>
                {tab === "decompiler" && (
                  <div className="decompiler-view">
                    <div className="code-banner">
                      <Code2 size={14} />
                      <span>Ghidra decompiler</span>
                      <span className="code-banner-note">
                        Reconstructed C · verify against assembly
                      </span>
                      <CopyButton text={func.decompiled || ""} />
                    </div>
                    {func.comment && (
                      <div className="function-comment">
                        <MessageSquarePlus size={14} />
                        <pre>{func.comment}</pre>
                      </div>
                    )}
                    {func.decompiled ? (
                      <CodeView code={func.decompiled} />
                    ) : (
                      <Empty title="No decompiler output">
                        <p>
                          This function could not be decompiled. Inspect its
                          assembly and references.
                        </p>
                        <button
                          className="button secondary small"
                          onClick={() => setTab("disassembly")}
                        >
                          View assembly
                          <ArrowRight size={14} />
                        </button>
                      </Empty>
                    )}
                    <div className="references-footer">
                      <span>{func.callers?.length || 0} callers</span>
                      <span>{func.callees?.length || 0} callees</span>
                      <button
                        className="text-button"
                        onClick={() => setTab("graph")}
                      >
                        Explore relationships
                        <ChevronRight size={13} />
                      </button>
                    </div>
                  </div>
                )}
                {tab === "disassembly" && <Assembly func={func} />}
                {tab === "graph" && (
                  <CallGraph func={func} onNavigate={props.onNavigate} />
                )}
              </>
            ))}
          {tab === "strings" && (
            <StringTable
              strings={analysis.strings || []}
              onNavigate={props.onNavigate}
            />
          )}
          {tab === "imports" && <Imports analysis={analysis} />}
          {tab === "annotations" && (
            <Changes
              annotations={props.annotations}
              onApply={props.onApply}
              applying={props.applying}
              onNavigate={props.onNavigate}
            />
          )}
        </>
      )}
    </section>
  );
}

function Welcome({ onUpload }: { onUpload: () => void }) {
  return (
    <div className="welcome">
      <div className="welcome-art" aria-hidden="true">
        <div className="art-orbit orbit-one" />
        <div className="art-orbit orbit-two" />
        <div className="art-line line-one" />
        <div className="art-line line-two" />
        <div className="art-node node-one">
          <Hash size={17} />
        </div>
        <div className="art-node node-two">
          <GitBranch size={19} />
        </div>
        <div className="art-core">
          <Binary size={42} strokeWidth={1.3} />
        </div>
        <div className="art-label">PE / x86 · x64</div>
      </div>
      <span className="eyebrow accent">FROM BINARY TO UNDERSTANDING</span>
      <h1>
        Your next investigation
        <br />
        starts here.
      </h1>
      <p>
        Explore Windows executables with Ghidra.
        <br />
        Follow the code, connect the evidence, and ask better questions.
      </p>
      <button className="button primary upload-large" onClick={onUpload}>
        <Upload size={17} />
        Open executable
        <ArrowRight size={17} />
      </button>
      <span className="drop-hint">
        or drop an .exe or .dll into the workbench
      </span>
      <div className="welcome-capabilities">
        <div>
          <Code2 size={18} />
          <span>Decompile & inspect</span>
        </div>
        <div>
          <GitBranch size={18} />
          <span>Follow relationships</span>
        </div>
        <div>
          <WandSparkles size={18} />
          <span>Investigate with AI</span>
        </div>
      </div>
      <div className="local-note">
        <ShieldCheck size={14} />
        Files stay on this server. Executables are never run.
      </div>
    </div>
  );
}

function Overview({
  sample,
  analysis,
  onNavigate,
  onAsk,
  onRetry,
}: {
  sample: Sample;
  analysis: Analysis;
  onNavigate: (address: string) => void;
  onAsk: (question: string) => void;
  onRetry: () => void;
}) {
  return (
    <div className="overview scroll-region">
      <div className="overview-heading">
        <div>
          <span className="eyebrow">PROGRAM OVERVIEW</span>
          <h2>{sample.name}</h2>
          <p>
            {analysis.format || "Portable Executable"}
            <span className="middle-dot">·</span>
            {analysis.architecture || sample.architecture}
            <span className="middle-dot">·</span>
            {sizeLabel(sample.size)}
          </p>
        </div>
        <Status value={sample.status} />
      </div>
      {analysis.preprocessing?.status === "unpacked" && (
        <Notice tone="info">
          UPX unpacked · {sizeLabel(analysis.preprocessing.original_size)} → {sizeLabel(analysis.preprocessing.analyzed_size)}.
          {" "}Ghidra and investigation tools use the unpacked copy. Original upload preserved.
        </Notice>
      )}
      {!analysis.preprocessing && analysis.sections?.some((section) => /^UPX[012]$/.test(section.name)) && (
        <Notice tone="warning">
          This analysis contains UPX packing. Reanalyze to unpack the file and recover the program inside.
          <button className="button secondary small" onClick={onRetry}>Unpack and reanalyze</button>
        </Notice>
      )}
      <div className="metric-strip">
        <div>
          <span>Functions</span>
          <strong>{sample.function_count.toLocaleString()}</strong>
        </div>
        <div>
          <span>Imports</span>
          <strong>{analysis.imports?.length.toLocaleString() || "0"}</strong>
        </div>
        <div>
          <span>Strings</span>
          <strong>{analysis.strings?.length.toLocaleString() || "0"}</strong>
        </div>
        <div>
          <span>Sections</span>
          <strong>{analysis.sections?.length.toLocaleString() || "0"}</strong>
        </div>
      </div>
      <div className="overview-section">
        <div className="section-title">
          <Hash size={15} />
          <h3>File identity</h3>
        </div>
        <dl className="identity-list">
          <div>
            <dt>Upload SHA-256</dt>
            <dd className="hash-value">
              <code>{sample.sha256}</code>
              <CopyButton text={sample.sha256} />
            </dd>
          </div>
          {analysis.preprocessing?.status === "unpacked" && (
            <>
              <div>
                <dt>Analyzed SHA-256</dt>
                <dd className="hash-value">
                  <code>{analysis.preprocessing.analyzed_sha256}</code>
                  <CopyButton text={analysis.preprocessing.analyzed_sha256} />
                </dd>
              </div>
              <div>
                <dt>Preprocessing</dt>
                <dd>UPX {analysis.preprocessing.tool_version} · unpacked PE · {sizeLabel(analysis.preprocessing.analyzed_size)}</dd>
              </div>
            </>
          )}
          <div>
            <dt>Image base</dt>
            <dd>
              <code>{analysis.image_base || "—"}</code>
            </dd>
          </div>
          <div>
            <dt>Entry point</dt>
            <dd>
              <button
                className="address-link"
                onClick={() => onNavigate(analysis.entry_point)}
              >
                {analysis.entry_point || "—"}
                <ChevronRight size={12} />
              </button>
            </dd>
          </div>
          <div>
            <dt>Analysis engine</dt>
            <dd>
              {typeof analysis.engine === "string"
                ? analysis.engine
                : Object.entries(analysis.engine || {})
                    .map(([key, value]) => `${key}: ${value}`)
                    .join(" · ")}
            </dd>
          </div>
        </dl>
      </div>
      <div className="overview-section">
        <div className="section-title">
          <Layers3 size={15} />
          <h3>Memory sections</h3>
          <span>{analysis.sections?.length || 0}</span>
        </div>
        <div className="section-map">
          {analysis.sections?.map((section) => (
            <div
              key={section.name + section.address}
              style={{ flexGrow: Math.max(1, Math.log2(section.size + 1)) }}
              title={`${section.name}: ${sizeLabel(section.size)} · ${section.permissions}`}
              className={
                section.permissions?.includes("x") ||
                section.permissions?.includes("X")
                  ? "executable"
                  : ""
              }
            >
              <span>{section.name}</span>
            </div>
          ))}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th>Size</th>
                <th>Permissions</th>
              </tr>
            </thead>
            <tbody>
              {analysis.sections?.map((section) => (
                <tr key={section.name + section.address}>
                  <td>
                    <span className="section-name">{section.name}</span>
                  </td>
                  <td>
                    <code>{section.address}</code>
                  </td>
                  <td>{sizeLabel(section.size)}</td>
                  <td>
                    <code className="permissions">{section.permissions}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {!!analysis.warnings?.length && (
        <div className="overview-section">
          <Notice tone="warning">
            <strong>Analysis notes</strong>
            <ul>
              {analysis.warnings.map((warning, index) => (
                <li key={index}>{warning}</li>
              ))}
            </ul>
          </Notice>
        </div>
      )}
      <button
        className="investigation-callout"
        onClick={() =>
          onAsk(
            "Give me an overview of this executable: its entry point, key imports, and likely purpose. Distinguish observed facts from inference and cite the evidence.",
          )
        }
      >
        <div className="callout-icon">
          <WandSparkles size={19} />
        </div>
        <div>
          <strong>Make sense of this program</strong>
          <span>
            Ask the agent for an overview grounded in analysis evidence.
          </span>
        </div>
        <ArrowRight size={18} />
      </button>
      <a
        className="report-link"
        href={`/api/samples/${sample.id}/report`}
        download
      >
        <ArrowDownToLine size={14} />
        Export analysis report
      </a>
    </div>
  );
}

function Assembly({ func }: { func: FunctionDetail }) {
  return (
    <div className="assembly-view scroll-region">
      <div className="code-banner">
        <Terminal size={14} />
        <span>Listing</span>
        <span className="code-banner-note">
          {func.disassembly?.length || 0} instructions
        </span>
      </div>
      {func.disassembly?.length ? (
        <table className="assembly-table">
          <thead>
            <tr>
              <th>Address</th>
              <th>Bytes</th>
              <th colSpan={2}>Instruction</th>
            </tr>
          </thead>
          <tbody>
            {func.disassembly.map((instruction, index) => (
              <tr key={instruction.address + index}>
                <td className="assembly-address">{instruction.address}</td>
                <td className="assembly-bytes">{instruction.bytes}</td>
                <td
                  className={`assembly-mnemonic ${/^(call|j|ret)/i.test(instruction.mnemonic) ? "control-flow" : ""}`}
                >
                  {instruction.mnemonic}
                </td>
                <td className="assembly-operands">{instruction.operands}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <Empty title="No instructions available">
          <p>This function has no exported assembly listing.</p>
        </Empty>
      )}
    </div>
  );
}

function StringTable({
  strings,
  onNavigate,
}: {
  strings: Analysis["strings"];
  onNavigate: (address: string) => void;
}) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(
    () =>
      strings.filter(
        (item) =>
          item.value.toLowerCase().includes(query.toLowerCase()) ||
          item.address.toLowerCase().includes(query.toLowerCase()),
      ),
    [strings, query],
  );
  return (
    <div className="data-view">
      <div className="data-toolbar">
        <div className="search-box">
          <Search size={14} />
          <input
            aria-label="Filter strings"
            placeholder="Search strings or address…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <kbd>/</kbd>
        </div>
        <span>{filtered.length.toLocaleString()} strings</span>
      </div>
      <div className="scroll-region table-wrap">
        <table>
          <thead>
            <tr>
              <th>Address</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 2500).map((item, index) => (
              <tr key={item.address + index}>
                <td>
                  <button
                    className="address-link"
                    onClick={() => onNavigate(item.address)}
                  >
                    {item.address}
                  </button>
                </td>
                <td className="string-value">{item.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && (
          <Empty title={query ? "No matching strings" : "No strings found"}>
            <p>
              {query
                ? "Try another search term or address."
                : "No strings were extracted during analysis."}
            </p>
          </Empty>
        )}
        {filtered.length > 2500 && (
          <p className="table-note">
            Showing 2,500 matches. Refine your search to find specific strings.
          </p>
        )}
      </div>
    </div>
  );
}

function Imports({ analysis }: { analysis: Analysis }) {
  const [query, setQuery] = useState("");
  const [mode, setMode] = useState<"imports" | "exports">("imports");
  const items = (
    mode === "imports" ? analysis.imports : analysis.exports
  ).filter((item) =>
    `${item.name} ${"library" in item ? item.library : ""} ${item.address}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return (
    <div className="data-view">
      <div className="data-toolbar">
        <div className="segmented">
          <button
            className={mode === "imports" ? "active" : ""}
            onClick={() => setMode("imports")}
          >
            Imports
          </button>
          <button
            className={mode === "exports" ? "active" : ""}
            onClick={() => setMode("exports")}
          >
            Exports
          </button>
        </div>
        <div className="search-box">
          <Search size={14} />
          <input
            aria-label="Filter symbols"
            placeholder="Filter symbols…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
      </div>
      <div className="scroll-region table-wrap">
        <table>
          <thead>
            <tr>
              <th>Symbol</th>
              {mode === "imports" && <th>Library</th>}
              <th>Address</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item, index) => (
              <tr key={item.name + index}>
                <td className="symbol-name">{item.name}</td>
                {mode === "imports" && (
                  <td>
                    {"library" in item ? (item.library as string) || "—" : "—"}
                  </td>
                )}
                <td>
                  <code>{item.address}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!items.length && (
          <Empty
            icon={<ArrowDownToLine size={24} />}
            title={`No ${query ? "matching " : ""}${mode}`}
          >
            <p>
              {query
                ? "Try a different symbol name."
                : `No ${mode} were found in this program.`}
            </p>
          </Empty>
        )}
      </div>
    </div>
  );
}

function CallGraph({
  func,
  onNavigate,
}: {
  func: FunctionDetail;
  onNavigate: (address: string) => void;
}) {
  const callers = func.callers || [];
  const callees = func.callees || [];
  return (
    <div className="graph-view scroll-region">
      <div className="graph-heading">
        <div>
          <h3>Function relationships</h3>
          <p>Direct calls recorded by Ghidra. Select a node to explore.</p>
        </div>
        <span className="subtle-badge">
          {callers.length + callees.length} edges
        </span>
      </div>
      <div className="graph-canvas">
        <div className="graph-column">
          <span className="graph-label">
            CALLERS <span>{callers.length}</span>
          </span>
          {callers.length ? (
            callers.slice(0, 30).map((item, index) => (
              <button
                className="graph-node"
                key={item.address + index}
                onClick={() => onNavigate(item.address)}
              >
                <Code2 size={14} />
                <span>
                  <strong>{item.name}</strong>
                  <code>{item.address}</code>
                </span>
                <ChevronRight size={13} />
              </button>
            ))
          ) : (
            <span className="graph-no-nodes">No recorded callers</span>
          )}
        </div>
        <div className="graph-center">
          <div className="graph-connector" />
          <div className="graph-node current">
            <GitBranch size={20} />
            <span>
              <strong>{func.name}</strong>
              <code>{func.address}</code>
            </span>
          </div>
          <div className="graph-connector" />
        </div>
        <div className="graph-column">
          <span className="graph-label">
            CALLEES <span>{callees.length}</span>
          </span>
          {callees.length ? (
            callees.slice(0, 30).map((item, index) => (
              <button
                className="graph-node"
                key={item.address + index}
                onClick={() => onNavigate(item.address)}
              >
                <Code2 size={14} />
                <span>
                  <strong>{item.name}</strong>
                  <code>{item.address}</code>
                </span>
                <ChevronRight size={13} />
              </button>
            ))
          ) : (
            <span className="graph-no-nodes">No recorded callees</span>
          )}
        </div>
      </div>
      {(callers.length > 30 || callees.length > 30) && (
        <p className="table-note">
          Showing up to 30 relationships in each direction.
        </p>
      )}
      <div className="graph-note">
        <BookOpen size={15} />
        <span>
          Indirect calls and dynamically resolved targets may not appear in this
          graph.
        </span>
      </div>
    </div>
  );
}

function Changes({
  annotations,
  onApply,
  applying,
  onNavigate,
}: {
  annotations: Annotation[];
  onApply: (annotation: Annotation) => void;
  applying: string;
  onNavigate: (address: string) => void;
}) {
  if (!annotations.length)
    return (
      <Empty
        icon={<PencilLine size={26} />}
        title="An annotation starts with a function"
      >
        <p>
          Use Rename or Comment in the code view to propose a change. Review it
          here before applying it to the Ghidra project.
        </p>
      </Empty>
    );
  return (
    <div className="changes-view scroll-region">
      <div className="section-title">
        <PencilLine size={16} />
        <h3>Annotation history</h3>
        <span>{annotations.length}</span>
      </div>
      <p className="changes-intro">
        Changes are applied to the Ghidra project after review. Original
        executable bytes remain unchanged.
      </p>
      {[...annotations].reverse().map((annotation) => (
        <article className="change-card" key={annotation.id}>
          <header>
            <span className="change-kind">
              {annotation.kind === "rename" ? (
                <PencilLine size={14} />
              ) : (
                <MessageSquarePlus size={14} />
              )}
              {annotation.kind === "rename"
                ? "Rename function"
                : "Function comment"}
            </span>
            <button
              className="address-link"
              onClick={() => onNavigate(annotation.address)}
            >
              {annotation.address}
            </button>
          </header>
          <div className="change-diff">
            {annotation.old_value && (
              <pre className="diff-old">− {annotation.old_value}</pre>
            )}
            <pre className="diff-new">+ {annotation.value}</pre>
          </div>
          <footer>
            {annotation.status === "applied" ? (
              <span className="applied">
                <Check size={14} />
                Applied to project
              </span>
            ) : (
              <>
                <span className="muted">Awaiting review</span>
                <button
                  className="button primary small"
                  onClick={() => onApply(annotation)}
                  disabled={!!applying}
                >
                  {applying === annotation.id ? "Applying…" : "Apply change"}
                  <Check size={14} />
                </button>
              </>
            )}
          </footer>
        </article>
      ))}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  return (
    <button
      className="icon-button copy-button"
      title={
        failed
          ? "Clipboard unavailable. Select the text to copy it."
          : copied
            ? "Copied"
            : "Copy to clipboard"
      }
      aria-label={copied ? "Copied" : "Copy to clipboard"}
      disabled={!text}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setFailed(false);
          window.setTimeout(() => setCopied(false), 1800);
        } catch {
          setFailed(true);
        }
      }}
    >
      {copied ? <Check size={14} /> : <Clipboard size={14} />}
    </button>
  );
}
