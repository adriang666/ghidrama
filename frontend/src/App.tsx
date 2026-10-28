import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  ArrowDownToLine,
  ArrowRight,
  Binary,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Code2,
  FileCode2,
  FolderOpen,
  GitBranch,
  LoaderCircle,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings2,
  ShieldCheck,
  Upload,
  WandSparkles,
  X,
} from "lucide-react";
import { errorMessage, request, sizeLabel } from "./api";
import type {
  Analysis,
  Annotation,
  FunctionDetail,
  FunctionSummary,
  Health,
  MainTab,
  Provider,
  Ask,
  RequestedPrompt,
  Sample,
} from "./types";
import AgentPanel from "./AgentPanel";
import SettingsDialog from "./SettingsDialog";
import WorkSurface from "./WorkSurface";
import { Modal, Notice, Status } from "./ui";

export default function App() {
  const [samples, setSamples] = useState<Sample[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [functions, setFunctions] = useState<FunctionSummary[]>([]);
  const [functionAddress, setFunctionAddress] = useState<string | null>(null);
  const [func, setFunc] = useState<FunctionDetail | null>(null);
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [tab, setTab] = useState<MainTab>("overview");
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [connectionError, setConnectionError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [functionLoading, setFunctionLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [agentOpen, setAgentOpen] = useState(() => window.innerWidth > 1180);
  const [explorerOpen, setExplorerOpen] = useState(
    () => window.innerWidth > 760,
  );
  const [dragging, setDragging] = useState(false);
  const [applying, setApplying] = useState("");
  const [annotationKind, setAnnotationKind] = useState<
    "rename" | "comment" | null
  >(null);
  const [annotationValue, setAnnotationValue] = useState("");
  const [annotationError, setAnnotationError] = useState("");
  const [annotationBusy, setAnnotationBusy] = useState(false);
  const [refreshRevision, setRefreshRevision] = useState(0);
  const [requestedPrompt, setRequestedPrompt] = useState<RequestedPrompt | null>(null);
  const [toast, setToast] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const searchInput = useRef<HTMLInputElement>(null);
  const dragCount = useRef(0);
  const selected = samples.find((sample) => sample.id === selectedId);

  const refreshSamples = useCallback(async () => {
    const items = await request<Sample[]>("/api/samples");
    setSamples(items);
    setSelectedId((current) =>
      current && items.some((item) => item.id === current)
        ? current
        : items[0]?.id || null,
    );
  }, []);
  const refreshProviders = useCallback(async () => {
    try {
      setProviders(await request<Provider[]>("/api/providers"));
    } catch (err) {
      setError(errorMessage(err));
    }
  }, []);
  useEffect(() => {
    let disposed = false;
    const refresh = async () => {
      try {
        const [healthData] = await Promise.all([
          request<Health>("/api/health"),
          refreshSamples(),
        ]);
        if (!disposed) {
          setHealth(healthData);
          setConnectionError(false);
        }
      } catch {
        if (!disposed) setConnectionError(true);
      }
    };
    void refresh();
    void refreshProviders();
    const interval = window.setInterval(refresh, 2500);
    return () => {
      disposed = true;
      window.clearInterval(interval);
    };
  }, [refreshSamples, refreshProviders]);
  useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      const tag = (event.target as HTMLElement)?.tagName;
      if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(tag)) {
        event.preventDefault();
        setExplorerOpen(true);
        searchInput.current?.focus();
      }
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, []);
  useEffect(() => {
    const mobile = window.matchMedia("(max-width: 760px)");
    const compact = window.matchMedia("(max-width: 1100px)");
    const closeExplorer = (event: MediaQueryListEvent) => {
      if (event.matches) setExplorerOpen(false);
    };
    const closeAgent = (event: MediaQueryListEvent) => {
      if (event.matches) setAgentOpen(false);
    };
    mobile.addEventListener("change", closeExplorer);
    compact.addEventListener("change", closeAgent);
    return () => {
      mobile.removeEventListener("change", closeExplorer);
      compact.removeEventListener("change", closeAgent);
    };
  }, []);
  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(""), 4500);
    return () => window.clearTimeout(timeout);
  }, [toast]);
  useEffect(() => {
    setAnalysis(null);
    setFunctions([]);
    setFunc(null);
    setFunctionAddress(null);
    setAnnotations([]);
    setQuery("");
    setTab("overview");
    setError("");
  }, [selectedId]);
  useEffect(() => {
    if (!selectedId || !["ready", "partial"].includes(selected?.status || ""))
      return;
    let cancelled = false;
    setLoading(true);
    Promise.all([
      request<Analysis>(`/api/samples/${selectedId}/analysis`),
      request<FunctionSummary[]>(`/api/samples/${selectedId}/functions`),
      request<Annotation[]>(`/api/samples/${selectedId}/annotations`),
    ])
      .then(([a, f, n]) => {
        if (cancelled) return;
        setAnalysis(a);
        setFunctions(f);
        setAnnotations(n);
        setFunctionAddress((current) =>
          current && f.some((item) => item.address === current)
            ? current
            : f.find((item) => item.address === a.entry_point)?.address ||
              f[0]?.address ||
              null,
        );
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    selectedId,
    selected?.status,
    selected?.analysis_revision,
    refreshRevision,
  ]);
  useEffect(() => {
    // Reanalysis can replace a packed loader with a different function index.
    // Wait for that revision's index before fetching the selected address.
    if (!selectedId || !functionAddress ||
        !["ready", "partial"].includes(selected?.status || "") ||
        analysis?.sample_id !== selectedId ||
        analysis?.revision !== selected?.analysis_revision) {
      setFunc(null);
      setFunctionLoading(false);
      return;
    }
    let cancelled = false;
    setFunc(null);
    setFunctionLoading(true);
    request<FunctionDetail>(
      `/api/samples/${selectedId}/functions/${encodeURIComponent(functionAddress)}`,
    )
      .then((result) => {
        if (!cancelled) setFunc(result);
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setFunctionLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    selectedId,
    functionAddress,
    selected?.status,
    selected?.analysis_revision,
    analysis?.sample_id,
    analysis?.revision,
    refreshRevision,
  ]);

  const filteredFunctions = useMemo(
    () =>
      functions.filter((item) =>
        `${item.name} ${item.address}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [functions, query],
  );
  const upload = async (file?: File) => {
    if (!file || uploading) return;
    setUploading(true);
    setError("");
    const data = new FormData();
    data.append("file", file);
    try {
      const sample = await request<Sample>("/api/samples", {
        method: "POST",
        body: data,
      });
      setSelectedId(sample.id);
      setSamples((previous) => [
        sample,
        ...previous.filter((item) => item.id !== sample.id),
      ]);
      setTab("overview");
      setToast(`${sample.name} added to the analysis queue.`);
      await refreshSamples();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setUploading(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  };
  const analysisAction = async (action: "analyze" | "cancel") => {
    if (!selected) return;
    setError("");
    try {
      await request(`/api/samples/${selected.id}/${action}`, {
        method: "POST",
      });
      await refreshSamples();
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  const navigate = (address: string) => {
    let target = functions.find(
      (item) => item.address.toLowerCase() === address.toLowerCase(),
    );
    if (!target) {
      try {
        const requested = BigInt(
          address.startsWith("0x") ? address : `0x${address}`,
        );
        target = functions.find((item) => {
          const start = BigInt(
            item.address.startsWith("0x") ? item.address : `0x${item.address}`,
          );
          return requested >= start && requested < start + BigInt(item.size);
        });
      } catch {
        /* Non-memory address spaces cannot be resolved arithmetically. */
      }
    }
    if (!target) {
      setToast(
        `No analyzed function contains ${address}. It may refer to data or an external symbol.`,
      );
      return;
    }
    setFunctionAddress(target.address);
    setTab("decompiler");
  };
  const proposeAnnotation = async () => {
    if (!selected || !func || !annotationKind) return;
    setAnnotationBusy(true);
    setAnnotationError("");
    try {
      const annotation = await request<Annotation>(
        `/api/samples/${selected.id}/annotations`,
        {
          method: "POST",
          body: JSON.stringify({
            address: func.address,
            kind: annotationKind,
            value: annotationValue.trim(),
            expected_revision: selected.analysis_revision,
          }),
        },
      );
      setAnnotations((previous) => [...previous, annotation]);
      setAnnotationKind(null);
      setTab("annotations");
      setToast("Change proposed. Review it before applying.");
    } catch (err) {
      setAnnotationError(errorMessage(err));
    } finally {
      setAnnotationBusy(false);
    }
  };
  const applyAnnotation = async (annotation: Annotation) => {
    if (!selected) return;
    setApplying(annotation.id);
    try {
      await request(
        `/api/samples/${selected.id}/annotations/${annotation.id}/apply`,
        { method: "POST" },
      );
      await refreshSamples();
      setRefreshRevision((value) => value + 1);
      setToast("Annotation applied to the Ghidra project.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setApplying("");
    }
  };
  const ask: Ask = (text, mode = "investigation", scope = "function") => {
    if (!selectedId) return;
    setAgentOpen(true);
    setRequestedPrompt({ text, mode, scope, sampleId: selectedId, nonce: Date.now() });
  };

  return (
    <div
      className={`app ${!explorerOpen ? "explorer-hidden" : ""} ${!agentOpen ? "agent-hidden" : ""}`}
      onDragEnter={(event) => {
        if (event.dataTransfer.types.includes("Files")) {
          event.preventDefault();
          dragCount.current++;
          setDragging(true);
        }
      }}
      onDragLeave={(event) => {
        event.preventDefault();
        dragCount.current = Math.max(0, dragCount.current - 1);
        if (!dragCount.current) setDragging(false);
      }}
      onDragOver={(event) => {
        if (event.dataTransfer.types.includes("Files")) event.preventDefault();
      }}
      onDrop={(event) => {
        event.preventDefault();
        dragCount.current = 0;
        setDragging(false);
        if (event.dataTransfer.files.length > 1)
          setToast(
            "Opening the first file. Add further executables one at a time.",
          );
        void upload(event.dataTransfer.files[0]);
      }}
    >
      <header className="app-header">
        <a className="brand" href="/" aria-label="Ghidrama home">
          <div className="brand-mark">
            <Binary size={21} strokeWidth={2} />
          </div>
          <span>ghidrama</span>
          <span className="brand-version">WORKBENCH</span>
        </a>
        <div className="header-center">
          <span className="local-indicator">
            <span />
            Local workspace
          </span>
          <span className="header-divider" />
          <span className="engine-status">
            <span
              className={`connection-dot ${health?.ghidra_available ? "connected" : ""}`}
            />
            {health?.ghidra_available
              ? `Ghidra ${health.ghidra_version || ""}`
              : health
                ? "Ghidra not configured"
                : "Connecting…"}
          </span>
        </div>
        <div className="header-actions">
          <button
            className="icon-button help-button"
            onClick={() => setHelpOpen(true)}
            aria-label="Workbench help"
            title="Workbench help"
          >
            <CircleHelp size={18} />
          </button>
          <button
            className="button secondary settings-button"
            onClick={() => setSettingsOpen(true)}
            aria-label="Model connections"
          >
            <Settings2 size={15} />
            <span>Connections</span>
            {providers.some((provider) => provider.configured) && (
              <span className="connection-dot connected" />
            )}
          </button>
          <button
            className="button primary"
            onClick={() => fileInput.current?.click()}
            disabled={uploading}
            aria-label={uploading ? "Uploading executable" : "Open executable"}
          >
            {uploading ? (
              <LoaderCircle size={15} className="spin" />
            ) : (
              <Upload size={15} />
            )}
            <span>{uploading ? "Uploading…" : "Open executable"}</span>
          </button>
        </div>
        <input
          ref={fileInput}
          type="file"
          className="sr-only"
          accept=".exe,.dll,.sys"
          aria-label="Upload Windows executable"
          onChange={(event) => void upload(event.target.files?.[0])}
        />
      </header>
      {connectionError && (
        <div className="global-notice">
          <Notice>
            Cannot reach the analysis server. Check that the backend is running;
            the workbench will reconnect automatically.
          </Notice>
        </div>
      )}
      {!connectionError && health && !health.ghidra_available && (
        <div className="setup-banner">
          <AlertCircle size={15} />
          <span>
            Ghidra needs a valid installation and Java runtime. Configure{" "}
            <code>GHIDRA_INSTALL_DIR</code> and <code>JAVA_HOME</code> on the
            server, then restart it.
          </span>
        </div>
      )}
      {error && (
        <div className="error-banner" role="alert">
          <AlertCircle size={16} />
          <span>{error}</span>
          <button
            className="icon-button"
            onClick={() => setError("")}
            aria-label="Dismiss error"
          >
            <X size={15} />
          </button>
        </div>
      )}
      <div className="workspace">
        {explorerOpen && (
          <aside className="explorer" aria-label="Program explorer">
            <div className="panel-heading">
              <div>
                <FolderOpen size={15} />
                <h2>Explorer</h2>
              </div>
              <button
                className="icon-button"
                title="Hide explorer"
                aria-label="Hide explorer"
                onClick={() => setExplorerOpen(false)}
              >
                <PanelLeftClose size={15} />
              </button>
            </div>
            <div className="explorer-section-heading">
              <ChevronDown size={12} />
              <span>EXECUTABLES</span>
              <span className="count">{samples.length}</span>
              <button
                className="icon-button"
                aria-label="Add executable"
                onClick={() => fileInput.current?.click()}
                title="Add executable"
              >
                <Upload size={13} />
              </button>
            </div>
            <div className="sample-list">
              {samples.map((sample) => (
                <button
                  className={`sample-item ${sample.id === selectedId ? "selected" : ""}`}
                  key={sample.id}
                  onClick={() => setSelectedId(sample.id)}
                >
                  <FileCode2 size={17} />
                  <span>
                    <strong>{sample.name}</strong>
                    <small>
                      {sizeLabel(sample.size)}
                      <span>·</span>
                      {sample.architecture || "PE"}
                    </small>
                  </span>
                  <span
                    className={`sample-status-dot sample-status-${sample.status}`}
                    title={sample.status}
                  />
                </button>
              ))}
              {!samples.length && (
                <div className="explorer-empty">
                  <FileCode2 size={22} />
                  <p>No executables yet</p>
                  <button
                    className="text-button"
                    onClick={() => fileInput.current?.click()}
                  >
                    Open a file
                    <ArrowRight size={12} />
                  </button>
                </div>
              )}
            </div>
            <div className="function-explorer">
              <div className="explorer-section-heading">
                <ChevronDown size={12} />
                <span>FUNCTIONS</span>
                <span className="count">
                  {functions.length.toLocaleString()}
                </span>
              </div>
              <div className="function-search search-box">
                <Search size={13} />
                <input
                  ref={searchInput}
                  aria-label="Search functions"
                  placeholder="Search functions…"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
                <kbd>/</kbd>
              </div>
              <div className="function-list scroll-region">
                {filteredFunctions.slice(0, 3000).map((item) => (
                  <button
                    key={item.address}
                    className={`function-item ${functionAddress === item.address ? "selected" : ""}`}
                    onClick={() => {
                      setFunctionAddress(item.address);
                      if (tab !== "pseudocode") setTab("decompiler");
                    }}
                    title={item.signature || item.name}
                  >
                    <span className="function-symbol">ƒ</span>
                    <span>
                      <strong>{item.name}</strong>
                      <code>{item.address}</code>
                    </span>
                    <ChevronRight size={12} />
                  </button>
                ))}
                {!filteredFunctions.length && (
                  <div className="functions-empty">
                    {loading
                      ? "Loading functions…"
                      : query
                        ? "No matching functions."
                        : selected
                          ? "Functions will appear after analysis."
                          : "Open an executable to explore its functions."}
                  </div>
                )}
                {filteredFunctions.length > 3000 && (
                  <p className="table-note">
                    Search to narrow 3,000+ functions.
                  </p>
                )}
              </div>
            </div>
            <div className="explorer-footer">
              <ShieldCheck size={13} />
              <span>Static analysis only</span>
            </div>
          </aside>
        )}
        <main className="main-column">
          <div className="breadcrumb-bar">
            <div>
              {!explorerOpen && (
                <button
                  className="icon-button"
                  aria-label="Show explorer"
                  title="Show explorer"
                  onClick={() => setExplorerOpen(true)}
                >
                  <PanelLeftOpen size={16} />
                </button>
              )}
              <span>Workspace</span>
              <ChevronRight size={12} />
              <strong>{selected?.name || "Get started"}</strong>
            </div>
            <div>
              {selected && ["ready", "partial"].includes(selected.status) && (
                <a
                  className="icon-button"
                  title="Export analysis report"
                  aria-label="Export analysis report"
                  href={`/api/samples/${selected.id}/report`}
                  download
                >
                  <ArrowDownToLine size={15} />
                </a>
              )}
              {!agentOpen && (
                <button
                  className="text-button accent"
                  onClick={() => setAgentOpen(true)}
                >
                  <WandSparkles size={15} />
                  Investigator
                </button>
              )}
            </div>
          </div>
          <WorkSurface
            providers={providers}
            onSettings={() => setSettingsOpen(true)}
            sample={selected}
            analysis={analysis}
            func={func}
            loading={loading}
            functionLoading={functionLoading}
            tab={tab}
            setTab={setTab}
            annotations={annotations}
            onNavigate={navigate}
            onUpload={() => fileInput.current?.click()}
            onRetry={() => void analysisAction("analyze")}
            onCancel={() => void analysisAction("cancel")}
            onAnnotate={(kind) => {
              setAnnotationKind(kind);
              setAnnotationValue(
                kind === "rename" ? func?.name || "" : func?.comment || "",
              );
              setAnnotationError("");
            }}
            onApply={(annotation) => void applyAnnotation(annotation)}
            applying={applying}
            onAsk={ask}
            onSelectFunction={setFunctionAddress}
          />
        </main>
        {agentOpen && (
          <AgentPanel
            sample={selected}
            func={func}
            providers={providers}
            requestedPrompt={requestedPrompt}
            onSettings={() => setSettingsOpen(true)}
            onNavigate={navigate}
            onClose={() => setAgentOpen(false)}
          />
        )}
      </div>
      <footer className="statusbar">
        <div>
          <span className="statusbar-brand">
            <GitBranch size={12} />
            Ghidrama
          </span>
          <span>
            {selected
              ? selected.architecture || "Portable Executable"
              : "Ready to explore"}
          </span>
          {selected && <Status value={selected.status} />}
        </div>
        <div>
          {health?.active_jobs ? (
            <span>
              <LoaderCircle size={11} className="spin" />
              {health.active_jobs} active{" "}
              {health.active_jobs === 1 ? "job" : "jobs"}
            </span>
          ) : (
            <span>
              <Check size={11} />
              Worker idle
            </span>
          )}
          <span className="statusbar-right">
            {func ? func.address : "Local · single analyst"}
          </span>
        </div>
      </footer>
      {settingsOpen && (
        <SettingsDialog
          providers={providers}
          onClose={() => setSettingsOpen(false)}
          onChanged={() => void refreshProviders()}
        />
      )}
      {annotationKind && func && (
        <Modal
          title={
            annotationKind === "rename"
              ? "Propose a function name"
              : "Propose a function comment"
          }
          subtitle="Review your change before applying it to the Ghidra project."
          onClose={() => setAnnotationKind(null)}
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void proposeAnnotation();
            }}
          >
            <div className="modal-body">
              <div className="annotation-target">
                <Code2 size={16} />
                <strong>{func.name}</strong>
                <code>{func.address}</code>
              </div>
              <label className="field-label" htmlFor="annotation-value">
                {annotationKind === "rename" ? "New function name" : "Comment"}
              </label>
              {annotationKind === "rename" ? (
                <input
                  id="annotation-value"
                  value={annotationValue}
                  onChange={(event) => setAnnotationValue(event.target.value)}
                  autoFocus
                  spellCheck={false}
                />
              ) : (
                <textarea
                  id="annotation-value"
                  value={annotationValue}
                  onChange={(event) => setAnnotationValue(event.target.value)}
                  autoFocus
                  rows={6}
                />
              )}
              {annotationError && <Notice>{annotationError}</Notice>}
            </div>
            <footer className="modal-footer">
              <button
                type="button"
                className="button secondary"
                onClick={() => setAnnotationKind(null)}
              >
                Cancel
              </button>
              <button
                className="button primary"
                type="submit"
                disabled={annotationBusy || !annotationValue.trim()}
              >
                {annotationBusy ? "Saving…" : "Propose change"}
                <ArrowRight size={14} />
              </button>
            </footer>
          </form>
        </Modal>
      )}
      {helpOpen && (
        <Modal
          title="A workbench built around evidence"
          subtitle="Ghidra analysis, with an agent that follows the same code you do."
          onClose={() => setHelpOpen(false)}
        >
          <div className="modal-body help-content">
            {[
              [
                "Open an executable",
                "Upload a native Windows x86 or x64 PE file. Ghidra analyzes it without executing it.",
              ],
              [
                "Explore the program",
                "Select a function to inspect reconstructed C, assembly, and callers. Press / to search functions.",
              ],
              [
                "Connect a model and investigate",
                "Add an Ollama Cloud or OpenRouter key in Connections. Questions send selected analysis evidence to that provider. Follow citation links back to the code.",
              ],
              [
                "Review changes",
                "Propose names and comments, then apply them from Changes. Original executable bytes stay unchanged.",
              ],
            ].map(([title, content], index) => (
              <div key={title}>
                <span>0{index + 1}</span>
                <section>
                  <h3>{title}</h3>
                  <p>{content}</p>
                </section>
              </div>
            ))}
            <Notice tone="info">
              Decompiler output and model conclusions can be incomplete. Inspect
              supporting instructions and references when accuracy matters.
            </Notice>
          </div>
          <footer className="modal-footer">
            <span />
            <button
              className="button primary"
              onClick={() => setHelpOpen(false)}
            >
              Back to workbench
              <ArrowRight size={14} />
            </button>
          </footer>
        </Modal>
      )}
      {dragging && (
        <div className="drop-overlay">
          <div>
            <Upload size={36} />
            <h2>Open an executable</h2>
            <p>Drop your Windows PE file to begin analysis.</p>
          </div>
        </div>
      )}
      {toast && (
        <div className="toast" role="status">
          <Check size={16} />
          <span>{toast}</span>
          <button
            className="icon-button"
            onClick={() => setToast("")}
            aria-label="Dismiss notification"
          >
            <X size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
