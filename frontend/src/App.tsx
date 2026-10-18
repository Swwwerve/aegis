import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  Check,
  Circle,
  ChevronRight,
  CircleAlert,
  Code2,
  Download,
  FolderGit2,
  GitBranch,
  GitFork,
  History,
  LayoutDashboard,
  LoaderCircle,
  Plus,
  RefreshCw,
  Shield,
  Sparkles,
  Terminal,
  Workflow,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { AnalysisView, Empty, StateBadge } from "@/components/analysis-view";
import { ResultsView } from "@/components/results-view";
import { PatchDemoView } from "@/components/patch-demo-view";
import {
  ApiError,
  canonicalUrl,
  downloadJson,
  get,
  register,
  streamScan,
} from "@/lib/api";
import {
  examples,
  stages,
  type Activity,
  type Analysis,
  type ProgressEvent,
  type Repository,
  type Scan,
} from "@/lib/types";
import { cn } from "@/lib/utils";
import { AgentActivity } from "@/components/ai-elements/agent-activity";
import { ExecutionPanel } from "@/components/ai-elements/execution-panel";

type View = "workspace" | "repositories" | "history";
export default function App() {
  const [view, setView] = useState<View>("workspace");
  const [repos, setRepos] = useState<Repository[]>([]);
  const [history, setHistory] = useState<Scan[]>([]);
  const [connected, setConnected] = useState<boolean | null>(null);
  const [loadError, setLoadError] = useState("");
  const [url, setUrl] = useState("");
  const [useModel, setUseModel] = useState(true);
  const [resolve, setResolve] = useState(false);
  const [repository, setRepository] = useState<Repository | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [activity, setActivity] = useState<Activity[]>([]);
  const [states, setStates] = useState<Record<string, string>>({});
  const [elapsed, setElapsed] = useState(0);
  const controller = useRef<AbortController | null>(null);
  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const [r, h] = await Promise.all([
        get<Repository[]>("/repositories", signal),
        get<Scan[]>("/scans?limit=30", signal),
      ]);
      setRepos(r);
      setHistory(h);
      setConnected(true);
      setLoadError("");
    } catch {
      if (!signal?.aborted) {
        setConnected(false);
        setLoadError(
          "Could not connect to Aegis. Start the backend on port 8000, then refresh the connection.",
        );
      }
    }
  }, []);
  useEffect(() => {
    const c = new AbortController();
    void refresh(c.signal);
    return () => {
      c.abort();
    };
  }, [refresh]);
  useEffect(
    () => () => {
      controller.current?.abort();
    },
    [],
  );
  useEffect(() => {
    if (!busy) return;
    setElapsed(0);
    const timer = setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => clearInterval(timer);
  }, [busy]);

  function progress(event: ProgressEvent) {
    setStates((s) => ({ ...s, [event.stage]: event.status }));
    setActivity((a) => [
      ...a,
      { ...event, time: new Date().toLocaleTimeString() },
    ]);
    if (event.analysis) setAnalysis(event.analysis);
  }
  async function start(event?: React.FormEvent) {
    event?.preventDefault();
    if (busy) return;
    let canonical: string;
    try {
      canonical = canonicalUrl(url);
    } catch (e) {
      setError((e as Error).message);
      return;
    }
    setView("workspace");
    setError("");
    setBusy(true);
    setScan(null);
    setAnalysis(null);
    setActivity([]);
    setStates({});
    setRepository(null);
    const c = new AbortController();
    controller.current = c;
    try {
      progress({
        stage: "intake",
        status: "running",
        message:
          "Validating the public GitHub URL and preparing a local repository clone.",
      });
      let repo = repos.find(
        (r) =>
          r.url.toLowerCase().replace(/\/$/, "") === canonical.toLowerCase(),
      );
      if (!repo) {
        try {
          repo = await register(canonical, c.signal);
        } catch (e) {
          if (!(e instanceof ApiError) || e.status !== 409) throw e;
          const registered = await get<Repository[]>("/repositories", c.signal);
          repo = registered.find(
            (r) => r.url.toLowerCase() === canonical.toLowerCase(),
          );
          if (!repo)
            throw new Error(
              "This repository is registered, but its record could not be found. Refresh the repository list.",
            );
        }
      }
      setRepository(repo);
      setConnected(true);
      setRepos((r) => (r.some((x) => x.id === repo!.id) ? r : [...r, repo!]));
      progress({
        stage: "intake",
        status: "completed",
        message: `${repo.owner}/${repo.name} is registered. Inspecting its saved clone on branch ${repo.default_branch || "unknown"}.`,
      });
      await streamScan(
        repo.id,
        { use_model: useModel, resolve_dependencies: resolve },
        c.signal,
        progress,
        (result) => {
          setScan(result);
          setHistory((h) =>
            [result, ...h.filter((run) => run.id !== result.id)].slice(0, 30),
          );
          if (result.report?.repository_analysis)
            setAnalysis(result.report.repository_analysis);
          setStates((s) =>
            Object.fromEntries(
              stages.map((stage) => [
                stage.id,
                s[stage.id] === "running" ? "failed" : s[stage.id] || "not_run",
              ]),
            ),
          );
          if (result.status === "failed")
            setError(
              "The scan failed. Available output and failure details are shown below.",
            );
        },
      );
    } catch (e) {
      const message = c.signal.aborted
        ? "Viewing stopped. The repository may still have been registered; refresh history before retrying."
        : e instanceof Error
          ? e.message
          : "The scan could not finish. Check history before retrying.";
      setError(message);
      setStates((s) =>
        Object.fromEntries(
          Object.entries(s).map(([k, v]) => [
            k,
            v === "running" ? "failed" : v,
          ]),
        ),
      );
    } finally {
      setBusy(false);
      controller.current = null;
    }
  }
  function newScan() {
    if (busy) {
      setView("workspace");
      return;
    }
    setScan(null);
    setAnalysis(null);
    setActivity([]);
    setStates({});
    setRepository(null);
    setError("");
    setUrl("");
    setView("workspace");
  }
  function openRun(run: Scan) {
    setScan(run);
    setRepository(repos.find((r) => r.id === run.repository_id) || null);
    setAnalysis(run.report?.repository_analysis || null);
    setActivity([]);
    setStates({});
    setError("");
    setView("workspace");
  }
  const hasRun = !!activity.length || !!scan;
  return (
    <TooltipProvider>
      <div className="workspace-shell min-h-screen">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[100] focus:rounded-md focus:bg-primary focus:p-3 focus:text-primary-foreground"
        >
          Skip to content
        </a>
        <header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur-xl">
          <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-8 gap-y-3 px-5 py-4 md:px-9">
            <button
              onClick={() => setView("workspace")}
              aria-label="Aegis overview"
              className="flex items-center gap-2.5"
            >
              <Logo />
              <span className="text-lg font-semibold tracking-[.16em]">
                AEGIS
              </span>
              <span className="hidden rounded border px-1.5 py-0.5 text-[11px] tracking-wider text-muted-foreground lg:block">
                WORKSPACE
              </span>
            </button>
            <nav
              aria-label="Main navigation"
              className="order-3 flex w-full gap-1 border-t pt-3 sm:order-none sm:w-auto sm:border-0 sm:pt-0"
            >
              {[
                { id: "workspace", label: "Overview", icon: LayoutDashboard },
                { id: "repositories", label: "Repositories", icon: FolderGit2 },
                { id: "history", label: "Scan history", icon: History },
              ].map(({ id, label, icon: Icon }) => (
                <Button
                  key={id}
                  variant="ghost"
                  size="sm"
                  aria-current={view === id ? "page" : undefined}
                  className={cn(
                    "flex-1 gap-2 text-xs sm:flex-none",
                    view === id
                      ? "bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary"
                      : "text-muted-foreground",
                  )}
                  onClick={() => setView(id as View)}
                >
                  <Icon size={15} />
                  {label}
                </Button>
              ))}
            </nav>
            <div className="ml-auto flex items-center gap-3">
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    onClick={() => void refresh()}
                    aria-label="Refresh backend connection"
                    className="flex items-center gap-2 rounded-full border bg-card px-3 py-2 text-[11px] text-muted-foreground"
                  >
                    <span
                      className={cn(
                        "size-1.5 rounded-full",
                        connected == null
                          ? "animate-pulse bg-slate-400"
                          : connected
                            ? "bg-emerald-400"
                            : "bg-amber-400",
                      )}
                    />
                    <span className="hidden md:inline">
                      {connected == null
                        ? "Connecting"
                        : connected
                          ? "Backend connected"
                          : "Backend offline"}
                    </span>
                  </button>
                </TooltipTrigger>
                <TooltipContent>
                  Refresh repositories and saved scans
                </TooltipContent>
              </Tooltip>
              <Button size="sm" className="text-xs" onClick={newScan}>
                <Plus size={14} />
                New scan
              </Button>
            </div>
          </div>
        </header>
        <div>
          <main
            id="main-content"
            className="mx-auto max-w-[1380px] space-y-8 px-5 py-8 md:px-9 lg:py-10"
          >
            {loadError && (
              <div
                role="status"
                className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-400/20 bg-amber-500/10 p-4 text-xs text-amber-300"
              >
                <span>{loadError}</span>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void refresh()}
                >
                  <RefreshCw size={13} />
                  Refresh
                </Button>
              </div>
            )}
            {view === "workspace" ? (
              <>
                {!hasRun && (
                  <section className="relative flex min-h-[250px] items-center justify-between overflow-hidden pb-4">
                    <div className="relative z-10 max-w-xl">
                      <p className="mb-4 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[.18em] text-primary">
                        <span className="size-1.5 rounded-full bg-primary" />
                        YOUR SECURITY CONTROL ROOM
                      </p>
                      <h1 className="text-balance text-[40px] font-semibold leading-[1.15] tracking-[-.045em] sm:text-[54px]">
                        Less noise.
                        <br />
                        <span className="text-primary">More certainty.</span>
                      </h1>
                      <p className="mt-4 max-w-[425px] text-sm leading-6 text-muted-foreground">
                        Understand your dependencies, investigate real threats,
                        and watch your agents build a safer codebase. Every
                        step, in view.
                      </p>
                    </div>
                    <div className="relative hidden h-[190px] w-[315px] shrink-0 xl:block">
                      <div className="hero-grid absolute inset-[-20px]" />
                      <div className="absolute left-5 top-7 z-10 flex items-center gap-3 rounded-xl border bg-card px-4 py-3 shadow-sm">
                        <FolderGit2
                          className="text-muted-foreground"
                          size={20}
                        />
                        <div>
                          <p className="text-[11px] uppercase tracking-widest text-muted-foreground">
                            Your repository
                          </p>
                          <p className="mono mt-1 text-xs">
                            code / dependencies
                          </p>
                        </div>
                      </div>
                      <div className="absolute left-[82px] top-[80px] h-7 border-l border-dashed border-border" />
                      <div className="absolute left-[58px] top-[102px] z-20 flex items-center gap-3 rounded-xl border border-orange-400/20 bg-primary/10 px-4 py-3 shadow-sm">
                        <Sparkles className="text-primary" size={18} />
                        <div>
                          <p className="text-xs font-semibold">
                            Connected intelligence
                          </p>
                          <p className="mt-1 text-[11px] text-muted-foreground">
                            Discover. Enrich. Prioritize.
                          </p>
                        </div>
                        <ArrowUpRight size={15} className="ml-2 text-primary" />
                      </div>
                    </div>
                  </section>
                )}
                {hasRun && (
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="mb-2 text-[11px] font-semibold uppercase tracking-[.16em] text-primary">
                        Repository workspace
                      </p>
                      <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
                        <FolderGit2
                          size={22}
                          className="text-muted-foreground"
                        />
                        {repository
                          ? `${repository.owner}/${repository.name}`
                          : "Preparing repository"}
                      </h1>
                      <p className="mt-2 text-xs text-muted-foreground">
                        {busy
                          ? `Analysis in progress · ${elapsed}s elapsed`
                          : scan
                            ? `Scan #${scan.id} · ${scan.status === "partial" ? "Completed with coverage gaps" : scan.status}`
                            : "Pipeline activity"}
                      </p>
                    </div>
                    {analysis && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          downloadJson(analysis, "aegis-analysis.json")
                        }
                      >
                        <Download size={13} />
                        Export inventory
                      </Button>
                    )}
                  </div>
                )}
                <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
                  <Card className="gap-0 overflow-hidden shadow-[0_2px_8px_#17213303]">
                    <CardContent className="p-6">
                      <div className="mb-5 flex items-center gap-3">
                        <span className="flex size-9 items-center justify-center rounded-lg border bg-muted/40">
                          <GitFork size={18} />
                        </span>
                        <div>
                          <h2 className="text-sm font-semibold">
                            {hasRun
                              ? "Scan configuration"
                              : "Start a security analysis"}
                          </h2>
                          <p className="mt-1 text-xs text-muted-foreground">
                            Public GitHub repositories · Python, Node.js & Java
                          </p>
                        </div>
                        <Badge
                          variant="secondary"
                          className="ml-auto hidden text-[11px] sm:inline-flex"
                        >
                          Read-only inspection
                        </Badge>
                      </div>
                      <form onSubmit={start}>
                        <label
                          htmlFor="repository-url"
                          className="mb-2 block text-xs font-medium"
                        >
                          Repository URL
                        </label>
                        <div className="flex flex-col gap-2 sm:flex-row">
                          <div className="relative min-w-0 flex-1">
                            <GitBranch className="absolute left-3 top-3 size-4 text-muted-foreground" />
                            <Input
                              id="repository-url"
                              className="h-10 bg-muted/20 pl-9 text-sm"
                              placeholder="https://github.com/owner/repository"
                              value={url}
                              onChange={(e) => setUrl(e.target.value)}
                              disabled={busy}
                              autoComplete="url"
                              required
                            />
                          </div>
                          <Button
                            type="submit"
                            className="h-10 px-5 text-xs shadow-none"
                            disabled={busy}
                          >
                            {busy ? (
                              <>
                                <LoaderCircle
                                  className="animate-spin"
                                  size={14}
                                />
                                Analyzing
                              </>
                            ) : (
                              <>
                                Analyze repository
                                <ArrowRight size={14} />
                              </>
                            )}
                          </Button>
                        </div>
                        <div className="mt-5 grid gap-4 border-t pt-4 sm:grid-cols-2">
                          <div className="flex items-start gap-3">
                            <Switch
                              id="model-option"
                              checked={useModel}
                              onCheckedChange={setUseModel}
                              disabled={busy}
                              className="mt-0.5"
                            />
                            <div>
                              <label
                                htmlFor="model-option"
                                className="cursor-pointer text-xs font-medium"
                              >
                                Model-assisted intelligence
                              </label>
                              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                                Architecture insights & contextual priority.
                                Uses your configured AI provider.
                              </p>
                            </div>
                          </div>
                          <div className="flex items-start gap-3">
                            <Switch
                              id="resolution-option"
                              checked={resolve}
                              onCheckedChange={setResolve}
                              disabled={busy}
                              className="mt-0.5"
                            />
                            <div>
                              <label
                                htmlFor="resolution-option"
                                className="cursor-pointer text-xs font-medium"
                              >
                                Resolve dependency graph
                              </label>
                              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                                Retrieve the cached dependency graph in Docker
                                and inspect command output. Uncached packages
                                are reported.
                              </p>
                            </div>
                          </div>
                        </div>
                      </form>
                      {busy && (
                        <button
                          className="mt-4 text-xs text-muted-foreground underline underline-offset-4"
                          onClick={() => controller.current?.abort()}
                        >
                          Stop viewing this run
                        </button>
                      )}
                      {error && (
                        <div
                          role="alert"
                          className="mt-4 flex items-start gap-2 rounded-lg border border-red-400/20 bg-red-500/10 p-3 text-xs leading-5 text-red-300"
                        >
                          <CircleAlert size={15} className="mt-0.5 shrink-0" />
                          {error}
                        </div>
                      )}
                    </CardContent>
                    {!hasRun && (
                      <div className="border-t bg-muted/30 px-6 py-4">
                        <p className="mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                          Try an example{" "}
                          <span className="font-normal normal-case tracking-normal">
                            Real security learning repositories
                          </span>
                        </p>
                        <div className="grid gap-2 sm:grid-cols-3">
                          {examples.map((e) => (
                            <button
                              disabled={busy}
                              key={e.name}
                              className={cn(
                                "group rounded-lg border bg-card p-3 text-left transition-colors hover:border-orange-400/20",
                                url === e.url &&
                                  "border-orange-400/20 bg-orange-500/10",
                              )}
                              onClick={() => {
                                setUrl(e.url);
                                setError("");
                              }}
                            >
                              <div className="flex items-center justify-between gap-1">
                                <span className="text-xs font-semibold">
                                  {e.name}
                                </span>
                                <ArrowUpRight className="size-3 text-muted-foreground group-hover:text-primary" />
                              </div>
                              <p className="mt-1 text-[11px] text-muted-foreground">
                                {e.owner}
                              </p>
                              <p className="mt-3 flex items-center gap-1.5 text-[11px]">
                                <span
                                  className="size-1.5 rounded-full"
                                  style={{ background: e.color }}
                                />
                                {e.language}
                              </p>
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </Card>
                  {hasRun ? (
                    <AgentActivity
                      events={activity}
                      running={busy}
                      label="Pipeline activity"
                    />
                  ) : (
                    <Card className="gap-0 border-dashed bg-transparent shadow-none">
                      <CardContent className="p-6">
                        <p className="mb-5 text-[11px] font-semibold uppercase tracking-[.15em] text-muted-foreground">
                          From discovery to verification
                        </p>
                        {[
                          {
                            icon: Code2,
                            title: "Understand the repository",
                            text: "Identify languages, dependencies, and build / test plans.",
                          },
                          {
                            icon: Shield,
                            title: "Discover the evidence",
                            text: "Query OSV and enrich findings with live security signals.",
                          },
                          {
                            icon: Sparkles,
                            title: "Put risk in context",
                            text: "Connect severity, exploitation, and source usage.",
                          },
                        ].map(({ icon: Icon, title, text }, i) => (
                          <div
                            key={title}
                            className={cn(
                              "relative flex gap-3 pb-5",
                              i < 2 &&
                                "before:absolute before:left-[14px] before:top-9 before:h-6 before:border-l before:border-dashed before:border-border",
                            )}
                          >
                            <span className="flex size-7 shrink-0 items-center justify-center rounded-lg border bg-card">
                              <Icon
                                size={13}
                                className="text-muted-foreground"
                              />
                            </span>
                            <div>
                              <h3 className="text-xs font-medium">{title}</h3>
                              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                                {text}
                              </p>
                            </div>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  )}
                </div>
                <section aria-label="Connected scan pipeline">
                  <div className="mb-4 flex items-center justify-between">
                    <h2 className="flex items-center gap-2 text-xs font-semibold">
                      <Workflow size={15} className="text-muted-foreground" />
                      The connected pipeline
                    </h2>
                    <p className="text-[11px] text-muted-foreground">
                      {busy
                        ? "Stages update as the backend runs"
                        : "Source to evidence to priority"}
                    </p>
                  </div>
                  <div className="grid grid-cols-3 gap-2 sm:grid-cols-5 xl:grid-cols-9">
                    {stages.map((s, i) => (
                      <div
                        key={s.id}
                        className={cn(
                          "relative min-w-0 rounded-lg border bg-card p-3",
                          states[s.id] === "running" &&
                            "border-orange-400/20 bg-orange-500/10",
                          ["partial", "failed", "unavailable"].includes(
                            states[s.id],
                          ) && "border-amber-400/20",
                        )}
                      >
                        <div className="mb-3 flex items-center justify-between">
                          <span className="mono text-[11px] text-muted-foreground">
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <StageIcon status={states[s.id] || "pending"} />
                        </div>
                        <p className="text-[11px] font-semibold">{s.title}</p>
                        <p className="mt-1 text-[11px] leading-4 text-muted-foreground">
                          {states[s.id]
                            ? states[s.id].replaceAll("_", " ")
                            : s.detail}
                        </p>
                      </div>
                    ))}
                  </div>
                </section>
                {hasRun && (
                  <ExecutionPanel
                    events={activity}
                    results={analysis?.execution_results}
                    running={busy}
                    enabled={resolve || !!analysis?.execution_results?.length}
                  />
                )}
                {analysis && <AnalysisView analysis={analysis} />}
                {scan && <ResultsView key={scan.id} scan={scan} />}
                <PatchDemoView />
                {!hasRun && (
                  <div className="flex flex-wrap items-center gap-5 border-t pt-5 text-[11px] text-muted-foreground">
                    <span className="flex items-center gap-1.5">
                      <Shield size={12} />
                      Evidence-backed findings
                    </span>
                    <span className="flex items-center gap-1.5">
                      <Terminal size={12} />
                      Isolated optional execution
                    </span>
                    <span className="flex items-center gap-1.5">
                      <History size={12} />
                      Saved scan snapshots
                    </span>
                    <span className="ml-auto">
                      Built for clarity. Grounded in evidence.
                    </span>
                  </div>
                )}
              </>
            ) : view === "repositories" ? (
              <section className="rise-in space-y-5">
                <PageHeading
                  title="Your repositories"
                  description="Registered clones ready for analysis. Reusing a repository inspects its saved clone."
                />
                <div className="grid gap-4 lg:grid-cols-2">
                  {repos.map((r) => (
                    <Card key={r.id} className="gap-0 shadow-none">
                      <CardContent className="p-5">
                        <div className="flex items-start gap-3">
                          <span className="rounded-lg border bg-muted p-2.5">
                            <FolderGit2 size={18} />
                          </span>
                          <div className="min-w-0">
                            <h2 className="break-all text-sm font-semibold">
                              {r.owner}/{r.name}
                            </h2>
                            <p className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
                              <GitBranch size={12} />
                              {r.default_branch || "Unknown branch"}
                            </p>
                          </div>
                        </div>
                        <div className="mt-5 flex items-center justify-between">
                          <a
                            href={r.url}
                            target="_blank"
                            rel="noreferrer"
                            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-primary"
                          >
                            View source
                            <ArrowUpRight size={13} />
                          </a>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={busy}
                            onClick={() => {
                              newScan();
                              setUrl(r.url);
                            }}
                          >
                            Analyze
                            <ArrowRight size={13} />
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
                {!repos.length && (
                  <Card className="shadow-none">
                    <Empty text="No repositories yet. Add a public GitHub URL or choose an example from Overview." />
                  </Card>
                )}
              </section>
            ) : (
              <section className="rise-in space-y-5">
                <div className="flex items-center justify-between">
                  <PageHeading
                    title="Scan history"
                    description="Saved evidence snapshots, newest first. Open a run to inspect its findings and inventory."
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void refresh()}
                  >
                    <RefreshCw size={14} />
                    Refresh
                  </Button>
                </div>
                <Card className="gap-0 overflow-hidden shadow-none">
                  <CardContent className="p-0">
                    {history.map((run) => {
                      const repo = repos.find(
                        (r) => r.id === run.repository_id,
                      );
                      return (
                        <button
                          key={run.id}
                          disabled={busy}
                          onClick={() => openRun(run)}
                          className="flex w-full items-center justify-between gap-3 border-b p-5 text-left last:border-0 hover:bg-muted/60"
                        >
                          <div className="flex min-w-0 items-center gap-3">
                            <History
                              size={17}
                              className="shrink-0 text-muted-foreground"
                            />
                            <div className="min-w-0">
                              <p className="truncate text-sm font-semibold">
                                {repo
                                  ? `${repo.owner}/${repo.name}`
                                  : `Repository #${run.repository_id}`}
                              </p>
                              <p className="mt-1 text-[11px] text-muted-foreground">
                                Scan #{run.id} ·{" "}
                                {new Date(run.created_at).toLocaleString()} ·{" "}
                                {run.report?.vulnerabilities.length ?? "--"}{" "}
                                findings
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <StateBadge status={run.status} />
                            <ChevronRight size={16} />
                          </div>
                        </button>
                      );
                    })}
                    {!history.length && (
                      <Empty text="Your completed and failed scans will appear here. Start a run from Overview." />
                    )}
                  </CardContent>
                </Card>
                <p className="text-xs text-muted-foreground">
                  Showing the latest 30 scans. Live activity belongs to the
                  current run; saved reports retain its evidence.
                </p>
              </section>
            )}
          </main>
          <footer className="flex items-center justify-between px-5 py-5 text-[11px] text-muted-foreground md:px-9">
            <span>Aegis / Repository intelligence</span>
            <span>Inspect with confidence. Act with context.</span>
          </footer>
        </div>
      </div>
    </TooltipProvider>
  );
}
function Logo() {
  return (
    <div
      className="relative grid size-7 grid-cols-2 gap-[3px]"
      aria-hidden="true"
    >
      <span className="rounded-tl-md bg-primary" />
      <span className="rounded-tr-md bg-primary/50" />
      <span className="rounded-bl-md bg-primary/50" />
      <span className="rounded-br-md bg-primary" />
    </div>
  );
}
function StageIcon({ status }: { status: string }) {
  return status === "running" ? (
    <LoaderCircle size={13} className="animate-spin text-primary" />
  ) : status === "completed" ? (
    <Check size={13} className="text-emerald-300" />
  ) : ["partial", "failed", "unavailable"].includes(status) ? (
    <CircleAlert size={13} className="text-amber-300" />
  ) : status === "skipped" || status === "not_run" ? (
    <span className="text-xs leading-3 text-muted-foreground">-</span>
  ) : (
    <Circle size={12} className="text-slate-300" />
  );
}
function PageHeading({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="mt-2 max-w-xl text-sm leading-6 text-muted-foreground">
        {description}
      </p>
    </div>
  );
}
