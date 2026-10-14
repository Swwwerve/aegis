import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  Activity as ActivityIcon,
  Boxes,
  ChevronRight,
  Check,
  Circle,
  CircleAlert,
  Code2,
  Download,
  FolderGit2,
  GitBranch,
  GitFork,
  History,
  LayoutDashboard,
  LoaderCircle,
  Menu,
  Plus,
  RefreshCw,
  Shield,
  Sparkles,
  Terminal,
  X,
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

type View = "workspace" | "repositories" | "history";
export default function App() {
  const [view, setView] = useState<View>("workspace");
  const [mobileNav, setMobileNav] = useState(false);
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
  const activityEnd = useRef<HTMLDivElement>(null);
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
  useEffect(() => {
    activityEnd.current?.scrollIntoView({
      block: "nearest",
      behavior: "instant",
    });
  }, [activity]);

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
  const title =
    view === "workspace"
      ? "Overview"
      : view === "repositories"
        ? "Repositories"
        : "Scan history";
  return (
    <TooltipProvider>
      <div className="min-h-screen">
        {mobileNav && (
          <button
            className="fixed inset-0 z-40 bg-black/40 md:hidden"
            aria-label="Close navigation"
            onClick={() => setMobileNav(false)}
          />
        )}
        <aside
          className={cn(
            "fixed inset-y-0 left-0 z-50 flex w-[218px] flex-col overflow-y-auto border-r border-white/5 bg-[#1c222c] text-slate-300 transition-transform md:translate-x-0",
            mobileNav ? "translate-x-0" : "hidden -translate-x-full md:flex",
          )}
        >
          <div className="flex h-[82px] items-center gap-3 px-7">
            <Logo />
            <span className="text-xl font-semibold tracking-[.12em] text-white">
              AEGIS
            </span>
            <button
              className="ml-auto md:hidden"
              onClick={() => setMobileNav(false)}
              aria-label="Close navigation"
            >
              <X size={17} />
            </button>
          </div>
          <div className="mx-4 mb-7 flex items-center gap-3 rounded-lg border border-white/10 bg-white/[.03] px-3 py-3">
            <div className="flex size-8 items-center justify-center rounded-md bg-white/10">
              <Boxes size={16} />
            </div>
            <div>
              <p className="text-xs font-medium text-slate-100">
                Local workspace
              </p>
              <p className="mt-0.5 text-[10px] text-slate-500">
                Repository intelligence
              </p>
            </div>
          </div>
          <p className="mb-3 px-7 text-[9px] font-semibold uppercase tracking-[.18em] text-slate-500">
            Workspace
          </p>
          <nav aria-label="Main navigation" className="space-y-1 px-3">
            {[
              { id: "workspace", label: "Overview", icon: LayoutDashboard },
              { id: "repositories", label: "Repositories", icon: FolderGit2 },
              { id: "history", label: "Scan history", icon: History },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                className={cn(
                  "flex w-full items-center gap-3 rounded-lg px-4 py-3 text-xs transition-colors",
                  view === id
                    ? "bg-white/[.08] text-white"
                    : "hover:bg-white/[.04] hover:text-white",
                )}
                onClick={() => {
                  setView(id as View);
                  setMobileNav(false);
                }}
              >
                <Icon
                  size={16}
                  className={view === id ? "text-[#f49a75]" : "text-slate-500"}
                />
                {label}
                {id === "repositories" && repos.length > 0 && (
                  <span className="ml-auto rounded bg-white/10 px-1.5 py-0.5 text-[10px] text-slate-400">
                    {repos.length}
                  </span>
                )}
              </button>
            ))}
          </nav>
          <div className="mx-6 mt-9 border-t border-white/10 pt-6">
            <p className="mb-4 text-[9px] font-semibold uppercase tracking-[.16em] text-slate-500">
              Connected intelligence
            </p>
            {[
              ["Source & dependencies", Code2],
              ["Advisory evidence", Shield],
              ["Contextual priorities", Sparkles],
            ].map(([label, Icon]) => {
              const I = Icon as typeof Code2;
              return (
                <p
                  key={label as string}
                  className="mb-4 flex items-center gap-3 text-[11px] text-slate-400"
                >
                  <I size={13} className="text-slate-600" />
                  {label as string}
                </p>
              );
            })}
          </div>
          <div className="mt-auto px-5 pb-5">
            <div className="mb-5 rounded-lg border border-white/10 p-4">
              <div className="mb-2 flex items-center gap-2 text-xs text-slate-200">
                <Workflow size={14} className="text-[#f49a75]" />
                Evidence, end to end.
              </div>
              <p className="text-[10px] leading-5 text-slate-500">
                Every finding connects back to a dependency, an advisory, and
                its context.
              </p>
            </div>
            <div className="flex items-center gap-2.5 border-t border-white/10 pt-4">
              <div className="flex size-8 items-center justify-center rounded-full bg-[#35404c] text-xs font-semibold text-white">
                A
              </div>
              <div>
                <p className="text-xs text-slate-200">Your workspace</p>
                <p className="mt-0.5 text-[10px] text-slate-500">
                  Local development
                </p>
              </div>
            </div>
          </div>
        </aside>
        <div className="md:ml-[218px]">
          <header className="flex h-[72px] items-center justify-between gap-3 border-b bg-white/70 px-5 md:px-9">
            <div className="flex items-center gap-2 text-xs">
              <button
                className="mr-2 md:hidden"
                aria-label="Open navigation"
                onClick={() => setMobileNav(true)}
              >
                <Menu size={20} />
              </button>
              <span className="text-muted-foreground">Workspace</span>
              <ChevronRight size={12} className="text-slate-400" />
              <span className="font-medium">{title}</span>
            </div>
            <div className="flex items-center gap-4">
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    onClick={() => void refresh()}
                    className="flex items-center gap-2 text-[11px] text-muted-foreground"
                    aria-label="Refresh backend connection"
                  >
                    <span
                      className={cn(
                        "size-1.5 rounded-full",
                        connected == null
                          ? "animate-pulse bg-slate-400"
                          : connected
                            ? "bg-emerald-500"
                            : "bg-amber-500",
                      )}
                    />
                    <span className="hidden sm:inline">
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
              <Button
                size="sm"
                variant="outline"
                className="h-8 gap-1.5 text-xs"
                onClick={newScan}
              >
                <Plus size={14} />
                New scan
              </Button>
            </div>
          </header>
          <main className="mx-auto max-w-[1480px] space-y-7 px-5 py-8 md:px-9 lg:py-10">
            {loadError && (
              <div
                role="status"
                className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50 p-4 text-xs text-amber-900"
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
                  <section className="relative flex min-h-[206px] items-center justify-between overflow-hidden pb-4">
                    <div className="relative z-10 max-w-xl">
                      <p className="mb-4 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.18em] text-primary">
                        <span className="size-1.5 rounded-full bg-primary" />
                        Clarity starts with your code
                      </p>
                      <h1 className="text-balance text-[36px] font-semibold leading-[1.15] tracking-[-.045em] sm:text-[43px]">
                        Know your code.
                        <br />
                        <span className="text-[#89909b]">
                          Understand your risk.
                        </span>
                      </h1>
                      <p className="mt-4 max-w-[425px] text-sm leading-6 text-muted-foreground">
                        From repository to prioritized findings. See what Aegis
                        discovers, how it connects, and why it matters.
                      </p>
                    </div>
                    <div className="relative hidden h-[190px] w-[315px] shrink-0 xl:block">
                      <div className="hero-grid absolute inset-[-20px]" />
                      <div className="absolute left-5 top-7 z-10 flex items-center gap-3 rounded-xl border bg-white px-4 py-3 shadow-sm">
                        <FolderGit2 className="text-slate-500" size={20} />
                        <div>
                          <p className="text-[9px] uppercase tracking-widest text-muted-foreground">
                            Your repository
                          </p>
                          <p className="mono mt-1 text-xs">
                            code / dependencies
                          </p>
                        </div>
                      </div>
                      <div className="absolute left-[82px] top-[80px] h-7 border-l border-dashed border-slate-300" />
                      <div className="absolute left-[58px] top-[102px] z-20 flex items-center gap-3 rounded-xl border border-orange-200 bg-[#fff9f4] px-4 py-3 shadow-sm">
                        <Sparkles className="text-primary" size={18} />
                        <div>
                          <p className="text-xs font-semibold">
                            Connected intelligence
                          </p>
                          <p className="mt-1 text-[10px] text-muted-foreground">
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
                      <p className="mb-2 text-[10px] font-semibold uppercase tracking-[.16em] text-primary">
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
                <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
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
                              : "Start with a repository"}
                          </h2>
                          <p className="mt-1 text-xs text-muted-foreground">
                            Public GitHub repositories · Python, Node.js & Java
                          </p>
                        </div>
                        <Badge
                          variant="secondary"
                          className="ml-auto hidden text-[10px] sm:inline-flex"
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
                                Requires a configured host API key.
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
                                Sandbox dependency resolution
                              </label>
                              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                                Optional offline resolution in Docker. Uncached
                                dependencies may remain unresolved.
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
                          className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs leading-5 text-red-800"
                        >
                          <CircleAlert size={15} className="mt-0.5 shrink-0" />
                          {error}
                        </div>
                      )}
                    </CardContent>
                    {!hasRun && (
                      <div className="border-t bg-muted/30 px-6 py-4">
                        <p className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
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
                                "group rounded-lg border bg-white p-3 text-left transition-colors hover:border-orange-300",
                                url === e.url &&
                                  "border-orange-300 bg-orange-50/40",
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
                              <p className="mt-1 text-[10px] text-muted-foreground">
                                {e.owner}
                              </p>
                              <p className="mt-3 flex items-center gap-1.5 text-[10px]">
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
                    <Card className="gap-0 shadow-none">
                      <CardContent className="p-5">
                        <div className="mb-4 flex items-center justify-between">
                          <h2 className="flex items-center gap-2 text-xs font-semibold">
                            <ActivityIcon size={14} />
                            Live activity
                          </h2>
                          {busy && (
                            <span className="flex items-center gap-1.5 text-[9px] font-medium text-emerald-700">
                              <span className="size-1.5 animate-pulse rounded-full bg-emerald-500" />
                              LIVE
                            </span>
                          )}
                        </div>
                        <div
                          className="max-h-[274px] space-y-4 overflow-auto pr-1"
                          role="log"
                          aria-label="Pipeline activity"
                          aria-live="polite"
                        >
                          {activity.length ? (
                            activity.map((a, i) => (
                              <div key={i} className="flex gap-2.5">
                                <div className="mt-0.5 shrink-0">
                                  <StageIcon status={a.status} />
                                </div>
                                <div>
                                  <p className="text-[11px] leading-5 text-slate-600">
                                    {a.message}
                                  </p>
                                  <p className="mt-1 text-[9px] text-slate-400">
                                    {a.time}
                                  </p>
                                </div>
                              </div>
                            ))
                          ) : (
                            <p className="text-xs leading-6 text-muted-foreground">
                              This is a saved result. Its evidence is preserved
                              below; live stage activity is shown during new
                              runs.
                            </p>
                          )}
                          <div ref={activityEnd} />
                        </div>
                      </CardContent>
                    </Card>
                  ) : (
                    <Card className="gap-0 border-dashed bg-transparent shadow-none">
                      <CardContent className="p-6">
                        <p className="mb-5 text-[10px] font-semibold uppercase tracking-[.15em] text-muted-foreground">
                          One connected workflow
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
                                "before:absolute before:left-[14px] before:top-9 before:h-6 before:border-l before:border-dashed before:border-slate-300",
                            )}
                          >
                            <span className="flex size-7 shrink-0 items-center justify-center rounded-lg border bg-white">
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
                    <p className="text-[10px] text-muted-foreground">
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
                          "relative min-w-0 rounded-lg border bg-white p-3",
                          states[s.id] === "running" &&
                            "border-orange-300 bg-orange-50/40",
                          ["partial", "failed", "unavailable"].includes(
                            states[s.id],
                          ) && "border-amber-200",
                        )}
                      >
                        <div className="mb-3 flex items-center justify-between">
                          <span className="mono text-[10px] text-slate-400">
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <StageIcon status={states[s.id] || "pending"} />
                        </div>
                        <p className="text-[11px] font-semibold">{s.title}</p>
                        <p className="mt-1 text-[9px] leading-4 text-muted-foreground">
                          {states[s.id]
                            ? states[s.id].replaceAll("_", " ")
                            : s.detail}
                        </p>
                      </div>
                    ))}
                  </div>
                </section>
                {analysis && <AnalysisView analysis={analysis} />}
                {scan && <ResultsView key={scan.id} scan={scan} />}
                {!hasRun && (
                  <div className="flex flex-wrap items-center gap-5 border-t pt-5 text-[10px] text-slate-400">
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
          <footer className="flex items-center justify-between px-5 py-5 text-[10px] text-slate-400 md:px-9">
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
      <span className="rounded-tl-md bg-[#ee986f]" />
      <span className="rounded-tr-md bg-[#f7c7af]" />
      <span className="rounded-bl-md bg-[#f7c7af]" />
      <span className="rounded-br-md bg-[#ee986f]" />
    </div>
  );
}
function StageIcon({ status }: { status: string }) {
  return status === "running" ? (
    <LoaderCircle size={13} className="animate-spin text-primary" />
  ) : status === "completed" ? (
    <Check size={13} className="text-emerald-600" />
  ) : ["partial", "failed", "unavailable"].includes(status) ? (
    <CircleAlert size={13} className="text-amber-600" />
  ) : status === "skipped" || status === "not_run" ? (
    <span className="text-xs leading-3 text-slate-400">-</span>
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
