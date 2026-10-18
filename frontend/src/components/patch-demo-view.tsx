import { useEffect, useRef, useState } from "react";
import { LoaderCircle, Play, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getPatchDemoStatus, streamPatchDemo } from "@/lib/api";
import type { PatchDemoStatus, PatchResult, ProgressEvent } from "@/lib/types";

export function PatchDemoView() {
  const [available, setAvailable] = useState<PatchDemoStatus | null>(null);
  const [running, setRunning] = useState(false);
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [result, setResult] = useState<PatchResult | null>(null);
  const [error, setError] = useState("");
  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    const abort = new AbortController();
    void getPatchDemoStatus(abort.signal)
      .then(setAvailable)
      .catch(() => setAvailable(null));
    return () => abort.abort();
  }, []);

  async function run() {
    if (running) return;
    const abort = new AbortController();
    controller.current = abort;
    setRunning(true);
    setError("");
    setResult(null);
    setEvents([]);
    try {
      await streamPatchDemo(
        abort.signal,
        (event) => setEvents((previous) => [...previous, event].slice(-50)),
        setResult,
      );
    } catch (cause) {
      setError(
        abort.signal.aborted
          ? "Sandbox demonstration stopped."
          : cause instanceof Error
            ? cause.message
            : "Sandbox demonstration failed.",
      );
    } finally {
      setRunning(false);
      controller.current = null;
    }
  }

  if (!available?.enabled) return null;

  return (
    <section
      aria-label="Patch Agent sandbox demonstration"
      className="rounded-lg border border-dashed border-orange-300 bg-orange-50/50 p-5"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[.16em] text-orange-700">
            Development demonstration
          </p>
          <h2 className="mt-1 text-lg font-semibold">
            Watch the Patch Agent in a disposable sandbox
          </h2>
          <p className="mt-2 max-w-2xl text-xs leading-5 text-muted-foreground">
            Runs a supplied synthetic remediation plan against a temporary local
            Git repository inside Docker. It never reads or modifies your actual
            project.
          </p>
        </div>
        <Button size="sm" disabled={running} onClick={() => void run()}>
          {running ? (
            <LoaderCircle size={14} className="animate-spin" />
          ) : (
            <Play size={14} />
          )}
          {running ? "Running sandbox demo" : "Run Patch Agent demo"}
        </Button>
        {running && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => controller.current?.abort()}
          >
            <Square size={13} /> Stop
          </Button>
        )}
      </div>
      {(events.length > 0 || result || error) && (
        <div className="mt-4 space-y-3 rounded-md border bg-white p-3 text-xs">
          <h3 className="font-semibold">Live Patch Agent activity</h3>
          <ol className="max-h-48 space-y-1 overflow-auto">
            {events.map((event, index) => (
              <li key={`${event.tool || event.stage}-${index}`}>
                <span className="mono text-muted-foreground">
                  {event.tool || event.stage}
                </span>{" "}
                {event.message}
              </li>
            ))}
          </ol>
          {error && (
            <p role="alert" className="text-amber-800">
              {error}
            </p>
          )}
          {result && (
            <div className="space-y-1 border-t pt-3">
              <p className="font-semibold">
                Demo result: {result.status.replaceAll("_", " ")}
              </p>
              <p>Modified files: {result.modified_files.join(", ") || "none"}</p>
              <p>Commands executed: {result.commands_executed.length}</p>
              <p className="text-muted-foreground">
                The temporary fixture was deleted after artifact export.
              </p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
