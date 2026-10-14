import { useEffect, useRef, useState } from "react";
import { LoaderCircle, Search, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { downloadJson, streamContext } from "@/lib/api";
import type { ContextPacket, ProgressEvent } from "@/lib/types";
import { StateBadge } from "./analysis-view";

export function ContextView({
  scanId,
  cveId,
}: {
  scanId: number;
  cveId: string;
}) {
  const [busy, setBusy] = useState(false);
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [packet, setPacket] = useState<ContextPacket | null>(null);
  const [error, setError] = useState("");
  const [clarification, setClarification] = useState("");
  const controller = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      controller.current?.abort();
    },
    [],
  );
  const needsInput =
    packet?.status === "partial" && !!packet.missing_context.length;

  async function investigate() {
    if (busy) return;
    const abort = new AbortController();
    controller.current = abort;
    setBusy(true);
    setError("");
    setEvents([]);
    try {
      await streamContext(
        scanId,
        cveId,
        clarification,
        abort.signal,
        (event) => setEvents((previous) => [...previous, event].slice(-100)),
        setPacket,
      );
    } catch (e) {
      setError(
        abort.signal.aborted
          ? "Investigation stopped."
          : e instanceof Error
            ? e.message
            : "Investigation could not finish.",
      );
    } finally {
      setBusy(false);
      controller.current = null;
    }
  }

  return (
    <section
      aria-label="Fix context"
      className="space-y-4 rounded-lg border p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">Fix context</h3>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            Investigate ambiguity and select the evidence needed to fix {cveId}.
          </p>
        </div>
        {packet && !busy && <StateBadge status={packet.status} />}
      </div>
      {needsInput && !busy && (
        <div className="space-y-3 rounded-md bg-amber-50 p-3 text-sm text-amber-900">
          <h4 className="font-semibold">Additional context needed</h4>
          {packet!.context_requests.length
            ? packet!.context_requests.map((request, i) => (
                <div key={i}>
                  <p>{request.question}</p>
                  <p className="mt-1 text-xs">{request.reason}</p>
                </div>
              ))
            : packet!.missing_context.map((gap, i) => <p key={i}>{gap}</p>)}
          <label
            htmlFor={`context-answer-${scanId}-${cveId}`}
            className="block text-xs font-semibold"
          >
            Missing context response
          </label>
          <textarea
            id={`context-answer-${scanId}-${cveId}`}
            value={clarification}
            onChange={(e) => setClarification(e.target.value)}
            maxLength={4000}
            className="min-h-24 w-full rounded-md border bg-white p-3 text-sm text-foreground"
            placeholder="Provide the relevant facts or describe where to find the missing evidence."
          />
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          disabled={busy || (needsInput && !clarification.trim())}
          onClick={() => void investigate()}
        >
          {busy ? (
            <LoaderCircle size={14} className="animate-spin" />
          ) : (
            <Search size={14} />
          )}
          {busy
            ? "Investigating context"
            : needsInput
              ? "Continue investigation"
              : "Investigate context"}
        </Button>
        {busy && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => controller.current?.abort()}
          >
            Stop investigation
          </Button>
        )}
        {packet && !busy && (
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              downloadJson(packet, `aegis-context-${scanId}-${cveId}.json`)
            }
          >
            <Download size={14} />
            Export context
          </Button>
        )}
      </div>
      {error && (
        <p role="alert" className="text-sm text-amber-900">
          {error}
        </p>
      )}
      {!!events.length && (
        <div
          role="log"
          aria-label="Context investigation progress"
          aria-live="polite"
          className="max-h-44 space-y-2 overflow-y-auto rounded-md bg-muted p-3 text-xs"
        >
          {events.map((event, i) => (
            <p key={i} className="break-words">
              {event.message}
            </p>
          ))}
        </div>
      )}
      {packet && !busy && (
        <div className="space-y-3">
          <p role="status" className="text-sm font-medium">
            {packet.status === "completed"
              ? "Context ready"
              : packet.status === "partial"
                ? "Context needs more evidence"
                : "Context unavailable"}{" "}
            · {packet.snippets.length} snippets selected
          </p>
          {!needsInput &&
            packet.missing_context.map((gap, i) => (
              <p key={i} className="text-xs text-muted-foreground">
                {gap}
              </p>
            ))}
          {!!packet.resolved_ambiguities.length && (
            <div className="space-y-1 text-xs text-muted-foreground">
              {packet.resolved_ambiguities.map((item, i) => (
                <p key={i}>{item}</p>
              ))}
            </div>
          )}
          {packet.snippets.map((snippet) => (
            <details key={snippet.snippet_id} className="rounded-md border p-3">
              <summary className="mono cursor-pointer break-all text-xs">
                {snippet.path}:{snippet.start}-{snippet.end}
              </summary>
              <p className="my-2 text-xs leading-5 text-muted-foreground">
                {snippet.reason}
              </p>
              <pre className="mono max-h-60 overflow-auto rounded-md bg-muted p-3 text-xs">
                <code>{snippet.content}</code>
              </pre>
            </details>
          ))}
          {!!packet.clarifications?.length && (
            <div className="space-y-2 text-xs">
              <h4 className="font-semibold">
                Operator-provided facts retained for the fix
              </h4>
              {packet.clarifications.map((fact, i) => (
                <p key={i} className="whitespace-pre-wrap break-words">
                  {fact.content}
                </p>
              ))}
            </div>
          )}
          {!!packet.diagnostics.length && (
            <details className="text-xs text-muted-foreground">
              <summary className="cursor-pointer">Retrieval notes</summary>
              {packet.diagnostics.map((note, i) => (
                <p key={i} className="mt-2 break-words">
                  {note}
                </p>
              ))}
            </details>
          )}
        </div>
      )}
    </section>
  );
}
