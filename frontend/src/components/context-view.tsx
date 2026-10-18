import { useEffect, useRef, useState } from "react";
import { LoaderCircle, Search, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  downloadJson,
  streamContext,
  streamPatch,
  streamPlan,
} from "@/lib/api";
import type {
  ContextPacket,
  PatchResult,
  ProgressEvent,
  RemediationPlan,
} from "@/lib/types";
import { AgentActivity } from "./ai-elements/agent-activity";
import { ExecutionPanel } from "./ai-elements/execution-panel";
import { PlanSteps } from "./ai-elements/plan";
import { StateBadge } from "./analysis-view";

export function ContextView({
  scanId,
  cveId,
}: {
  scanId: number;
  cveId: string;
}) {
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<"investigation" | "planning" | "patch">(
    "investigation",
  );
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [packet, setPacket] = useState<ContextPacket | null>(null);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [patch, setPatch] = useState<PatchResult | null>(null);
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
    setPhase("investigation");
    setPacket(null);
    const abort = new AbortController();
    controller.current = abort;
    setBusy(true);
    setError("");
    setEvents([]);
    setPlan(null);
    setPatch(null);
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

  async function proposePlan() {
    if (busy || packet?.status !== "completed") return;
    const abort = new AbortController();
    controller.current = abort;
    setBusy(true);
    setError("");
    setPhase("planning");
    setPlan(null);
    setPatch(null);
    try {
      await streamPlan(
        scanId,
        cveId,
        clarification,
        abort.signal,
        (event) => setEvents((previous) => [...previous, event].slice(-100)),
        setPlan,
      );
    } catch (e) {
      setError(
        abort.signal.aborted
          ? "Planning stopped."
          : e instanceof Error
            ? e.message
            : "Planning failed.",
      );
    } finally {
      setBusy(false);
      controller.current = null;
    }
  }

  async function applyPatch() {
    if (busy || !packet || !plan || plan.status !== "ready") return;
    const abort = new AbortController();
    controller.current = abort;
    setBusy(true);
    setError("");
    setPatch(null);
    setPhase("patch");
    try {
      await streamPatch(
        scanId,
        cveId,
        plan,
        packet,
        abort.signal,
        (event) => setEvents((previous) => [...previous, event].slice(-100)),
        setPatch,
      );
    } catch (e) {
      setError(
        abort.signal.aborted
          ? "Patch execution stopped."
          : e instanceof Error
            ? e.message
            : "Patch execution failed.",
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
        <div className="space-y-3 rounded-md bg-amber-500/10 p-3 text-sm text-amber-300">
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
            className="min-h-24 w-full rounded-md border bg-card p-3 text-sm text-foreground"
            placeholder="Provide the relevant facts or describe where to find the missing evidence."
          />
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {packet?.status === "completed" && (
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => void proposePlan()}
          >
            Create remediation plan
          </Button>
        )}
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
            ? phase === "patch"
              ? "Applying patch & running checks"
              : phase === "planning"
                ? "Creating remediation plan"
                : "Investigating context"
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
            Stop viewing
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
        <p role="alert" className="text-sm text-amber-300">
          {error}
        </p>
      )}
      {plan && (
        <section
          aria-label="Remediation plan"
          className="space-y-3 rounded-md border p-3"
        >
          <h4 className="text-sm font-semibold">Proposed remediation plan</h4>
          <p className="text-xs text-muted-foreground">
            {phase === "patch"
              ? "The reviewed plan is shown below. See patch verification for the commands executed and their results."
              : "Changes and checks below are proposals for review. No files were changed or commands executed."}
          </p>
          <StateBadge status={plan.status} />
          <p className="text-sm">{plan.summary}</p>
          {plan.status !== "ready" && (
            <p className="rounded-md bg-amber-500/10 p-2 text-xs text-amber-300">
              The Patch Agent is unavailable for this plan until the status is
              ready. Resolve the listed context or evidence gaps, then continue
              the investigation and create a new plan.
            </p>
          )}
          <p className="text-xs">
            Skills used: {plan.skills_used.join(", ") || "None"}
          </p>
          {plan.status === "ready" && packet?.status === "completed" && (
            <Button size="sm" disabled={busy} onClick={() => void applyPatch()}>
              Apply patch in isolated sandbox
            </Button>
          )}
          {!!plan.version_changes.length && (
            <div className="space-y-2 text-xs">
              <h5 className="font-semibold">Proposed dependency changes</h5>
              {plan.version_changes.map((change, i) => (
                <p key={i} className="mono break-all">
                  {change.package}: {change.installed_version} →{" "}
                  {change.proposed_version}
                </p>
              ))}
            </div>
          )}
          <PlanSteps plan={plan} />
          {!!plan.validation.length && (
            <div className="space-y-2 text-xs">
              <h5 className="font-semibold">Proposed validation</h5>
              {plan.validation.map((check, i) => (
                <div key={i}>
                  <p>{check.description}</p>
                  {!!check.argv.length && (
                    <code className="mono block break-all">
                      {check.cwd}: {check.argv.join(" ")}
                    </code>
                  )}
                </div>
              ))}
            </div>
          )}
          {[...plan.risks, ...plan.missing_context].map((note, i) => (
            <p key={i} className="text-xs text-amber-300">
              {note}
            </p>
          ))}
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              downloadJson(plan, `aegis-plan-${scanId}-${cveId}.json`)
            }
          >
            Export plan
          </Button>
        </section>
      )}
      {patch && !busy && (
        <section
          aria-label="Patch execution"
          className="space-y-2 rounded-md border p-3"
        >
          <h4 className="text-sm font-semibold">Sandbox patch execution</h4>
          <StateBadge status={patch.status} />
          <p className="text-xs">
            Modified files: {patch.modified_files.join(", ") || "None"}
          </p>
          <p className="text-xs">
            Commands executed: {patch.commands_executed.length}
          </p>
          {patch.artifact_location && (
            <p className="mono break-all text-xs text-muted-foreground">
              Patch artifact: {patch.artifact_location}
            </p>
          )}
          {!!patch.errors.length && (
            <div className="space-y-1 text-xs text-amber-300">
              {patch.errors.map((item, i) => (
                <p key={i}>{item}</p>
              ))}
            </div>
          )}
          {!!patch.dependency_changes.length && (
            <div className="space-y-1 text-xs">
              <h5 className="font-semibold">Reported dependency changes</h5>
              {patch.dependency_changes.map((change, i) => (
                <p key={i} className="mono break-all">
                  {change.package}: {change.from_version} ? {change.to_version}
                </p>
              ))}
            </div>
          )}
          {!!patch.unresolved_issues.length && (
            <div className="space-y-1 text-xs text-amber-300">
              {patch.unresolved_issues.map((issue, i) => (
                <p key={i}>{issue}</p>
              ))}
            </div>
          )}
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              downloadJson(patch, `aegis-patch-${scanId}-${cveId}.json`)
            }
          >
            Export patch result
          </Button>
          <p className="text-xs text-muted-foreground">
            Independent testing is required; a completed sandbox run does not
            prove remediation.
          </p>
        </section>
      )}
      {!!events.length && (
        <AgentActivity
          events={events}
          running={busy}
          label="Context investigation progress"
        />
      )}
      {(phase === "patch" || !!patch?.execution_results?.length) && (
        <ExecutionPanel
          events={events}
          results={patch?.execution_results}
          running={busy}
          validation
        />
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
