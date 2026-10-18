// shadcn/ui AI Elements Terminal and Test Results patterns, backed by Docker events.
import { useMemo } from "react";
import {
  Check,
  CircleAlert,
  Container,
  Download,
  LoaderCircle,
  Terminal,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Trace,
  TraceCollapsible,
  TraceCollapsibleContent,
  TraceCollapsibleTrigger,
  TraceIcon,
  TraceLine,
  TraceTitle,
} from "@/components/ui/trace";
import { downloadJson } from "@/lib/api";
import type { ExecutionLog, ProgressEvent } from "@/lib/types";

export function ExecutionPanel({
  events,
  results = [],
  running = false,
  enabled = true,
  validation = false,
}: {
  events: ProgressEvent[];
  results?: ExecutionLog[];
  running?: boolean;
  enabled?: boolean;
  validation?: boolean;
}) {
  const commands = useMemo(() => {
    const byId = new Map<string, ExecutionLog>();
    for (const result of results) byId.set(result.command_id, result);
    for (const event of events)
      if (event.stage === "container" && event.command_id && event.argv) {
        byId.set(event.command_id, {
          ...byId.get(event.command_id),
          ...event,
          command_id: event.command_id,
          argv: event.argv,
          cwd: event.cwd || ".",
          phase: event.phase || "resolution",
        });
      }
    return [...byId.values()];
  }, [events, results]);
  const checks = commands.filter((c) => c.phase === "validation");
  const passed = checks.filter((c) => c.status === "passed").length;
  const failed = checks.filter((c) =>
    ["failed", "error", "timeout"].includes(c.status),
  ).length;
  return (
    <Card
      className="min-w-0 gap-0 overflow-hidden"
      role="region"
      aria-label={validation ? "Remediation validation" : "Docker execution"}
    >
      <CardContent className="p-4 sm:p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <Container size={17} className="text-primary" />
              {validation ? "Patch verification" : "Docker execution"}
            </h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Commands, dependency retrieval, and actual exit codes. Output
              arrives as each command finishes.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline">Isolated · offline</Badge>
            {!!commands.length && (
              <Button
                size="sm"
                variant="ghost"
                aria-label="Download execution logs"
                onClick={() => downloadJson(commands, "aegis-execution.json")}
              >
                <Download size={14} />
              </Button>
            )}
          </div>
        </div>
        <Tabs defaultValue="terminal">
          <TabsList aria-label="Execution details" className="mb-2">
            <TabsTrigger value="terminal" className="text-xs">
              Terminal {commands.length > 0 && `(${commands.length})`}
            </TabsTrigger>
            <TabsTrigger value="checks" className="text-xs">
              Validation results
            </TabsTrigger>
          </TabsList>
          <TabsContent value="terminal">
            {commands.length ? (
              <Trace className="max-h-[480px] overflow-y-auto rounded-lg border bg-[#0c0c11] p-3">
                {commands.map((command) => (
                  <TraceCollapsible key={command.command_id} defaultOpen>
                    <TraceCollapsibleTrigger className="w-full py-2">
                      <TraceLine
                        className="w-full items-start"
                        status={
                          command.status === "running" && running
                            ? "running"
                            : ["failed", "error", "timeout"].includes(
                                  command.status,
                                )
                              ? "error"
                              : undefined
                        }
                      >
                        <TraceIcon>
                          <Terminal />
                        </TraceIcon>
                        <TraceTitle className="mono whitespace-pre-wrap break-all text-xs">
                          {commandLabel(command.argv)}
                        </TraceTitle>
                        <span className="ml-auto shrink-0 text-[10px]">
                          {command.status === "running" && !running
                            ? "Interrupted"
                            : command.status}
                          {command.exit_code != null &&
                            ` · exit ${command.exit_code}`}
                        </span>
                      </TraceLine>
                    </TraceCollapsibleTrigger>
                    <TraceCollapsibleContent>
                      <p className="mono mb-2 break-all text-[10px] text-muted-foreground">
                        /workspace/repo
                        {command.cwd === "." ? "" : `/${command.cwd}`}
                      </p>
                      {commandLabel(command.argv) !==
                        command.argv.join(" ") && (
                        <details className="mb-3 text-xs">
                          <summary>Full command</summary>
                          <pre className="mono mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all text-foreground">
                            {command.argv.join(" ")}
                          </pre>
                        </details>
                      )}
                      {command.stdout && (
                        <pre
                          aria-label="Standard output"
                          className="mono max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-background p-3 text-xs leading-6 text-slate-200"
                        >
                          {cleanOutput(command.stdout)}
                        </pre>
                      )}
                      {command.stderr && (
                        <pre
                          aria-label="Standard error"
                          className="mono mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-red-500/5 p-3 text-xs leading-6 text-red-300"
                        >
                          {cleanOutput(command.stderr)}
                        </pre>
                      )}
                      {!command.stdout && !command.stderr && (
                        <p className="text-xs">
                          {command.status === "running"
                            ? running
                              ? "Container is running. Waiting for command output…"
                              : "Viewing ended before command output arrived."
                            : "Command returned no console output."}
                        </p>
                      )}
                      {command.reason && (
                        <p className="mt-2 text-xs text-amber-300">
                          {command.reason}
                        </p>
                      )}
                      {command.truncated && (
                        <p className="mt-2 text-xs text-amber-300">
                          Output truncated to the display limit.
                        </p>
                      )}
                    </TraceCollapsibleContent>
                  </TraceCollapsible>
                ))}
              </Trace>
            ) : (
              <div className="rounded-lg border border-dashed bg-background/50 p-6 text-center">
                <Container className="mx-auto mb-3 size-6 text-muted-foreground" />
                <p className="text-sm">
                  {!enabled
                    ? "Dependency resolution is off"
                    : running
                      ? "Waiting for Docker commands"
                      : "No container commands recorded"}
                </p>
                <p className="mx-auto mt-2 max-w-lg text-xs leading-5 text-muted-foreground">
                  {!enabled
                    ? "Turn on Resolve dependency graph before your next scan to inspect dependency retrieval and Docker output."
                    : "Container output will appear when dependency resolution or patch validation runs. Older scans may not contain saved logs."}
                </p>
              </div>
            )}
          </TabsContent>
          <TabsContent
            value="checks"
            className="space-y-3 rounded-lg border bg-background/50 p-4"
          >
            <div className="flex flex-wrap gap-3 text-xs">
              <span className="text-emerald-300">{passed} passed</span>
              <span className="text-red-300">{failed} failed</span>
              <span className="text-muted-foreground">
                {checks.length - passed - failed} pending or skipped
              </span>
            </div>
            {checks.length ? (
              checks.map((check) => (
                <div
                  key={check.command_id}
                  className="flex items-start gap-2 border-t pt-3 text-xs"
                >
                  {check.status === "passed" ? (
                    <Check className="size-4 shrink-0 text-emerald-300" />
                  ) : check.status === "running" && running ? (
                    <LoaderCircle className="size-4 shrink-0 animate-spin" />
                  ) : (
                    <CircleAlert className="size-4 shrink-0 text-amber-300" />
                  )}
                  <p className="mono min-w-0 break-all">
                    {check.argv.join(" ")}
                    <span className="ml-2 font-sans text-muted-foreground">
                      {check.status === "running" && !running
                        ? "interrupted"
                        : check.status}
                      {check.exit_code != null && ` · exit ${check.exit_code}`}
                    </span>
                  </p>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">
                No validation commands have run. Dependency resolution alone
                does not verify a remediation.
              </p>
            )}
            {validation && (
              <p className="border-t pt-3 text-xs leading-5 text-muted-foreground">
                These results show whether declared checks passed. Independent
                security verification is still required to confirm the
                vulnerability is fixed.
              </p>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

function cleanOutput(value: string) {
  // Render untrusted output as text; remove ANSI control sequences.
  return value.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "");
}

function commandLabel(argv: string[]) {
  return argv
    .map((arg, i) => {
      if (
        i > 0 &&
        ["-c", "-e", "--eval"].includes(argv[i - 1]) &&
        arg.length > 100
      )
        return "[inline script]";
      return arg.length > 180 ? `${arg.slice(0, 160)}…` : arg;
    })
    .join(" ");
}
