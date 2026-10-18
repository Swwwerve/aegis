// Composed from the shadcn/ui AI Elements Task and Chain of Thought patterns.
import {
  BrainCircuit,
  Check,
  CircleAlert,
  LoaderCircle,
  Wrench,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Trace,
  TraceCollapsible,
  TraceCollapsibleContent,
  TraceCollapsibleTrigger,
  TraceIcon,
  TraceLine,
  TraceTitle,
} from "@/components/ui/trace";
import type { ProgressEvent } from "@/lib/types";

export function AgentActivity({
  events,
  running,
  label = "Agent activity",
}: {
  events: ProgressEvent[];
  running: boolean;
  label?: string;
}) {
  const steps = events.filter((event) => event.stage !== "container");
  return (
    <Card className="agent-glow min-w-0 gap-0">
      <CardContent className="p-5">
        <div className="mb-4 flex items-center justify-between gap-2">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <BrainCircuit size={16} className="text-primary" />
            Agent activity
          </h2>
          <Badge
            variant="outline"
            className={
              running
                ? "border-emerald-400/20 text-emerald-300"
                : "text-muted-foreground"
            }
          >
            {running ? "Live" : "Recorded"}
          </Badge>
        </div>
        <p className="mb-4 text-xs leading-5 text-muted-foreground">
          Follow the agent’s actions, tools, and evidence as the work
          progresses.
        </p>
        <div
          role="log"
          aria-label={label}
          aria-live="polite"
          aria-relevant="additions"
          className="max-h-80 overflow-y-auto pr-1"
        >
          {steps.length ? (
            <Trace>
              {steps.map((event, index) => {
                const active =
                  running &&
                  index === steps.length - 1 &&
                  event.status === "running";
                const failed = ["failed", "error", "unavailable"].includes(
                  event.status,
                );
                return (
                  <TraceCollapsible key={index} defaultOpen={failed}>
                    <TraceCollapsibleTrigger className="py-1">
                      <TraceLine
                        status={
                          active ? "running" : failed ? "error" : undefined
                        }
                      >
                        <TraceIcon>
                          {active ? (
                            <LoaderCircle className="animate-spin text-primary" />
                          ) : failed ? (
                            <CircleAlert />
                          ) : event.tool ? (
                            <Wrench />
                          ) : (
                            <Check className="text-emerald-300" />
                          )}
                        </TraceIcon>
                        <TraceTitle className="whitespace-normal text-xs leading-5">
                          {event.message}
                        </TraceTitle>
                      </TraceLine>
                    </TraceCollapsibleTrigger>
                    <TraceCollapsibleContent>
                      <div className="space-y-1 text-xs">
                        <p>
                          Stage: {event.stage.replaceAll("_", " ")} ·{" "}
                          {event.status}
                        </p>
                        {event.tool && <p>Tool: {event.tool}</p>}
                        {event.tool_calls != null && (
                          <p>
                            {event.tool_calls} tool calls ·{" "}
                            {event.retrieved_chars ?? 0} characters retrieved
                          </p>
                        )}
                      </div>
                    </TraceCollapsibleContent>
                  </TraceCollapsible>
                );
              })}
            </Trace>
          ) : (
            <p className="text-xs leading-6 text-muted-foreground">
              Activity appears here during a new run. Saved findings and
              evidence are available below.
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
