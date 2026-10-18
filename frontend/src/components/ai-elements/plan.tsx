// shadcn/ui AI Elements Plan pattern: an expandable plan and evidence-backed rationale.
import { Circle, FileText, Route } from "lucide-react";
import {
  Trace,
  TraceCollapsible,
  TraceCollapsibleContent,
  TraceCollapsibleTrigger,
  TraceIcon,
  TraceLine,
  TraceTitle,
} from "@/components/ui/trace";
import type { RemediationPlan } from "@/lib/types";

export function PlanSteps({ plan }: { plan: RemediationPlan }) {
  return (
    <Trace>
      <TraceCollapsible defaultOpen>
        <TraceCollapsibleTrigger>
          <TraceLine>
            <TraceIcon>
              <Route />
            </TraceIcon>
            <TraceTitle>
              Remediation plan · {plan.steps.length} proposed steps
            </TraceTitle>
          </TraceLine>
        </TraceCollapsibleTrigger>
        <TraceCollapsibleContent>
          <Trace>
            {plan.steps.map((step, i) => (
              <TraceCollapsible key={i} defaultOpen>
                <TraceCollapsibleTrigger>
                  <TraceLine>
                    <TraceIcon>
                      <Circle />
                    </TraceIcon>
                    <TraceTitle className="whitespace-normal text-xs">
                      {step.description}
                    </TraceTitle>
                  </TraceLine>
                </TraceCollapsibleTrigger>
                <TraceCollapsibleContent>
                  <p className="mono break-all text-xs">
                    {step.paths.join(", ") || "No file edits"}
                  </p>
                  <p className="mt-1 text-xs">
                    Evidence: {step.evidence_ids.join(", ") || "Not supplied"}
                  </p>
                </TraceCollapsibleContent>
              </TraceCollapsible>
            ))}
          </Trace>
        </TraceCollapsibleContent>
      </TraceCollapsible>
      {(plan.reasoning || plan.root_cause) && (
        <TraceCollapsible defaultOpen>
          <TraceCollapsibleTrigger>
            <TraceLine>
              <TraceIcon>
                <FileText />
              </TraceIcon>
              <TraceTitle>Why this plan</TraceTitle>
            </TraceLine>
          </TraceCollapsibleTrigger>
          <TraceCollapsibleContent>
            <div className="space-y-2 text-xs leading-6">
              {plan.root_cause && <p>{plan.root_cause}</p>}
              {plan.reasoning && (
                <p className="whitespace-pre-wrap">{plan.reasoning}</p>
              )}
              {plan.confidence != null && (
                <p>Agent confidence: {Math.round(plan.confidence * 100)}%</p>
              )}
            </div>
          </TraceCollapsibleContent>
        </TraceCollapsible>
      )}
    </Trace>
  );
}
