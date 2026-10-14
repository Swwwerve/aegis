import { useMemo, useState } from "react";
import {
  ArrowUpRight,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  ChevronRight,
  Fingerprint,
  Activity,
  Sparkles,
  FileCode2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Empty, StateBadge } from "./analysis-view";
import { downloadJson, safeLink } from "@/lib/api";
import type { Finding, Scan } from "@/lib/types";
import { cn } from "@/lib/utils";
import { ContextView } from "./context-view";

const levelColors: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-100",
  high: "bg-orange-50 text-orange-700 border-orange-100",
  medium: "bg-amber-50 text-amber-800 border-amber-100",
  low: "bg-slate-100 text-slate-600 border-slate-200",
};
export function percent(value: number | null | undefined) {
  return value == null
    ? "Unknown"
    : `${(value * 100).toFixed(value === 0 ? 0 : 2)}%`;
}
export function ResultsView({ scan }: { scan: Scan }) {
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState("all");
  const [selected, setSelected] = useState<Finding | null>(null);
  const report = scan.report;
  const findings = report?.vulnerabilities || [];
  const filtered = useMemo(
    () =>
      [...findings]
        .filter(
          (f) =>
            (level === "all" || (f.priority?.level || "unscored") === level) &&
            `${f.package} ${f.advisory_id} ${f.cves.join(" ")}`
              .toLowerCase()
              .includes(search.toLowerCase()),
        )
        .sort((a, b) => (b.priority?.score || 0) - (a.priority?.score || 0)),
    [findings, search, level],
  );
  if (!report)
    return (
      <Empty text="This run has no saved report yet. Refresh history to see its latest status." />
    );
  return (
    <section className="rise-in space-y-5" aria-label="Vulnerability results">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[.15em] text-muted-foreground">
            Vulnerability intelligence
          </p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight">
            What deserves your attention
          </h2>
        </div>
        <Button
          variant="outline"
          onClick={() => downloadJson(scan, `aegis-scan-${scan.id}.json`)}
        >
          <Download size={15} />
          Export report
        </Button>
      </div>
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        {[
          {
            label: "Vulnerabilities",
            value: findings.length,
            icon: <ShieldAlert size={17} />,
            note: "Deduplicated advisory findings",
          },
          {
            label: "Critical priorities",
            value: findings.filter((f) => f.priority?.level === "critical")
              .length,
            icon: <AlertTriangle size={17} />,
            note: "Priority score of 90 or more",
          },
          {
            label: "Known exploited",
            value: findings.filter((f) => f.kev === true).length,
            icon: <Fingerprint size={17} />,
            note: "Matched in the CISA KEV catalog",
          },
          {
            label: "Packages queried",
            value: `${report.packages_completed}/${report.packages_queried}`,
            icon: <ShieldCheck size={17} />,
            note: `${report.unscanned_dependencies.length} dependencies not queryable`,
          },
        ].map((m, i) => (
          <Card className="gap-0 shadow-none" key={m.label}>
            <CardContent className="p-5">
              <p className="flex items-center justify-between text-xs text-muted-foreground">
                {m.label}
                <span
                  className={
                    i === 1 && m.value
                      ? "text-red-500"
                      : "text-muted-foreground"
                  }
                >
                  {m.icon}
                </span>
              </p>
              <p className="my-2 text-3xl font-semibold tracking-tight">
                {m.value}
              </p>
              <p className="text-[11px] leading-5 text-muted-foreground">
                {m.note}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
      <div
        className={cn(
          "flex items-start gap-3 rounded-lg border p-4",
          report.status === "completed"
            ? "border-emerald-200 bg-emerald-50/40"
            : "border-amber-200 bg-amber-50/40",
        )}
      >
        <Activity size={17} className="mt-0.5 shrink-0" />
        <div className="min-w-0 text-sm">
          <div className="flex flex-wrap items-center gap-2 font-medium">
            Scan coverage <StateBadge status={report.status} />
            <span className="ml-1 text-xs font-normal text-muted-foreground">
              Prioritization:{" "}
              {report.prioritization_status.replaceAll("_", " ")}
            </span>
          </div>
          <p className="mt-2 text-xs leading-5 text-slate-600">
            {report.status === "completed"
              ? "All identified exact versions were queried. Results cover known dependency advisories; they do not establish source-code safety."
              : "Coverage is incomplete. Available findings are retained; unresolved versions or provider errors may leave additional vulnerabilities undiscovered."}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Commit {scan.commit_sha?.slice(0, 12) || "unavailable"} · Scan #
            {scan.id} · {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>
      </div>
      <Tabs defaultValue="findings">
        <TabsList className="mb-3 h-10">
          <TabsTrigger value="findings">
            Findings{" "}
            <span className="ml-1 text-xs opacity-60">{findings.length}</span>
          </TabsTrigger>
          <TabsTrigger value="coverage">Coverage & notes</TabsTrigger>
          <TabsTrigger value="raw">Full output</TabsTrigger>
        </TabsList>
        <TabsContent value="findings">
          <Card className="gap-0 overflow-hidden shadow-none">
            <CardContent className="p-0">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b p-4">
                <div className="relative min-w-0 flex-1 sm:max-w-sm">
                  <Search className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
                  <Input
                    className="bg-muted/50 pl-9"
                    aria-label="Search findings"
                    placeholder="Search packages, CVEs, advisories..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <select
                  aria-label="Filter by priority"
                  className="h-9 rounded-md border bg-white px-3 text-xs"
                  value={level}
                  onChange={(e) => setLevel(e.target.value)}
                >
                  {["all", "critical", "high", "medium", "low", "unscored"].map(
                    (l) => (
                      <option key={l} value={l}>
                        {l === "all"
                          ? "All priorities"
                          : l[0].toUpperCase() + l.slice(1)}
                      </option>
                    ),
                  )}
                </select>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[650px] text-left text-sm">
                  <thead className="bg-muted/60 text-[11px] uppercase tracking-wide text-muted-foreground">
                    <tr>
                      {[
                        "Priority",
                        "Package / advisory",
                        "CVSS",
                        "EPSS",
                        "Fixed version",
                        "",
                      ].map((x, i) => (
                        <th key={i} className="px-5 py-3 font-medium">
                          {x}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((f) => (
                      <tr
                        key={`${f.ecosystem}:${f.package}:${f.installed_version}:${f.advisory_id}`}
                        className="border-b transition-colors last:border-0 hover:bg-muted/40"
                      >
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-2">
                            <span className="w-8 text-lg font-semibold tabular-nums">
                              {f.priority?.score.toFixed(0) ?? "--"}
                            </span>
                            <Badge
                              variant="outline"
                              className={cn(
                                "capitalize",
                                levelColors[f.priority?.level || ""],
                              )}
                            >
                              {f.priority?.level || "Unscored"}
                            </Badge>
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <button
                            className="text-left font-semibold hover:text-primary"
                            onClick={() => setSelected(f)}
                            aria-label={`Inspect ${f.package} ${f.advisory_id}`}
                          >
                            {f.package}{" "}
                            <span className="mono ml-1 text-xs font-normal text-muted-foreground">
                              {f.installed_version}
                            </span>
                          </button>
                          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                            {f.cve || f.advisory_id}
                            {f.kev === true && (
                              <span className="rounded bg-red-50 px-1.5 py-0.5 text-[10px] font-medium text-red-700">
                                KNOWN EXPLOITED
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-5 py-4 tabular-nums">
                          {f.cvss_score ?? "--"}
                        </td>
                        <td className="px-5 py-4 text-xs tabular-nums">
                          {percent(f.epss_probability)}
                        </td>
                        <td className="mono px-5 py-4 text-xs">
                          {f.fixed_version || (
                            <span className="font-sans text-muted-foreground">
                              Unconfirmed
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-4">
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={`Open ${f.advisory_id} evidence`}
                            onClick={() => setSelected(f)}
                          >
                            <ChevronRight size={16} />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {!filtered.length && (
                <Empty
                  text={
                    findings.length
                      ? "No findings match your filters."
                      : report.status === "completed"
                        ? "No known vulnerabilities were returned for the queried exact versions. Review coverage and scope before drawing conclusions."
                        : "No findings available. This incomplete scan does not establish that the repository is free of vulnerabilities."
                  }
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="coverage">
          <Card className="gap-0 shadow-none">
            <CardContent className="space-y-5 p-5">
              <div>
                <h3 className="mb-2 text-sm font-semibold">
                  What this scan covers
                </h3>
                <p className="text-sm leading-6 text-muted-foreground">
                  {report.scope}
                </p>
                <p className="mt-2 text-xs text-muted-foreground">
                  {report.advisory_records} advisory records ·{" "}
                  {report.withdrawn_records} withdrawn · model interpretation{" "}
                  {report.analysis_inference_status} · sandbox resolution{" "}
                  {report.analysis_resolution_status}
                </p>
              </div>
              {!!report.errors.length && (
                <Notes
                  title="Provider / execution errors"
                  lines={report.errors}
                />
              )}
              <Notes
                title="Coverage and evidence notes"
                lines={report.warnings}
              />
              {!!report.unscanned_dependencies.length && (
                <div>
                  <h3 className="mb-3 text-sm font-semibold">
                    Dependencies that could not be scanned
                  </h3>
                  {report.unscanned_dependencies.map((d, i) => (
                    <div key={i} className="mb-2 rounded-md border p-3 text-xs">
                      <b>{d.package}</b>{" "}
                      <span className="mono">{d.declared_version}</span>
                      <p className="mt-1 text-muted-foreground">
                        {d.reason} · {d.manifest}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="raw">
          <Card className="gap-0 shadow-none">
            <CardContent className="p-5">
              <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
                <FileCode2 size={16} />
                Original persisted scan output
              </div>
              <pre className="mono max-h-[600px] overflow-auto rounded-lg bg-[#202630] p-4 text-xs leading-6 text-slate-200">
                {JSON.stringify(scan, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      <Dialog
        open={!!selected}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent className="max-h-[88dvh] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle className="pr-7 text-xl">
              {selected?.package}
              <span className="mono ml-2 text-sm font-normal text-muted-foreground">
                {selected?.installed_version}
              </span>
            </DialogTitle>
            <DialogDescription>
              {selected?.cve || selected?.advisory_id} · {selected?.ecosystem}
            </DialogDescription>
          </DialogHeader>
          {selected && <FindingDetail finding={selected} />}
          {selected && (selected.cve || selected.cves[0]) && (
            <ContextView
              key={`${scan.id}-${selected.cve || selected.cves[0]}`}
              scanId={scan.id}
              cveId={selected.cve || selected.cves[0]}
            />
          )}
        </DialogContent>
      </Dialog>
    </section>
  );
}
function FindingDetail({ finding: f }: { finding: Finding }) {
  return (
    <div className="space-y-6">
      <p className="text-sm leading-6 text-slate-600">
        {f.summary || "No advisory summary provided."}
      </p>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ["Priority", f.priority ? `${f.priority.score} / 100` : "Unscored"],
          ["CVSS base", f.cvss_score ?? "Unknown"],
          ["EPSS", percent(f.epss_probability)],
          [
            "CISA KEV",
            f.kev == null
              ? "Unknown"
              : f.kev
                ? "Known exploited"
                : "Not in catalog",
          ],
        ].map(([k, v]) => (
          <div className="rounded-lg bg-muted p-3" key={k}>
            <p className="text-[11px] text-muted-foreground">{k}</p>
            <p className="mt-1 text-sm font-semibold">{v}</p>
          </div>
        ))}
      </div>
      {f.priority && (
        <div>
          <h3 className="mb-3 text-sm font-semibold">Why this priority?</h3>
          <div className="space-y-2">
            {Object.entries(f.priority.components).map(([k, v]) => (
              <div className="flex items-center gap-3 text-xs" key={k}>
                <span className="w-44 shrink-0 text-muted-foreground">
                  {k.replaceAll("_", " ")}
                </span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary/70"
                    style={{ width: `${Math.min(100, v * 2)}%` }}
                  />
                </div>
                <span className="w-10 text-right tabular-nums">
                  {v.toFixed(1)}
                </span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs leading-5 text-muted-foreground">
            Evidence baseline {f.priority.baseline_score}. Model adjustment{" "}
            {f.priority.model_adjustment > 0 ? "+" : ""}
            {f.priority.model_adjustment}. This ranking score is a heuristic,
            not an exploit probability.
          </p>
          <details className="mt-3 text-xs text-muted-foreground">
            <summary className="cursor-pointer">Scoring method</summary>
            {f.priority.explanation.map((x, i) => (
              <p className="mt-2 leading-5" key={i}>
                {x}
              </p>
            ))}
          </details>
          {f.priority.model_reason && (
            <div className="mt-4 rounded-lg border bg-orange-50/30 p-4">
              <p className="mb-2 flex items-center gap-2 text-xs font-semibold">
                <Sparkles size={14} />
                Model assessment <StateBadge status={f.priority.model_status} />
              </p>
              <p className="text-sm leading-6">{f.priority.model_reason}</p>
            </div>
          )}
          {!f.priority.model_reason && (
            <p className="mt-3 text-xs text-muted-foreground">
              Model assessment: {f.priority.model_status.replaceAll("_", " ")}
            </p>
          )}
          {!!f.priority.missing_evidence.length && (
            <p className="mt-3 text-xs leading-5 text-amber-800">
              Missing evidence: {f.priority.missing_evidence.join(" · ")}
            </p>
          )}
        </div>
      )}
      <div>
        <h3 className="mb-3 text-sm font-semibold">Package usage evidence</h3>
        <div className="grid grid-cols-3 gap-2">
          {[
            ["Static call sites", f.usage.static_call_count],
            ["Imports", f.usage.import_count],
            ["Runtime calls", f.usage.runtime_call_count],
          ].map(([label, value]) => (
            <div className="rounded-lg border p-3" key={label}>
              <p className="text-[11px] text-muted-foreground">{label}</p>
              <p className="mt-1 text-lg font-semibold">{value ?? "Unknown"}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-xs leading-5 text-muted-foreground">
          {f.usage.method.replaceAll("_", " ")} ·{" "}
          {f.usage.status.replaceAll("_", " ")} · {f.usage.files_scanned} files
          inspected. Package call sites do not establish vulnerable-function
          execution or runtime frequency.
        </p>
        {f.usage.affected_function_call_count != null && (
          <p className="mt-2 text-xs">
            Exact advisory-symbol matches:{" "}
            {f.usage.affected_function_call_count}
          </p>
        )}
        {!!f.usage.sites.length && (
          <div className="mono mt-3 max-h-40 space-y-2 overflow-auto rounded-lg bg-muted p-3 text-[11px]">
            {f.usage.sites.map((s, i) => (
              <p key={i} className="break-all">
                {s.path}:{s.line}{" "}
                <span className="text-muted-foreground">
                  {s.kind} → {s.symbol}
                </span>
              </p>
            ))}
          </div>
        )}
        <details className="mt-3 text-xs text-muted-foreground">
          <summary className="cursor-pointer">Usage limitations</summary>
          {f.usage.limitations.map((l, i) => (
            <p key={i} className="mt-2 leading-5">
              {l}
            </p>
          ))}
        </details>
      </div>
      <div className="rounded-lg border p-4">
        <h3 className="mb-2 text-sm font-semibold">Remediation evidence</h3>
        <p className="text-sm">
          Confirmed fixed release:{" "}
          <span className="mono font-semibold">
            {f.fixed_version || "Unconfirmed"}
          </span>
        </p>
        {!!f.fixed_versions.length && (
          <p className="mt-2 text-xs text-muted-foreground">
            Reported fix boundaries: {f.fixed_versions.join(", ")}
          </p>
        )}
        <p className="mt-2 text-xs leading-5 text-muted-foreground">
          A release boundary addresses this advisory. Assess other findings and
          compatibility before selecting an upgrade.
        </p>
        {f.notes.map((n, i) => (
          <p key={i} className="mt-2 text-xs leading-5 text-muted-foreground">
            {n}
          </p>
        ))}
      </div>
      <div>
        <h3 className="mb-3 text-sm font-semibold">
          Advisory & feed provenance
        </h3>
        {f.advisory_evidence.map((e) => (
          <div key={e.advisory_id} className="mb-2 rounded-lg border p-3">
            <a
              className="flex items-center gap-2 text-xs font-semibold text-primary hover:underline"
              href={safeLink(e.source)}
              target="_blank"
              rel="noreferrer"
            >
              {e.advisory_id}
              <ArrowUpRight size={13} />
            </a>
            <p className="mt-2 text-[11px] text-muted-foreground">
              Published{" "}
              {e.published
                ? new Date(e.published).toLocaleDateString()
                : "unknown"}{" "}
              · Modified{" "}
              {e.modified
                ? new Date(e.modified).toLocaleDateString()
                : "unknown"}
            </p>
            <details className="mt-2 text-xs">
              <summary className="cursor-pointer text-muted-foreground">
                Affected ranges
              </summary>
              <pre className="mono mt-2 overflow-auto text-[11px]">
                {JSON.stringify(e.ranges, null, 2)}
              </pre>
            </details>
          </div>
        ))}
        {f.epss.map((e) => (
          <p className="mt-2 text-xs text-muted-foreground" key={e.cve}>
            FIRST EPSS · {e.cve} · {e.date} · probability{" "}
            {percent(e.probability)} · percentile {percent(e.percentile)}
          </p>
        ))}
        {f.cvss_vector && (
          <p className="mono mt-3 break-all text-[11px] text-muted-foreground">
            {f.cvss_vector}
          </p>
        )}
        <p className="mt-3 text-xs text-muted-foreground">
          Feed snapshot: {f.enrichment.fetched_at || "Not available"}
        </p>
        <div className="mt-2 flex flex-wrap gap-2">
          {Object.entries(f.enrichment)
            .filter(([k]) => k.endsWith("status"))
            .map(([k, v]) => (
              <Badge key={k} variant="secondary">
                {k.replaceAll("_", " ")}: {v}
              </Badge>
            ))}
        </div>
        {f.kev_entries.map((e, i) => (
          <div key={i} className="mt-3 rounded-lg bg-red-50/50 p-3 text-xs">
            <p className="font-medium">CISA KEV · {String(e.cveID)}</p>
            <p className="mt-1">
              Required action: {String(e.requiredAction || "Unknown")}
            </p>
            <p className="mt-1 text-muted-foreground">
              Catalog added {String(e.dateAdded)} · Catalog due date{" "}
              {String(e.dueDate)} (not an application-specific deadline)
            </p>
          </div>
        ))}
        <div className="mt-4 space-y-2">
          {f.references
            .filter((x) => safeLink(x))
            .map((r, i) => (
              <a
                key={i}
                className="flex items-center gap-1.5 break-all text-xs text-primary hover:underline"
                href={safeLink(r)}
                target="_blank"
                rel="noreferrer"
              >
                <ArrowUpRight size={13} className="shrink-0" />
                {r}
              </a>
            ))}
        </div>
      </div>
    </div>
  );
}
function Notes({ title, lines }: { title: string; lines: string[] }) {
  return (
    <div>
      <h3 className="mb-3 text-sm font-semibold">{title}</h3>
      {lines.length ? (
        <ul className="space-y-2">
          {lines.map((line, i) => (
            <li
              key={i}
              className="rounded-md bg-amber-50/40 p-3 text-xs leading-5 text-amber-900"
            >
              {line}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">No additional notes.</p>
      )}
    </div>
  );
}
