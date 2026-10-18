import {
  Code2,
  FolderTree,
  Layers3,
  Terminal,
  FileCode2,
  Sparkles,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { Analysis } from "@/lib/types";
import { cn } from "@/lib/utils";

export function StateBadge({ status }: { status: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded-md border-transparent font-medium capitalize",
        status === "completed"
          ? "bg-emerald-50 text-emerald-700"
          : ["failed", "unavailable", "partial"].includes(status)
            ? "bg-amber-50 text-amber-800"
            : "bg-slate-100 text-slate-600",
      )}
    >
      {status.replaceAll("_", " ")}
    </Badge>
  );
}
export function AnalysisView({ analysis }: { analysis: Analysis }) {
  const managers = [
    ...new Set(analysis.projects.flatMap((p) => p.package_managers)),
  ];
  const dependencies = analysis.projects.flatMap((p) => p.dependencies);
  const commands = analysis.projects.flatMap((p) => p.commands);
  return (
    <section className="rise-in space-y-5" aria-label="Repository analysis">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[.15em] text-muted-foreground">
            Repository intelligence
          </p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight">
            The shape of your code
          </h2>
        </div>
        <Badge variant="outline">
          <Layers3 className="mr-1 size-3" />
          {analysis.projects.length} projects
        </Badge>
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <Fact
          icon={<Code2 size={17} />}
          label="Languages"
          value={Object.keys(analysis.languages).join(" / ") || "Not detected"}
          sub={`${analysis.files_examined.toLocaleString()} files examined${analysis.truncated ? " · inventory truncated" : ""}`}
        />
        <Fact
          icon={<Layers3 size={17} />}
          label="Package managers"
          value={managers.join(" / ") || "Not detected"}
          sub={`${analysis.projects.flatMap((p) => p.manifests).length} manifests found`}
        />
        <Fact
          icon={<FileCode2 size={17} />}
          label="Declared dependencies"
          value={dependencies.length.toLocaleString()}
          sub="Versions and scope from manifests / locks"
        />
      </div>
      {analysis.summary && (
        <Card className="gap-0 border shadow-none">
          <CardContent className="flex gap-3 p-5">
            <Sparkles className="mt-1 size-5 shrink-0 text-primary" />
            <div>
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
                Architecture insight{" "}
                <StateBadge status={analysis.inference_status} />
              </div>
              <p className="whitespace-pre-wrap text-sm leading-7 text-slate-600">
                {analysis.summary}
              </p>
            </div>
          </CardContent>
        </Card>
      )}
      <Tabs defaultValue="projects">
        <TabsList className="mb-3 h-10 bg-[#ebedf1]">
          <TabsTrigger value="projects">Projects</TabsTrigger>
          <TabsTrigger value="commands">
            Build & test{" "}
            <span className="ml-1 text-xs opacity-60">{commands.length}</span>
          </TabsTrigger>
          <TabsTrigger value="structure">Structure</TabsTrigger>
          <TabsTrigger value="dependencies">Dependencies</TabsTrigger>
        </TabsList>
        <TabsContent value="projects">
          <div className="grid gap-4 lg:grid-cols-2">
            {analysis.projects.map((project) => (
              <Card key={project.root} className="gap-0 shadow-none">
                <CardContent className="p-5">
                  <div className="mb-4 flex items-center justify-between">
                    <span className="flex items-center gap-2 font-semibold">
                      <FolderTree size={16} className="text-primary" />
                      <span className="mono text-sm">
                        {project.root === "."
                          ? "Repository root"
                          : project.root}
                      </span>
                    </span>
                    <div className="flex gap-1">
                      {project.languages.map((l) => (
                        <Badge variant="secondary" key={l}>
                          {l}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-2">
                    {[
                      ...new Set([...project.manifests, ...project.lockfiles]),
                    ].map((m) => (
                      <div
                        key={m}
                        className="flex gap-2 rounded-md bg-muted px-3 py-2 text-xs"
                      >
                        <FileCode2
                          size={14}
                          className="shrink-0 text-muted-foreground"
                        />
                        <span className="mono break-all">{m}</span>
                      </div>
                    ))}
                  </div>
                  {Object.entries(project.runtime_constraints).map(([k, v]) => (
                    <p key={k} className="mt-3 text-xs text-muted-foreground">
                      {k}: <span className="mono">{v}</span>
                    </p>
                  ))}
                  {project.resolutions.map((r, i) => (
                    <details
                      className="mt-3 rounded-md border p-3 text-xs"
                      key={i}
                    >
                      <summary className="cursor-pointer">
                        {r.ecosystem} dependency graph · {r.status}
                      </summary>
                      <div className="mt-2 text-muted-foreground">
                        {r.method}
                        {r.diagnostics.map((d, j) => (
                          <p className="mt-2 whitespace-pre-wrap" key={j}>
                            {d}
                          </p>
                        ))}
                      </div>
                    </details>
                  ))}
                  {project.warnings.map((w, i) => (
                    <p
                      className="mt-3 text-xs leading-5 text-amber-800"
                      key={i}
                    >
                      {w}
                    </p>
                  ))}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
        <TabsContent value="commands">
          <Card className="gap-0 shadow-none">
            <CardContent className="p-5">
              <div className="mb-4 flex items-center gap-2 text-sm text-muted-foreground">
                <Terminal size={16} />
                Proposed commands from manifests and analysis. These have not
                been run.
              </div>
              {commands.length ? (
                <div className="space-y-3">
                  {commands.map((command, i) => (
                    <div key={i} className="rounded-lg border p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <Badge variant="secondary" className="capitalize">
                          {command.kind}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {command.origin} · {command.confidence} confidence
                        </span>
                      </div>
                      <pre className="mono my-3 overflow-x-auto rounded-md bg-[#232933] p-3 text-xs text-slate-100">
                        {command.argv.join(" ")}
                      </pre>
                      <p className="text-xs text-muted-foreground">
                        Directory: {command.cwd} · Evidence: {command.source}
                      </p>
                      <p className="mt-2 text-sm text-slate-600">
                        {command.reason}
                      </p>
                      {command.requires_network && (
                        <p className="mt-2 text-xs text-amber-800">
                          Requires network access
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <Empty text="No build or test commands could be established from the supplied evidence." />
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="structure">
          <Card className="gap-0 shadow-none">
            <CardContent className="p-5">
              {analysis.important_directories.length ? (
                analysis.important_directories.map((d) => (
                  <div
                    className="flex gap-3 border-b py-4 last:border-0"
                    key={d.path}
                  >
                    <FolderTree
                      size={17}
                      className="mt-1 shrink-0 text-primary"
                    />
                    <div>
                      <p className="mono text-sm font-semibold">{d.path}</p>
                      <p className="mt-1 text-sm text-slate-600">{d.role}</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {d.evidence}
                      </p>
                    </div>
                  </div>
                ))
              ) : (
                <Empty text="No important directories identified." />
              )}
              <div className="mt-4 grid gap-4 sm:grid-cols-3">
                {[
                  ["CI workflows", analysis.ci_files],
                  ["Documentation", analysis.documentation],
                  ["Containers", analysis.container_files],
                ].map(([label, files]) => (
                  <div key={label as string}>
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      {label as string}
                    </h3>
                    {(files as string[]).length ? (
                      (files as string[]).map((file) => (
                        <p key={file} className="mono mb-2 break-all text-xs">
                          {file}
                        </p>
                      ))
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        None detected
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="dependencies">
          <Card className="gap-0 overflow-hidden shadow-none">
            <CardContent className="p-0">
              <div className="max-h-[420px] overflow-auto">
                <table className="w-full text-left text-sm">
                  <thead className="sticky top-0 bg-muted text-xs text-muted-foreground">
                    <tr>
                      {["Package", "Version", "Scope", "Evidence"].map((x) => (
                        <th key={x} className="px-5 py-3 font-medium">
                          {x}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {dependencies.map((d, i) => (
                      <tr key={i} className="border-b last:border-0">
                        <td className="px-5 py-3 font-medium">
                          {d.name}
                          <span className="ml-2 text-xs text-muted-foreground">
                            {d.ecosystem}
                          </span>
                        </td>
                        <td className="mono px-5 py-3 text-xs">
                          {d.version || "Unknown"}
                        </td>
                        <td className="px-5 py-3 text-xs">{d.scope}</td>
                        <td className="mono px-5 py-3 text-xs text-muted-foreground">
                          {d.manifest}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!dependencies.length && (
                  <Empty text="No dependency declarations detected." />
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      {!!analysis.warnings.length && (
        <details className="rounded-lg border border-amber-200 bg-amber-50/40 p-4 text-sm">
          <summary className="cursor-pointer font-medium text-amber-900">
            Inventory notes ({analysis.warnings.length})
          </summary>
          <ul className="mt-3 space-y-2 text-xs leading-5 text-amber-900">
            {analysis.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
function Fact({
  icon,
  label,
  value,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
}) {
  return (
    <Card className="gap-0 shadow-none">
      <CardContent className="p-5">
        <p className="flex items-center justify-between text-xs font-medium text-muted-foreground">
          {label}
          {icon}
        </p>
        <p className="mt-3 text-lg font-semibold tracking-tight">{value}</p>
        <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
      </CardContent>
    </Card>
  );
}
export function Empty({ text }: { text: string }) {
  return (
    <div className="p-6 text-center text-sm leading-6 text-muted-foreground">
      {text}
    </div>
  );
}
