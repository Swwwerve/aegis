export interface Repository {
  id: number;
  url: string;
  owner: string;
  name: string;
  default_branch: string | null;
  created_at: string;
}
export interface Dependency {
  name: string;
  version: string | null;
  ecosystem: string;
  scope: string;
  manifest: string;
  resolved: boolean;
}
export interface Command {
  kind: string;
  argv: string[];
  cwd: string;
  source: string;
  confidence: string;
  origin: string;
  reason: string;
  requires_network: boolean;
}
export interface Analysis {
  execution_results?: ExecutionLog[];
  languages: Record<string, number>;
  primary_language: string | null;
  files_examined: number;
  truncated: boolean;
  projects: {
    root: string;
    languages: string[];
    package_managers: string[];
    manifests: string[];
    lockfiles: string[];
    dependencies: Dependency[];
    commands: Command[];
    warnings: string[];
    runtime_constraints: Record<string, string>;
    resolutions: {
      ecosystem: string;
      method: string;
      status: string;
      diagnostics: string[];
    }[];
  }[];
  important_directories: { path: string; role: string; evidence: string }[];
  ci_files: string[];
  documentation: string[];
  container_files: string[];
  inference_status: string;
  resolution_status: string;
  summary: string | null;
  warnings: string[];
}
export interface Finding {
  package: string;
  installed_version: string;
  ecosystem: string;
  advisory_id: string;
  advisory_ids: string[];
  cve: string | null;
  cves: string[];
  summary: string;
  fixed_version: string | null;
  fixed_versions: string[];
  references: string[];
  manifests: string[];
  scopes: string[];
  notes: string[];
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_probability: number | null;
  epss: {
    cve: string;
    probability: number;
    percentile: number;
    date: string;
    source: string;
  }[];
  kev: boolean | null;
  kev_entries: Record<string, unknown>[];
  enrichment: Record<string, string>;
  advisory_evidence: {
    advisory_id: string;
    source: string;
    published: string | null;
    modified: string | null;
    ranges: unknown[];
    affected_functions: string[];
  }[];
  usage: {
    status: string;
    method: string;
    static_call_count: number | null;
    import_count: number | null;
    runtime_call_count: number | null;
    affected_function_call_count: number | null;
    files_scanned: number;
    sites: { path: string; line: number; symbol: string; kind: string }[];
    limitations: string[];
    truncated: boolean;
  };
  priority: {
    score: number;
    baseline_score: number;
    level: string;
    method: string;
    components: Record<string, number>;
    explanation: string[];
    missing_evidence: string[];
    model_status: string;
    model_reason: string | null;
    model_adjustment: number;
    model_evidence_fields: string[];
  } | null;
}
export interface Scan {
  id: number;
  repository_id: number;
  status: string;
  commit_sha: string | null;
  created_at: string;
  report: {
    status: string;
    vulnerabilities: Finding[];
    dependencies: {
      package: string;
      installed_version: string;
      ecosystem: string;
      manifests: string[];
      scopes: string[];
      version_source: string;
    }[];
    unscanned_dependencies: {
      package: string;
      declared_version: string | null;
      reason: string;
      manifest: string;
    }[];
    packages_queried: number;
    packages_completed: number;
    advisory_records: number;
    withdrawn_records: number;
    warnings: string[];
    errors: string[];
    prioritization_status: string;
    analysis_summary: string | null;
    analysis_inference_status: string;
    analysis_resolution_status: string;
    scope: string;
    repository_analysis?: Analysis | null;
  } | null;
}
export interface ProgressEvent {
  stage: string;
  status: string;
  message: string;
  analysis?: Analysis;
  scan_id?: number;
  tool?: string;
  tool_calls?: number;
  retrieved_chars?: number;
  command_id?: string;
  argv?: string[];
  cwd?: string;
  phase?: "resolution" | "validation";
  stdout?: string;
  stderr?: string;
  exit_code?: number | null;
  truncated?: boolean;
  reason?: string;
}
export interface ExecutionLog {
  command_id: string;
  argv: string[];
  cwd: string;
  phase: "resolution" | "validation";
  status: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number | null;
  truncated?: boolean;
  reason?: string;
}
export interface ContextPacket {
  cve_id: string;
  status: "completed" | "partial" | "unavailable" | "failed";
  investigation_status:
    "not_requested" | "completed" | "needs_context" | "failed";
  snippets: {
    snippet_id: string;
    path: string;
    start: number;
    end: number;
    content: string;
    reason: string;
    sha256: string;
    truncated: boolean;
  }[];
  context_requests: { kind: string; question: string; reason: string }[];
  resolved_ambiguities: string[];
  missing_context: string[];
  diagnostics: string[];
  tool_calls: number;
  retrieved_chars: number;
  clarifications?: {
    source: string;
    content: string;
    reason: string;
    sha256: string;
  }[];
}

export interface RemediationPlan {
  cve_id: string;
  status: "ready" | "needs_context" | "unavailable" | "failed";
  summary: string;
  skills_used: string[];
  steps: {
    kind: string;
    description: string;
    paths: string[];
    evidence_ids: string[];
  }[];
  version_changes: {
    package: string;
    ecosystem: string;
    installed_version: string;
    proposed_version: string;
  }[];
  validation: {
    description: string;
    argv: string[];
    cwd: string;
    evidence_ids: string[];
  }[];
  risks: string[];
  missing_context: string[];
  affected_files?: string[];
  root_cause?: string;
  application_code_changes?: string[];
  reasoning?: string;
  confidence?: number;
  human_intervention_required?: boolean;
  source_references?: {
    evidence_id: string;
    path: string;
    sha256: string | null;
  }[];
  advisory_references?: {
    advisory_id: string;
    source: string;
    evidence_ids: string[];
  }[];
  skill_references?: { name: string; path: string; sha256: string }[];
}
export interface PatchResult {
  execution_results?: ExecutionLog[];
  remediation_id: string;
  run_id: string;
  cve_id: string;
  status: "completed" | "needs_context" | "failed" | "sandbox_error";
  modified_files: string[];
  dependency_changes: {
    package: string;
    ecosystem: string;
    from_version: string;
    to_version: string;
    files: string[];
  }[];
  artifact_location: string | null;
  commands_executed: string[][];
  errors: string[];
  unresolved_issues: string[];
  further_testing_required: boolean;
  human_intervention_required: boolean;
  plan_references: string[];
  demonstration?: boolean;
  demonstration_label?: string | null;
}
export interface PatchDemoStatus {
  enabled: boolean;
  label: string;
}
export interface Activity extends ProgressEvent {
  time: string;
}
export const stages = [
  { id: "intake", title: "Repository", detail: "Validate and clone" },
  { id: "inventory", title: "Understand", detail: "Languages & manifests" },
  {
    id: "resolution",
    title: "Resolve dependencies",
    detail: "Optional offline graph",
  },
  {
    id: "interpretation",
    title: "Interpret",
    detail: "Architecture & commands",
  },
  { id: "advisories", title: "Discover", detail: "OSV vulnerabilities" },
  { id: "enrichment", title: "Enrich", detail: "CVSS, EPSS & KEV" },
  { id: "usage", title: "Trace usage", detail: "Static call sites" },
  { id: "ranking", title: "Prioritize", detail: "Contextual risk" },
  { id: "saving", title: "Save", detail: "Evidence & history" },
];
export const examples = [
  {
    name: "NodeGoat",
    owner: "OWASP",
    language: "Node.js",
    url: "https://github.com/OWASP/NodeGoat",
    description:
      "An intentionally vulnerable application with an npm lockfile.",
    color: "#5d9779",
  },
  {
    name: "PyGoat",
    owner: "adeyosemanputra",
    language: "Python",
    url: "https://github.com/adeyosemanputra/pygoat",
    description: "A Django security learning project with Python dependencies.",
    color: "#668dcc",
  },
  {
    name: "WebGoat",
    owner: "WebGoat",
    language: "Java",
    url: "https://github.com/WebGoat/WebGoat",
    description: "A Maven application for learning application security.",
    color: "#bb8560",
  },
];
