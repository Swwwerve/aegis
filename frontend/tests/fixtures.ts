import type { Analysis, Finding, Repository, Scan } from "../src/lib/types";
export const repository: Repository = {
  id: 7,
  owner: "adeyosemanputra",
  name: "pygoat",
  url: "https://github.com/adeyosemanputra/pygoat",
  default_branch: "main",
  created_at: "2026-10-14T00:00:00Z",
};
export const analysis: Analysis = {
  languages: { Python: 12 },
  primary_language: "Python",
  files_examined: 23,
  truncated: false,
  projects: [
    {
      root: ".",
      languages: ["Python"],
      package_managers: ["pip"],
      manifests: ["requirements.txt"],
      lockfiles: [],
      runtime_constraints: {},
      warnings: [],
      resolutions: [],
      dependencies: [
        {
          name: "urllib3",
          version: "==1.26.4",
          ecosystem: "Python",
          scope: "runtime",
          manifest: "requirements.txt",
          resolved: false,
        },
      ],
      commands: [
        {
          kind: "test",
          argv: ["python", "-m", "pytest"],
          cwd: ".",
          source: "tests/",
          confidence: "medium",
          origin: "inferred",
          reason: "Test files are present",
          requires_network: false,
        },
      ],
    },
  ],
  important_directories: [
    { path: "tests/", role: "test suite", evidence: "Python test files" },
  ],
  ci_files: [],
  documentation: ["README.md"],
  container_files: [],
  inference_status: "not_requested",
  resolution_status: "not_requested",
  summary: null,
  warnings: ["No complete transitive inventory"],
};
const finding: Finding = {
  package: "urllib3",
  installed_version: "1.26.4",
  ecosystem: "PyPI",
  advisory_id: "CVE-2023-45803",
  advisory_ids: ["GHSA-example"],
  cve: "CVE-2023-45803",
  cves: ["CVE-2023-45803"],
  summary: "Request body not stripped on redirect",
  fixed_version: "1.26.18",
  fixed_versions: ["1.26.18", "2.0.7"],
  references: [
    "https://github.com/advisories/GHSA-example",
    "javascript:alert(1)",
  ],
  manifests: ["requirements.txt"],
  scopes: ["runtime"],
  notes: [],
  cvss_score: 8.1,
  cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
  epss_probability: 0.03,
  epss: [
    {
      cve: "CVE-2023-45803",
      probability: 0.03,
      percentile: 0.8,
      date: "2026-10-14",
      source: "https://api.first.org/data/v1/epss",
    },
  ],
  kev: false,
  kev_entries: [],
  enrichment: {
    fetched_at: "2026-10-14T01:00:00Z",
    epss_status: "available",
    kev_status: "available",
  },
  advisory_evidence: [
    {
      advisory_id: "GHSA-example",
      source: "https://api.osv.dev/v1/vulns/GHSA-example",
      published: "2023-10-01T00:00:00Z",
      modified: "2024-10-01T00:00:00Z",
      ranges: [],
      affected_functions: [],
    },
  ],
  usage: {
    status: "analyzed",
    method: "python_ast_import_aliases",
    static_call_count: 2,
    import_count: 1,
    runtime_call_count: null,
    affected_function_call_count: null,
    files_scanned: 3,
    sites: [
      { path: "app.py", line: 3, symbol: "urllib3.request", kind: "call" },
    ],
    limitations: ["Dynamic calls may be missed"],
    truncated: false,
  },
  priority: {
    score: 72,
    baseline_score: 72,
    level: "high",
    method: "evidence_v1",
    components: { severity: 40.5, dependency_scope: 10 },
    explanation: ["Evidence based heuristic"],
    missing_evidence: [],
    model_status: "not_requested",
    model_reason: null,
    model_adjustment: 0,
    model_evidence_fields: [],
  },
};
export const scan: Scan = {
  id: 19,
  repository_id: 7,
  status: "partial",
  commit_sha: "abcdef0123456789abcdef0123456789abcdef0123",
  created_at: "2026-10-14T01:00:00Z",
  report: {
    status: "partial",
    vulnerabilities: [finding],
    dependencies: [
      {
        package: "urllib3",
        installed_version: "1.26.4",
        ecosystem: "PyPI",
        manifests: ["requirements.txt"],
        scopes: ["runtime"],
        version_source: "pinned",
      },
    ],
    unscanned_dependencies: [
      {
        package: "requests",
        declared_version: ">=2",
        manifest: "requirements.txt",
        reason: "No exact version",
      },
    ],
    packages_queried: 1,
    packages_completed: 1,
    advisory_records: 2,
    withdrawn_records: 0,
    warnings: ["Transitive dependencies may be absent"],
    errors: [],
    prioritization_status: "partial",
    analysis_summary: null,
    analysis_inference_status: "not_requested",
    analysis_resolution_status: "not_requested",
    scope: "Known OSV dependency advisories for identified exact versions",
    repository_analysis: analysis,
  },
};
export function events(result = scan) {
  let body = "";
  const emit = (event: string, data: unknown) => {
    body += `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  };
  for (const stage of [
    "inventory",
    "resolution",
    "interpretation",
    "advisories",
    "enrichment",
    "usage",
    "ranking",
    "saving",
  ]) {
    if (["resolution", "interpretation"].includes(stage)) {
      emit("progress", {
        stage,
        status: "skipped",
        message: `${stage} is off.`,
      });
      continue;
    }
    emit("progress", {
      stage,
      status: "running",
      message: `Running ${stage}.`,
    });
    emit("progress", {
      stage,
      status: "completed",
      message: `${stage} finished.`,
      ...(stage === "inventory" ? { analysis } : {}),
    });
  }
  emit("result", result);
  emit("end", {});
  return body;
}
