import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { analysis, repository, scan, events } from "./fixtures";

async function mock(
  page: Page,
  { conflict = false, interrupt = false, failed = false } = {},
) {
  let registered = false,
    saved = false,
    registrations = 0;
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = (data: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(data),
      });
    if (path === "/api/repositories" && route.request().method() === "GET")
      return json(registered ? [repository] : []);
    if (path === "/api/repositories") {
      registrations++;
      registered = true;
      return json(
        conflict ? { detail: "Repository is already registered." } : repository,
        conflict ? 409 : 201,
      );
    }
    if (path === "/api/scans/stream") {
      saved = !interrupt;
      const result = failed
        ? {
            ...scan,
            status: "failed",
            report: {
              ...scan.report!,
              status: "failed",
              vulnerabilities: [],
              errors: ["OSV scan deadline exceeded"],
            },
          }
        : scan;
      return route.fulfill({
        contentType: "text/event-stream",
        body: interrupt
          ? 'event: progress\ndata: {"stage":"inventory","status":"running","message":"Reading inventory"}\n\n'
          : events(result),
      });
    }
    if (path === "/api/scans") return json(saved ? [scan] : []);
    return json({ detail: "Not found" }, 404);
  });
  return { registrations: () => registrations };
}
async function start(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: /PyGoat/ }).click();
  await page
    .getByRole("switch", { name: "Model-assisted intelligence" })
    .click();
  await page
    .getByRole("button", { name: "Analyze repository", exact: true })
    .click();
}
async function navigate(page: Page, label: string) {
  if (await page.getByRole("button", { name: "Open navigation" }).isVisible())
    await page.getByRole("button", { name: "Open navigation" }).click();
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("button", { name: label })
    .click();
}
test("repository to evidence to saved history, with usable details and filters", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const backend = await mock(page);
  await start(page);
  await expect(
    page.getByRole("heading", { name: "What deserves your attention" }),
  ).toBeVisible();
  await expect(page.getByRole("log")).toContainText("Running enrichment");
  await page
    .getByRole("button", { name: "Inspect urllib3 CVE-2023-45803" })
    .click();
  await expect(page.getByRole("dialog")).toContainText("Runtime calls");
  await expect(page.getByRole("dialog")).toContainText("Unknown");
  await expect(page.getByRole("dialog")).toContainText("app.py:3");
  await expect(
    page.getByRole("dialog").locator('a[href^="javascript:"]'),
  ).toHaveCount(0);
  await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();
  await page
    .getByRole("textbox", { name: "Search findings" })
    .fill("nonexistent");
  await expect(page.getByText("No findings match your filters.")).toBeVisible();
  await page.getByRole("textbox", { name: "Search findings" }).fill("");
  await page.getByRole("tab", { name: "Coverage & notes" }).click();
  await expect(
    page.getByText("No exact version", { exact: false }),
  ).toBeVisible();
  await page.getByRole("tab", { name: /Build & test/ }).click();
  await expect(page.getByText("python -m pytest")).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export report" }).click();
  expect((await download).suggestedFilename()).toBe("aegis-scan-19.json");
  await navigate(page, "Scan history");
  await page.getByRole("button", { name: /Scan #19/ }).click();
  await expect(
    page.getByRole("heading", { name: "The shape of your code" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "What deserves your attention" }),
  ).toBeVisible();
  expect(errors).toEqual([]);
  await page.evaluate(async () => {
    await Promise.all(
      document.getAnimations().map((animation) => animation.finished),
    );
  });
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
  expect(backend.registrations()).toBe(1);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});
test("duplicate registration recovers and reuses the saved clone", async ({
  page,
}) => {
  const backend = await mock(page, { conflict: true });
  await start(page);
  await expect(
    page.getByRole("heading", { name: "What deserves your attention" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Analyze repository", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "What deserves your attention" }),
  ).toBeVisible();
  expect(backend.registrations()).toBe(1);
});
test("saved scans become usable without waiting for a history refresh", async ({
  page,
}) => {
  await mock(page);
  let historyRequests = 0;
  let blockHistory = false;
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/scans?*", async (route) => {
    historyRequests++;
    if (blockHistory) await pending;
    await route.fulfill({ contentType: "application/json", body: "[]" });
  });
  try {
    await page.goto("/");
    await expect(
      page.getByText("Backend connected", { exact: true }),
    ).toBeAttached();
    const initialRequests = historyRequests;
    blockHistory = true;
    await page.getByRole("button", { name: /PyGoat/ }).click();
    await page
      .getByRole("switch", { name: "Model-assisted intelligence" })
      .click();
    await page
      .getByRole("button", { name: "Analyze repository", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "What deserves your attention" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Analyze repository", exact: true }),
    ).toBeEnabled();
    await navigate(page, "Scan history");
    await expect(page.getByRole("button", { name: /Scan #19/ })).toBeEnabled();
    expect(historyRequests).toBe(initialRequests);
  } finally {
    release();
  }
});

test("interrupted stream leaves an honest error instead of a clean result", async ({
  page,
}) => {
  await mock(page, { interrupt: true });
  await start(page);
  await expect(page.getByRole("alert")).toContainText(
    "connection ended before results",
  );
  await expect(
    page.getByRole("heading", { name: "What deserves your attention" }),
  ).toHaveCount(0);
});
test("failed scans show coverage and provider errors", async ({ page }) => {
  await mock(page, { failed: true });
  await start(page);
  await expect(page.getByRole("alert")).toContainText("scan failed");
  await page.getByRole("tab", { name: "Coverage & notes" }).click();
  await expect(page.getByText("OSV scan deadline exceeded")).toBeVisible();
});

test("context investigation shows live evidence and supports missing-context answers", async ({
  page,
}) => {
  await mock(page);
  const requests: { scan_id: number; cve_id: string; clarification: string }[] =
    [];
  await page.route("**/api/remediation/context/stream", async (route) => {
    const request = route.request().postDataJSON();
    requests.push(request);
    const needsAnswer = !request.clarification;
    const packet = {
      cve_id: "CVE-2023-45803",
      status: needsAnswer ? "partial" : "completed",
      investigation_status: needsAnswer ? "needs_context" : "completed",
      missing_context: needsAnswer
        ? ["Which caller is exposed in production?"]
        : [],
      context_requests: needsAnswer
        ? [
            {
              kind: "operator",
              question: "Which caller is exposed in production?",
              reason: "Selects the regression test boundary",
            },
          ]
        : [],
      snippets: [
        {
          snippet_id: "selected",
          path: "app.py",
          start: 3,
          end: 4,
          content: "urllib3.request('GET', url)",
          reason: "Affected request caller",
          sha256: "fixture",
          truncated: false,
        },
      ],
      resolved_ambiguities: needsAnswer
        ? []
        : ["Confirmed the production caller at app.py:3"],
      diagnostics: [],
      tool_calls: 9,
      retrieved_chars: 1500,
      clarifications: needsAnswer
        ? []
        : [
            {
              source: "operator",
              content: request.clarification,
              reason: "Identifies the production caller",
              sha256: "fixture",
            },
          ],
    };
    await route.fulfill({
      contentType: "text/event-stream",
      body:
        'event: progress\ndata: {"stage":"context_investigation","status":"running","message":"Checking ambiguous callers"}\n\n' +
        `event: result\ndata: ${JSON.stringify(packet)}\n\n`,
    });
  });
  await start(page);
  await page
    .getByRole("button", { name: "Inspect urllib3 CVE-2023-45803" })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByRole("button", { name: "Investigate context", exact: true })
    .click();
  await expect(
    dialog.getByRole("log", { name: "Context investigation progress" }),
  ).toContainText("Checking ambiguous callers");
  await expect(
    dialog.getByText("Which caller is exposed in production?", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Continue investigation" }),
  ).toBeDisabled();
  await dialog
    .getByRole("textbox", { name: "Missing context response" })
    .fill("Client handles production requests");
  await dialog.getByRole("button", { name: "Continue investigation" }).click();
  await expect(dialog.getByRole("status")).toContainText("Context ready");
  await dialog.getByText("app.py:3-4", { exact: true }).click();
  await expect(
    dialog.getByText("Affected request caller", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByText("Client handles production requests", { exact: true }),
  ).toBeVisible();
  expect(requests).toEqual([
    { scan_id: 19, cve_id: "CVE-2023-45803", clarification: "" },
    {
      scan_id: 19,
      cve_id: "CVE-2023-45803",
      clarification: "Client handles production requests",
    },
  ]);
  const download = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Export context" }).click();
  expect((await download).suggestedFilename()).toBe(
    "aegis-context-19-CVE-2023-45803.json",
  );
  const accessibility = await new AxeBuilder({ page })
    .include('[role="dialog"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
});

test("context provider failures leave usable finding details and a retry", async ({
  page,
}) => {
  await mock(page);
  await page.route("**/api/remediation/context/stream", (route) =>
    route.fulfill({
      contentType: "text/event-stream",
      body: 'event: error\ndata: {"message":"Context investigation could not finish."}\n\n',
    }),
  );
  await start(page);
  await page
    .getByRole("button", { name: "Inspect urllib3 CVE-2023-45803" })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByRole("button", { name: "Investigate context", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText("could not finish");
  await expect(
    dialog.getByRole("button", { name: "Investigate context", exact: true }),
  ).toBeEnabled();
  await expect(
    dialog.getByText("Package usage evidence", { exact: true }),
  ).toBeVisible();
});

test("skill-guided remediation displays a proposal without an execution control", async ({
  page,
}) => {
  await mock(page);
  await page.route("**/api/remediation/context/stream", (route) =>
    route.fulfill({
      contentType: "text/event-stream",
      body: 'event: result\ndata: {"cve_id":"CVE-2023-45803","status":"completed","investigation_status":"completed","snippets":[],"context_requests":[],"resolved_ambiguities":[],"missing_context":[],"diagnostics":[],"tool_calls":4,"retrieved_chars":800}\n\n',
    }),
  );
  await page.route("**/api/remediation/plan/stream", (route) => {
    expect(route.request().postDataJSON().scan_id).toBe(19);
    const plan = {
      cve_id: "CVE-2023-45803",
      status: "ready",
      summary: "Propose upgrading the affected dependency",
      skills_used: ["python-remediation"],
      steps: [
        {
          kind: "dependency",
          description: "Propose updating the owning dependency pin",
          paths: ["requirements.txt"],
          evidence_ids: ["pin"],
        },
      ],
      version_changes: [],
      validation: [
        {
          description: "Propose running the existing regression suite",
          argv: ["python", "-m", "pytest"],
          cwd: ".",
          evidence_ids: ["test"],
        },
      ],
      risks: ["Check interpreter compatibility before implementation"],
      missing_context: [],
    };
    return route.fulfill({
      contentType: "text/event-stream",
      body:
        'event: progress\ndata: {"stage":"remediation_skills","status":"running","message":"Loaded python-remediation for the remediation plan."}\n\n' +
        `event: result\ndata: ${JSON.stringify(plan)}\n\n`,
    });
  });
  await start(page);
  await page
    .getByRole("button", { name: "Inspect urllib3 CVE-2023-45803" })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByRole("button", { name: "Investigate context", exact: true })
    .click();
  await dialog.getByRole("button", { name: "Create remediation plan" }).click();
  await expect(
    dialog.getByRole("heading", { name: "Proposed remediation plan" }),
  ).toBeVisible();
  await expect(
    dialog.getByText("Skills used: python-remediation", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByText(
      "Changes and checks below are proposals for review. No files were changed or commands executed.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: /Execute|Apply fix|Run checks/ }),
  ).toHaveCount(0);
  const download = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Export plan" }).click();
  expect((await download).suggestedFilename()).toBe(
    "aegis-plan-19-CVE-2023-45803.json",
  );
});
test("offline status, URL validation and responsive empty state", async ({
  page,
}) => {
  await page.route("**/api/**", (route) => route.abort("connectionrefused"));
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("Could not connect");
  await page
    .getByRole("textbox", { name: "Repository URL" })
    .fill("https://gitlab.com/a/b");
  await page
    .getByRole("button", { name: "Analyze repository", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("public GitHub");
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
  await page.screenshot({
    path: `test-results/landing-${test.info().project.name}.png`,
    fullPage: true,
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});

test("saved Docker output stays reviewable and untrusted output is plain text", async ({
  page,
}) => {
  await mock(page);
  const output = {
    command_id: "resolution-1",
    argv: ["npm", "ls", "--all"],
    cwd: ".",
    phase: "resolution",
    status: "passed",
    exit_code: 0,
    stdout: "urllib3@1.26.4\n<script>window.injected=true</script>",
    stderr: "",
    truncated: true,
  };
  const saved = {
    ...scan,
    report: {
      ...scan.report!,
      repository_analysis: { ...analysis, execution_results: [output] },
    },
  };
  await page.route("**/api/scans/stream", (route) =>
    route.fulfill({ contentType: "text/event-stream", body: events(saved) }),
  );
  await start(page);
  const terminal = page.getByRole("region", { name: "Docker execution" });
  await expect(terminal.getByLabel("Standard output")).toContainText(
    "urllib3@1.26.4",
  );
  await expect(terminal.getByLabel("Standard output")).toContainText(
    "<script>",
  );
  expect(
    await page.evaluate(
      () => (window as unknown as { injected?: boolean }).injected,
    ),
  ).toBeUndefined();
  await expect(terminal).toContainText("exit 0");
  await expect(terminal).toContainText("Output truncated");
  const download = page.waitForEvent("download");
  await terminal
    .getByRole("button", { name: "Download execution logs" })
    .click();
  expect((await download).suggestedFilename()).toBe("aegis-execution.json");
  await navigate(page, "Scan history");
  await page.getByRole("button", { name: /Scan #19/ }).click();
  await expect(page.getByLabel("Standard output")).toContainText(
    "urllib3@1.26.4",
  );
  expect(await page.locator("aside").count()).toBe(0);
  expect(
    (await page
      .getByRole("navigation", { name: "Main navigation" })
      .boundingBox())!.y,
  ).toBeLessThan(130);
});

test("patch flow shows plan rationale, Docker stderr and failed validation", async ({
  page,
}) => {
  await mock(page);
  const frame = (event: string, data: unknown) =>
    `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  const packet = {
    cve_id: "CVE-2023-45803",
    status: "completed",
    investigation_status: "completed",
    snippets: [],
    context_requests: [],
    resolved_ambiguities: [],
    missing_context: [],
    diagnostics: [],
    tool_calls: 1,
    retrieved_chars: 80,
  };
  const plan = {
    cve_id: packet.cve_id,
    status: "ready",
    summary: "Update the confirmed pin and check the callers",
    reasoning: "The selected caller uses the affected dependency.",
    root_cause: "An affected version is pinned.",
    skills_used: ["python-remediation"],
    steps: [
      {
        kind: "dependency",
        description: "Update the owning pin",
        paths: ["requirements.txt"],
        evidence_ids: ["pin"],
      },
    ],
    version_changes: [],
    validation: [
      {
        description: "Regression suite",
        argv: ["python", "-m", "pytest"],
        cwd: ".",
        evidence_ids: ["tests"],
      },
    ],
    risks: [],
    missing_context: [],
  };
  const log = {
    command_id: "check-1",
    argv: ["python", "-m", "pytest"],
    cwd: ".",
    phase: "validation",
    status: "failed",
    exit_code: 1,
    stdout: "2 passed, 1 failed",
    stderr: "AssertionError: regression in the request caller",
  };
  const patch = {
    remediation_id: "fix-1",
    run_id: "run-1",
    cve_id: packet.cve_id,
    status: "failed",
    modified_files: ["requirements.txt"],
    dependency_changes: [],
    artifact_location: null,
    commands_executed: [log.argv],
    execution_results: [log],
    errors: ["Validation failed"],
    unresolved_issues: ["Regression needs review"],
    further_testing_required: true,
    human_intervention_required: true,
    plan_references: ["pin"],
  };
  await page.route("**/api/remediation/context/stream", (route) =>
    route.fulfill({
      contentType: "text/event-stream",
      body: frame("result", packet),
    }),
  );
  await page.route("**/api/remediation/plan/stream", (route) =>
    route.fulfill({
      contentType: "text/event-stream",
      body: frame("result", plan),
    }),
  );
  await page.route("**/api/remediation/patch/stream", (route) =>
    route.fulfill({
      contentType: "text/event-stream",
      body:
        frame("progress", {
          stage: "container",
          message: "Docker command returned",
          ...log,
        }) + frame("result", patch),
    }),
  );
  await start(page);
  await page
    .getByRole("button", { name: "Inspect urllib3 CVE-2023-45803" })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByRole("button", { name: "Investigate context", exact: true })
    .click();
  await dialog.getByRole("button", { name: "Create remediation plan" }).click();
  await expect(dialog.getByText(plan.reasoning)).toBeVisible();
  await dialog
    .getByRole("button", { name: "Apply patch in isolated sandbox" })
    .click();
  await expect(dialog.getByLabel("Standard error")).toContainText(
    "AssertionError",
  );
  await expect(dialog.getByLabel("Standard output")).toContainText(
    "2 passed, 1 failed",
  );
  await dialog.getByRole("tab", { name: "Validation results" }).click();
  await expect(dialog.getByText("1 failed", { exact: true })).toBeVisible();
  await expect(dialog.getByText("0 passed", { exact: true })).toBeVisible();
  await expect(dialog.getByText("Regression needs review")).toBeVisible();
  const accessibility = await new AxeBuilder({ page })
    .include('[role="dialog"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
  await dialog.screenshot({
    path: `test-results/patch-${test.info().project.name}.png`,
  });
});
