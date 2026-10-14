/** Opt-in browser-to-backend check against real providers and a public example. */
import { chromium, expect } from "@playwright/test";
import { mkdir, readFile } from "node:fs/promises";
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const errors: string[] = [];
page.on("pageerror", (error) => errors.push(error.message));
try {
  await mkdir("test-results", { recursive: true });
  await page.goto(process.env.AEGIS_UI_URL || "http://127.0.0.1:5173");
  await expect(
    page.getByText("Backend connected", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: "test-results/live-landing.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: /NodeGoat/ }).click();
  await page
    .getByRole("switch", { name: "Model-assisted intelligence" })
    .click();
  await page
    .getByRole("button", { name: "Analyze repository", exact: true })
    .click();
  console.log("Started real NodeGoat intake and scan.");
  await expect(
    page.getByRole("heading", { name: "What deserves your attention" }),
  ).toBeVisible({ timeout: 600000 });
  const downloading = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export report" }).click();
  const download = await downloading;
  await download.saveAs("test-results/live-report.json");
  const scan = JSON.parse(
    await readFile("test-results/live-report.json", "utf8"),
  );
  expect(scan.status).not.toBe("failed");
  expect(scan.report.packages_queried).toBeGreaterThan(0);
  expect(scan.report.repository_analysis.projects.length).toBeGreaterThan(0);
  expect(scan.report.vulnerabilities.length).toBeGreaterThan(0);
  await expect(page.getByRole("log")).toContainText("Collecting CVSS");
  await page.screenshot({
    path: "test-results/live-results.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: /^Inspect / })
    .first()
    .click();
  await expect(page.getByRole("dialog")).toContainText(
    "Package usage evidence",
  );
  await page.screenshot({ path: "test-results/live-evidence.png" });
  expect(errors).toEqual([]);
  console.log(
    `Live browser scan passed: scan #${scan.id}, ${scan.report.packages_queried} packages, ${scan.report.vulnerabilities.length} findings; ${scan.status} coverage.`,
  );
} finally {
  await browser.close();
}
