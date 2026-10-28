import { test, expect } from "@playwright/test";

test("LAB customer journey: account, organization, findings, playbooks and report", async ({ page }) => {
  const id = Date.now().toString(36);
  const email = `browser-${id}@cyberpilot.local`;
  const orgName = `Browser Pilot ${id}`;

  await page.goto("/login");
  await expect(page.getByText("Local Lab access")).toBeVisible();
  await page.getByLabel("Name").fill("Browser Pilot Owner");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("BrowserPilotOnly-2026!");
  await page.getByRole("button", { name: "Create Lab account" }).click();
  // Surface the actual authentication error in CI instead of a generic navigation timeout.
  await expect.poll(async () => {
    const heading = await page.getByRole("heading", { name: "Security workspace" }).count();
    if (heading) return "ready";
    const error = await page.locator(".auth-error").count()
      ? await page.locator(".auth-error").textContent()
      : null;
    return error ? `Auth error: ${error.trim()}` : `At ${page.url()}: ${(await page.locator("body").innerText()).slice(0,160)}`;
  }, { timeout: 30_000, intervals: [500, 1000, 2000] }).toBe("ready");

  await expect(page.getByRole("heading", { name: "Security workspace" })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("link", { name: "Create an organization" }).click();
  await page.getByLabel("Organization name").fill(orgName);
  await page.getByRole("button", { name: "Create organization" }).click();

  await expect(page.getByRole("button", { name: "Start Microsoft 365 Lab" })).toBeVisible();
  await page.getByRole("button", { name: "Start Microsoft 365 Lab" }).click();
  await expect(page.getByRole("button", { name: "Re-evaluate lab" })).toBeVisible();
  await page.getByRole("button", { name: "Re-evaluate lab" }).click();

  await expect(page.getByRole("heading", { name: "Top actions" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Remediation playbooks" })).toBeVisible();
  await expect(page.locator(".priority-list a[href^='#']").first()).toBeVisible();
  const target = await page.locator(".priority-list a[href^='#']").first().getAttribute("href");
  await page.locator(".priority-list a[href^='#']").first().click();
  expect(new URL(page.url()).hash).toBe(target);

  // A guided acknowledgement tracks work, but cannot close a finding or change the score.
  const guidedCard = page.locator(".remediation-card").filter({ has: page.locator(".priority-score", { hasText: "GUIDED" }) }).first();
  await expect(guidedCard).toBeVisible();
  const scoreBefore = await page.locator(".panel").getByText("CyberScore v0").locator("..").locator(".panel-value").innerText();
  const findingsBefore = await page.locator(".panel").getByText("Open findings").locator("..").locator(".panel-value").innerText();
  const historyBefore = await page.locator(".history-list .history-row").count();

  const approve = guidedCard.getByRole("button", { name: "Approve playbook" });
  if (await approve.count()) {
    await approve.click();
  }
  const activeGuidedCard = page.locator(".remediation-card").filter({ has: page.locator(".priority-score", { hasText: "GUIDED" }) }).first();
  await expect(activeGuidedCard.getByText(/Steps acknowledged: 0 \/ /)).toBeVisible();
  const acknowledgements = activeGuidedCard.getByRole("button", { name: /^Acknowledge step \d+$/ });
  const stepCount = await acknowledgements.count();
  expect(stepCount).toBeGreaterThan(0);
  for (let step = 1; step <= stepCount; step++) {
    await activeGuidedCard.getByRole("button", { name: `Acknowledge step ${step}` }).click();
    await expect(activeGuidedCard.getByRole("button", { name: `Step ${step} acknowledged` })).toBeDisabled();
    await expect(activeGuidedCard.getByText(new RegExp(`Steps acknowledged: ${step} / ${stepCount}`))).toBeVisible();
  }
  await expect(activeGuidedCard.getByRole("button", { name: "Re-evaluate LAB evidence" })).toBeVisible();
  await expect(page.locator(".panel").getByText("CyberScore v0").locator("..").locator(".panel-value")).toHaveText(scoreBefore);
  await expect(page.locator(".panel").getByText("Open findings").locator("..").locator(".panel-value")).toHaveText(findingsBefore);
  expect(await page.locator(".history-list .history-row").count()).toBe(historyBefore);
  await page.reload();
  await expect(page.locator(".remediation-card").filter({ has: page.locator(".priority-score", { hasText: "GUIDED" }) }).first().getByText(new RegExp(`Steps acknowledged: ${stepCount} / ${stepCount}`))).toBeVisible();

  const reportUrl = new URL(page.url());
  reportUrl.hash = "";
  reportUrl.pathname += "/report";
  await page.goto(reportUrl.toString());
  await expect(page.locator(".executive-report")).toBeVisible();
  await expect(page.getByText("LAB REPORT — SYNTHETIC EVIDENCE")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Multi-source evidence coverage (preview)" })).toBeVisible();
  await expect(page.getByText("Missing evidence is not a passing security control.", { exact: false })).toBeVisible();
});
