import { expect, test } from "@playwright/test";

test("dashboard shell renders", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible();
  await expect(page.getByRole("table")).toContainText("QUARANTINE_PENDING_ANALYSIS");
});