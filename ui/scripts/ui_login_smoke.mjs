import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");
const artifactDir = path.join(repoRoot, "output", "playwright");

const baseUrl = (process.env.UI_URL ?? "http://localhost:3000").replace(/\/$/, "");
const username = process.env.ADMIN_USER ?? "admin";
const password = process.env.ADMIN_PASS;

if (!password) {
  console.error("Set ADMIN_PASS=yourpassword");
  process.exit(1);
}

async function main() {
  await fs.mkdir(artifactDir, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  page.on("console", (msg) => {
    if (msg.type() === "error") {
      console.error(`[browser:${msg.type()}] ${msg.text()}`);
    }
  });

  try {
    await page.goto(`${baseUrl}/login`, { waitUntil: "domcontentloaded" });

    const submit = page.getByRole("button", { name: /log in/i });
    await submit.waitFor({ state: "visible" });
    await page.waitForFunction(() => {
      const button = Array.from(document.querySelectorAll("button")).find((candidate) =>
        /log in/i.test(candidate.textContent ?? ""),
      );
      return Boolean(button && !button.hasAttribute("disabled"));
    }, undefined, { timeout: 10000 });

    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await submit.click();

    await page.waitForURL(/\/(admin|dashboard)(?:\?.*)?$/, { timeout: 15000 });
    await page.getByRole("button", { name: /log out/i }).waitFor({ timeout: 15000 });

    await page.goto(`${baseUrl}/sensors`, { waitUntil: "domcontentloaded" });
    await page.getByRole("heading", { name: "Sensors" }).waitFor({ timeout: 15000 });
    await page.getByRole("button", { name: /add sensor/i }).click();

    const sensorName = `ui-smoke-${Date.now()}`;
    await page.locator('input[placeholder*="Sensor name"]').fill(sensorName);
    await page.getByRole("button", { name: /^Generate$/ }).click();

    await page.getByText("Sensor Onboarding Ready").waitFor({ timeout: 15000 });
    await page.getByText("Install Command", { exact: true }).waitFor({ timeout: 15000 });

    console.log("UI login + sensor onboarding smoke passed");
  } catch (error) {
    await page.screenshot({ path: path.join(artifactDir, "ui-login-failure.png"), fullPage: true });
    await fs.writeFile(path.join(artifactDir, "ui-login-failure.html"), await page.content(), "utf8");
    console.error("UI login smoke failed");
    throw error;
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exit(1);
});
