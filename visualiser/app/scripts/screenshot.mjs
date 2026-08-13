// Smoke-test the built app in a real browser: loads each view of an example
// and screenshots it after the page settles (including worker results).
// Usage: node scripts/screenshot.mjs [example] [baseUrl] [outDir]
import puppeteer from "puppeteer-core";

const example = process.argv[2] ?? "poseidon";
const base = process.argv[3] ?? "http://localhost:4173";
const outDir = process.argv[4] ?? "/tmp";
const chromium =
  process.env.CHROMIUM_BIN ?? "/etc/profiles/per-user/thomas/bin/chromium";

const browser = await puppeteer.launch({
  executablePath: chromium,
  headless: true,
  args: ["--no-sandbox", "--disable-gpu"],
});
const page = await browser.newPage();
await page.setViewport({ width: 1720, height: 1100 });

page.on("console", (msg) => {
  if (msg.type() === "error") console.log("PAGE ERROR:", msg.text());
});
page.on("pageerror", (e) => console.log("PAGE EXCEPTION:", e.message));

const views = [
  ["table", null],
  ["domain", null],
  ["prover", null],
  ["verifier", "text/Proof accepted"],
];

for (const [view, waitFor] of views) {
  await page.goto(`${base}/#/${example}/${view}`, { waitUntil: "networkidle0" });
  if (waitFor) {
    const [kind, text] = waitFor.split("/");
    if (kind === "text") {
      await page
        .waitForFunction(
          (t) => document.body.innerText.includes(t),
          { timeout: 30000 },
          text,
        )
        .catch(() => console.log(`TIMEOUT waiting for "${text}" on ${view}`));
    }
  } else {
    await new Promise((r) => setTimeout(r, 1500));
  }
  const path = `${outDir}/app_${example}_${view}.png`;
  await page.screenshot({ path });
  console.log("saved", path);
}

await browser.close();
