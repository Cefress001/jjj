/**
 * DOM integration test — boots the real index.html + JS against the running
 * server (default http://127.0.0.1:8000) and drives the full user flow:
 *
 *   landing → console → tour → difficulty select → attack (real engine)
 *   → live network inspector → report modal (MITRE / recommendations)
 *   → replay enter/exit → archive + compare → help modal → shortcuts
 *
 * Run:  node tests/js/dom_flow.js   (server must be running; `python run.py`)
 * Needs jsdom:  npm i jsdom   (or NODE_PATH pointing at an existing install)
 */
const fs = require("fs");
const path = require("path");
const http = require("http");
const { JSDOM } = require("jsdom");

const BASE = process.env.OE_BASE || "http://127.0.0.1:8000";
const STATIC = path.join(__dirname, "..", "..", "offensive_emulator", "static");

function nodeFetch(url, opts) {
  return new Promise((resolve, reject) => {
    const u = new URL(url, BASE);
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: (opts && opts.method) || "GET",
      headers: Object.assign(
        { "Content-Length": opts && opts.body ? Buffer.byteLength(opts.body) : 0 },
        (opts && opts.headers) || {}),
    }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({
        ok: res.statusCode >= 200 && res.statusCode < 300,
        status: res.statusCode,
        json: () => Promise.resolve(JSON.parse(data || "{}")),
      }));
    });
    req.on("error", reject);
    if (opts && opts.body) req.write(opts.body);
    req.end();
  });
}

function get(p) {
  return new Promise((resolve, reject) => {
    http.get(BASE + p, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  console.log("· loading app from", BASE);
  const html = await get("/");
  const dom = new JSDOM(html, { url: BASE + "/", runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  const { document } = window;

  window.fetch = nodeFetch;
  window.matchMedia = window.matchMedia || (() => ({ matches: false }));
  window.HTMLCanvasElement.prototype.getContext = () => null;   // force no3d path

  window.eval(fs.readFileSync(path.join(STATIC, "vendor/three.min.js"), "utf8"));
  window.eval(fs.readFileSync(path.join(STATIC, "js/scenes.js"), "utf8"));
  window.eval(fs.readFileSync(path.join(STATIC, "js/sound.js"), "utf8"));
  window.eval(fs.readFileSync(path.join(STATIC, "js/tour.js"), "utf8"));
  window.eval(fs.readFileSync(path.join(STATIC, "js/app.js"), "utf8"));

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const A = (cond, msg) => { if (!cond) throw new Error("FAIL: " + msg); console.log("  ✓", msg); };

  // ---------- 1. boot
  A(!$("#view-landing").classList.contains("hidden"), "landing visible on boot");
  A(window.OE_Sound && window.OE_Tour, "sound + tour modules loaded");
  for (let i = 0; i < 40 && $$("#preset-grid .preset").length !== 4; i++) await sleep(150);
  A($$("#preset-grid .preset").length === 4, "presets rendered");
  A($("#target-input").value.includes("/demo"), "demo target prefilled");
  A($$("#difficulty .diff").length === 3, "difficulty selector rendered");

  // ---------- 2. CTA → console (+ tour auto-starts on first visit)
  $("#cta-enter").click();
  await sleep(200);
  A(!$("#view-console").classList.contains("hidden"), "console opened");
  for (let i = 0; i < 20 && !$(".tour-root.open"); i++) await sleep(150);
  A($(".tour-root.open"), "onboarding tour auto-started");
  $(".tour-skip").click();
  await sleep(100);
  A(!$(".tour-root.open"), "tour dismissed");

  // ---------- 3. difficulty selector switches target
  $$("#difficulty .diff").find((b) => b.dataset.mode === "fortified").click();
  await sleep(100);
  A($("#target-input").value.includes("/demo/fortified"), "fortified mode sets target");
  $$("#difficulty .diff").find((b) => b.dataset.mode === "easy").click();
  await sleep(50);
  A($("#target-input").value.endsWith("/demo"), "easy mode restores target");

  // ---------- 4. full attack (real engine against demo target)
  console.log("· launching attack (this takes ~15-25s)…");
  $("#btn-attack").click();
  await sleep(1500);
  A($("#btn-attack").disabled, "attack button locked during run");
  A($("#btn-abort").classList.contains("show"), "abort button visible");

  let netRowsSeen = 0;
  let modalOpen = false;
  for (let i = 0; i < 160 && !modalOpen; i++) {
    await sleep(500);
    modalOpen = $("#modal-backdrop").classList.contains("open");
    // switch to the network tab mid-run to watch live traffic
    if (i === 6) { $("#tab-network").click(); await sleep(50); }
    if (i === 8) netRowsSeen = $$(".net-row").length;
  }
  A(modalOpen, "report modal opened after run");
  A(netRowsSeen > 10, `network inspector showed live requests (${netRowsSeen} rows mid-run)`);
  const totalReq = parseInt($("#ns-total").textContent, 10);
  A(totalReq > 80, `network stats counted requests (${totalReq})`);

  // ---------- 5. report contents
  A($("#rep-verdict").textContent.length > 5, "verdict line present: " + $("#rep-verdict").textContent);
  A($$("#rep-chain .chain-row").length === 6, "chain rows (6)");
  A($$("#rep-chain .mchip").length >= 10, "MITRE technique chips attached (" + $$("#rep-chain .mchip").length + ")");
  A($$("#rep-recs .rec").length >= 5, "remediation recommendations (" + $$("#rep-recs .rec").length + ")");
  A($("#rep-sev").textContent.includes("HIGH"), "easy run severity HIGH");
  A($("#rep-print").href.includes("print=1"), "print/pdf link wired");

  // ---------- 6. replay
  closeModal();
  A(!$("#replay-bar").classList.contains("hidden"), "replay bar shown after completion");
  $("#replay-play").click();       // enter replay happens via R or the bar; enter directly:
  // (enterReplay is triggered by the R key or the report button)
  document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "r" }));
  await sleep(1500);
  A($("#hud-livechip").textContent === "REPLAY", "replay mode engaged (chip=REPLAY)");
  A(!$("#replay-bar").classList.contains("hidden"), "replay transport visible");
  document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape" }));
  await sleep(300);
  A($("#hud-livechip").textContent === "LIVE", "escape exits replay (chip=LIVE)");
  A($$("#terminal .tl").length > 50, "terminal restored after replay exit");

  function closeModal() { $("#modal-close").click(); }

  // ---------- 7. fortified run → defenses + defense section in report
  console.log("· launching FORTIFIED attack…");
  $$("#difficulty .diff").find((b) => b.dataset.mode === "fortified").click();
  await sleep(100);
  $("#btn-attack").click();
  let modal2 = false;
  for (let i = 0; i < 160 && !modal2; i++) {
    await sleep(500);
    modal2 = $("#modal-backdrop").classList.contains("open");
  }
  A(modal2, "fortified run completed");
  A($("#rep-verdict").textContent.includes("HELD"), "fortified verdict: " + $("#rep-verdict").textContent);
  A(parseInt($("#ns-def").textContent, 10) > 40, "defense blocks counted in network panel (" + $("#ns-def").textContent + ")");
  A($("#rep-defense-section").style.display !== "none", "defense posture section visible");
  A($$("#rep-defense-chips .dchip").length >= 2, "defense type chips present");
  closeModal();

  // ---------- 8. archive + compare
  $("#btn-archive").click();
  await sleep(800);
  const archRows = $$(".arch-row");
  A(archRows.length >= 2, `archive lists runs (${archRows.length})`);
  archRows[0].click();
  archRows[1].click();
  await sleep(100);
  A(!$("#btn-compare").disabled, "compare enabled with two selected");
  $("#btn-compare").click();
  await sleep(1200);
  A($$("#archive-compare .cmp-grid .v").length > 20, "compare table rendered");
  $("#archive-close").click();

  // ---------- 9. help modal + shortcuts + mute
  $("#btn-help").click();
  A($("#help-backdrop").classList.contains("open"), "help modal opens");
  $("#help-close").click();
  document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "m" }));
  A($("#btn-mute").textContent.includes("MUTED"), "M toggles mute");
  document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "m" }));

  // ---------- 10. back to landing
  $("#btn-back").click();
  await sleep(150);
  A(!$("#view-landing").classList.contains("hidden"), "returned to landing");

  console.log("\nALL DOM INTEGRATION TESTS PASSED ✅");
  process.exit(0);
})().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
