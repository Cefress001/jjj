/* ============================================================================
   OFFENSIVE EMULATOR v4 — application logic
   Landing → Console, attack orchestration, live terminal, report modal.
   ============================================================================ */
(function () {
  "use strict";

  var $ = function (sel, el) { return (el || document).querySelector(sel); };
  var $$ = function (sel, el) { return Array.prototype.slice.call((el || document).querySelectorAll(sel)); };

  var state = {
    config: null,
    preset: "balanced",
    runId: null,
    running: false,
    logCursor: -1,
    logShown: 0,
    pollHandle: null,
    tickHandle: null,
    demoHandle: null,
    runStartLocal: null,
    lastElapsed: 0,
    terminalStick: true
  };

  var PHASE_NAMES = {
    recon: "Reconnaissance", exploit: "Exploitation", persistence: "Persistence",
    lateral_movement: "Lateral Movement", exfiltration: "Exfiltration", cover_tracks: "Cover Tracks"
  };
  var PHASE_DESCS = {
    recon: "Endpoint mapping · tech fingerprinting · hidden routes",
    exploit: "JWT tampering · race conditions · privilege escalation",
    persistence: "Hidden admins · API keys · webhooks · cron backdoors",
    lateral_movement: "Credential harvesting · service discovery · key theft",
    exfiltration: "Bulk user export · transaction dumps · file extraction",
    cover_tracks: "Log deletion · audit purge · false-flag attribution"
  };

  // ------------------------------------------------------------------ utils

  function toast(msg, isError) {
    var box = $("#toasts");
    var el = document.createElement("div");
    el.className = "toast" + (isError ? " error" : "");
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      el.style.transition = "opacity .4s ease";
      setTimeout(function () { el.remove(); }, 420);
    }, 3400);
  }

  function api(path, opts) {
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok && r.status !== 202) throw new Error(data.error || ("HTTP " + r.status));
        return data;
      });
    });
  }

  function fmtTime(epochS) {
    var d = new Date(epochS * 1000);
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }

  function fmtElapsed(s) {
    s = Math.max(0, Math.round(s));
    var m = Math.floor(s / 60);
    return (m > 0 ? m + "m " : "") + (s % 60) + "s";
  }

  // ------------------------------------------------------------------ views

  function showLanding(instant) {
    location.hash = "#/";
    document.body.classList.remove("in-console");
    $("#view-console").classList.add("hidden");
    $("#view-landing").classList.remove("hidden");
    if (window.OE3D && OE3D.available) OE3D.backToLanding();
    // timers keep running — a live attack stays current and poll()
    // stops itself once the run finishes
  }

  function showConsole(instant) {
    location.hash = "#/console";
    document.body.classList.add("in-console");
    var doSwap = function () {
      $("#view-landing").classList.add("hidden");
      $("#view-console").classList.remove("hidden");
      refreshHistory();
    };
    if (instant || !OE3D.available) {
      doSwap();
      if (OE3D.available) OE3D.active = OE3D.console;
      return;
    }
    // cinematic warp into the core; swap the DOM at the dive midpoint
    OE3D.enterConsole(doSwap);
  }

  // ------------------------------------------------------------------ config

  function loadConfig() {
    return api("/api/configs").then(function (cfg) {
      state.config = cfg;

      // engine badge
      var badge = $("#engine-badge");
      badge.textContent = cfg.engine === "real" ? "◈ ENGINE: REAL" : "◈ ENGINE: SIMULATION";
      badge.className = "engine-badge " + (cfg.engine === "real" ? "real" : "sim");
      badge.title = cfg.engine === "real"
        ? "Real HTTP attack engines active (aiohttp detected)"
        : "Simulation mode — install aiohttp for real HTTP engines";
      var le = $("#landing-engine");
      if (le) le.textContent = cfg.engine === "real" ? "REAL" : "SIMULATION";

      // presets
      var grid = $("#preset-grid");
      grid.innerHTML = "";
      Object.keys(cfg.presets).forEach(function (key) {
        var p = cfg.presets[key];
        var el = document.createElement("div");
        el.className = "preset" + (key === state.preset ? " selected" : "");
        el.style.setProperty("--pcolor", p.color);
        el.dataset.preset = key;
        el.innerHTML =
          '<div class="p-dot"></div>' +
          '<div class="p-name" style="color:' + p.color + '">' + p.name + '</div>' +
          '<div class="p-tag">' + p.tag + '</div>';
        el.addEventListener("click", function () {
          if (state.running) { toast("Attack in progress — abort first", true); return; }
          state.preset = key;
          $$(".preset", grid).forEach(function (x) { x.classList.remove("selected"); });
          el.classList.add("selected");
        });
        grid.appendChild(el);
      });

      // default target = built-in demo
      if (!$("#target-input").value) $("#target-input").value = cfg.demo_target_url || "";
      $("#demo-open-note").textContent = "built-in target · zero setup";
      return cfg;
    });
  }

  // ----------------------------------------------------------------- attack

  function startAttack() {
    var target = ($("#target-input").value || "").trim();
    if (!target) { toast("Enter a target URL first", true); $("#target-input").classList.add("invalid"); return; }
    $("#target-input").classList.remove("invalid");
    if (!/^https?:\/\//i.test(target)) target = "http://" + target;

    api("/api/attack/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target, preset: state.preset })
    }).then(function (run) {
      state.runId = run.run_id;
      state.running = true;
      state.logCursor = -1;
      state.logShown = 0;
      state.runStartLocal = Date.now();
      state.lastElapsed = 0;
      state._prevPhases = {};

      // reset UI
      $("#terminal").innerHTML = "";
      $("#terminal-count").textContent = "0";
      $$(".pcard").forEach(function (c) {
        c.className = "pcard";
        $(".pc-state", c).textContent = "PENDING";
        $(".pc-metric", c).innerHTML = "&nbsp;";
      });
      if (OE3D.available) {
        OE3D.console.resetPhases();
        OE3D.console.setRunning(true);
        OE3D.console.resetView();
        OE3D.console.setTargetLabel(shortHost(run.target));
      }
      setPill("running", "ATTACK IN PROGRESS");
      setHudStatus("live", "ENGAGED");
      $("#hud-phase").textContent = "initializing…";
      $("#hud-target-label").innerHTML = "<b>" + escapeHtml(shortHost(run.target)) + "</b>";
      $("#btn-attack").disabled = true;
      $("#btn-abort").classList.add("show");

      toast("Attack " + run.run_id + " launched → " + shortHost(run.target));
      poll();
      refreshHistory();
    }).catch(function (err) {
      toast("Failed to start: " + err.message, true);
    });
  }

  function abortAttack() {
    if (!state.runId) return;
    api("/api/attack/" + state.runId + "/cancel", { method: "POST" })
      .then(function () { toast("Abort requested — winding down…"); })
      .catch(function (e) { toast(e.message, true); });
  }

  function stopTimers() {
    if (state.pollHandle) { clearTimeout(state.pollHandle); state.pollHandle = null; }
    if (state.tickHandle) { clearInterval(state.tickHandle); state.tickHandle = null; }
  }

  function poll() {
    if (!state.runId) return;
    api("/api/attack/" + state.runId + "/status?after=" + state.logCursor)
      .then(function (snap) {
        if (snap.run_id !== state.runId) return;   // stale

        state.lastElapsed = snap.elapsed_s;
        state.runStartLocal = Date.now() - snap.elapsed_s * 1000;

        // logs
        (snap.logs || []).forEach(appendLog);
        if (snap.log_total !== undefined) $("#terminal-count").textContent = snap.log_total;

        // phase states
        var prev = state._prevPhases || {};
        Object.keys(snap.phase_states || {}).forEach(function (key) {
          if (prev[key] !== snap.phase_states[key]) {
            updatePhaseCard(key, snap.phase_states[key]);
            if (OE3D.available) OE3D.console.setPhaseState(key, snap.phase_states[key]);
          }
        });
        state._prevPhases = snap.phase_states;

        // HUD
        $("#hud-pct").innerHTML = Math.floor(snap.progress) + "<small>%</small>";
        $("#hud-bar-i").style.width = snap.progress + "%";
        var phaseName = snap.current_phase ? PHASE_NAMES[snap.current_phase] : null;
        if (phaseName) $("#hud-phase").textContent = "◈ " + phaseName.toUpperCase();
        else if (snap.status === "complete") $("#hud-phase").textContent = "◈ MISSION COMPLETE";

        if (snap.status === "running" || snap.status === "queued") {
          state.pollHandle = setTimeout(poll, 750);
          return;
        }

        // finished
        state.running = false;
        $("#btn-attack").disabled = false;
        $("#btn-abort").classList.remove("show");
        if (OE3D.available) OE3D.console.setRunning(false);

        if (snap.status === "complete") {
          setPill("done", "COMPLETE");
          setHudStatus("ok", "COMPLETE");
          $("#hud-pct").innerHTML = "100<small>%</small>";
          $("#hud-bar-i").style.width = "100%";
        } else if (snap.status === "aborted") {
          setPill("done", "ABORTED");
          setHudStatus("bad", "ABORTED");
        } else {
          setPill("fail", "FAILED");
          setHudStatus("bad", "FAILED");
          toast("Attack failed: " + (snap.error || "unknown error"), true);
        }

        fetchReport(snap.run_id);
        refreshHistory();
      })
      .catch(function (err) {
        if (state.running) {
          toast("Connection lost: " + err.message, true);
          state.pollHandle = setTimeout(poll, 1600);
        }
      });
  }

  function fetchReport(runId) {
    api("/api/attack/" + runId + "/report")
      .then(function (report) { openReport(report); })
      .catch(function () { /* no report (aborted/failed early) */ });
  }

  // ------------------------------------------------------------------- logs

  function appendLog(entry) {
    if (entry.i <= state.logCursor) return;
    state.logCursor = entry.i;
    var term = $("#terminal");
    var empty = $(".terminal-empty", term);
    if (empty) empty.remove();

    var row = document.createElement("div");
    row.className = "tl lv-" + (entry.level || "INFO");
    var tt = document.createElement("span");
    tt.className = "tt";
    tt.textContent = fmtTime(entry.t);
    var tm = document.createElement("span");
    tm.className = "tm";
    tm.textContent = entry.msg;
    row.appendChild(tt);
    row.appendChild(tm);

    // stick to bottom unless the user scrolled up
    var stick = term.scrollTop + term.clientHeight >= term.scrollHeight - 50;
    term.appendChild(row);
    while (term.children.length > 420) term.removeChild(term.firstChild);
    if (stick) term.scrollTop = term.scrollHeight;
    state.logShown++;
  }

  // ------------------------------------------------------------ phase cards

  function updatePhaseCard(key, phaseState) {
    var card = $('.pcard[data-phase="' + key + '"]');
    if (!card) return;
    card.className = "pcard " + (phaseState === "complete" ? "complete" : phaseState);
    $(".pc-state", card).textContent = phaseState.toUpperCase();
    var metric = { running: "engaged…" }[phaseState];
    if (metric) $(".pc-metric", card).textContent = metric;
  }

  function fillPhaseMetrics(report) {
    var r = report || {};
    var g = function (k) { return r[k] || {}; };
    var m = {
      recon: (g("recon_results").endpoints_discovered || 0) + " endpoints",
      exploit: (g("exploit_results").methods || []).join(", ") || "no access",
      persistence: (g("persistence_results").backdoors_installed || 0) + " backdoors",
      lateral_movement: (g("lateral_movement_results").credentials_extracted || 0) + " credentials",
      exfiltration: (g("exfiltration_results").records_stolen || 0) + " records · " +
        (g("exfiltration_results").data_exfiltrated_mb || 0).toFixed(2) + " MB",
      cover_tracks: (g("cover_tracks_results").logs_deleted || 0) + " logs wiped"
    };
    Object.keys(m).forEach(function (key) {
      var card = $('.pcard[data-phase="' + key + '"]');
      if (card) $(".pc-metric", card).textContent = m[key];
    });
  }

  // -------------------------------------------------------------------- HUD

  function setPill(kind, text) {
    var pill = $("#run-pill");
    pill.className = "run-pill show " + (kind === "running" ? "" : kind === "fail" ? "fail" : "done");
    $("#run-pill-text").textContent = text;
  }

  function setHudStatus(kind, text) {
    var el = $("#hud-tl");
    el.className = "hud " + (kind || "");
    $("#hud-status-text").textContent = text;
  }

  function shortHost(url) {
    try {
      var u = new URL(url);
      return u.host + (u.pathname !== "/" ? u.pathname : "");
    } catch (e) { return url; }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // ------------------------------------------------------------------ modal

  function openReport(report) {
    fillPhaseMetrics(report);
    var s = report.summary || {};
    var modal = $("#modal-backdrop");
    $("#modal-run").textContent = "run " + (report.run_id || "—") + " · post-mission assessment";

    // severity + vitals
    var sev = s.severity || "Low";
    $("#rep-sev").textContent = "SEVERITY: " + sev.toUpperCase();
    $("#rep-sev").className = "sev-chip sev-" + sev;
    $("#rep-v-target").textContent = report.target;
    $("#rep-v-run").textContent = report.run_id;
    $("#rep-v-engine").textContent = report.engine === "real" ? "real HTTP engines" : "simulation";
    $("#rep-v-time").textContent = (report.total_time_seconds || 0).toFixed(2) + "s · " +
      new Date(report.timestamp || Date.now()).toLocaleString();

    // success ring
    var pct = parseFloat(s.attack_success_rate) || 0;
    var C = 2 * Math.PI * 48;
    var arc = $("#ring-arc");
    arc.style.strokeDasharray = C.toFixed(1);
    arc.style.strokeDashoffset = C.toFixed(1);
    $("#ring-num").textContent = Math.round(pct) + "%";
    setTimeout(function () {
      arc.style.strokeDashoffset = (C * (1 - pct / 100)).toFixed(1);
    }, 80);

    // chain
    var names = {
      phase_1_recon: "Reconnaissance", phase_2_exploit: "Exploitation",
      phase_3_persistence: "Persistence", phase_4_lateral_movement: "Lateral Movement",
      phase_5_exfiltration: "Exfiltration", phase_6_cover_tracks: "Cover Tracks"
    };
    var icons = { phase_1_recon: "◉", phase_2_exploit: "⚡", phase_3_persistence: "🔓", phase_4_lateral_movement: "⇄", phase_5_exfiltration: "▤", phase_6_cover_tracks: "☄" };
    var timings = report.phase_timings || {};
    var timingKeys = ["recon", "exploit", "persistence", "lateral_movement", "exfiltration", "cover_tracks"];
    var chainBox = $("#rep-chain");
    chainBox.innerHTML = "";
    Object.keys(report.attack_chain || {}).forEach(function (k, idx) {
      var ok = report.attack_chain[k];
      var row = document.createElement("div");
      var cls = ok ? "ok" : (timings[timingKeys[idx]] !== undefined && timings[timingKeys[idx]] > 0 ? "bad" : "skip");
      row.className = "chain-row " + cls;
      var t = timings[timingKeys[idx]];
      row.innerHTML =
        '<span class="c-ico">' + icons[k] + '</span>' +
        '<span class="c-name">' + names[k] + '</span>' +
        '<span class="c-time">' + (ok ? (t !== undefined ? t.toFixed(2) + "s" : "✓") : (cls === "skip" ? "skipped" : "failed")) + '</span>';
      chainBox.appendChild(row);
    });

    // findings
    var fl = $("#rep-findings");
    fl.innerHTML = "";
    (s.key_findings || []).forEach(function (f) {
      var li = document.createElement("li");
      li.textContent = f;
      fl.appendChild(li);
    });

    // tiles
    var tiles = [
      [report.recon_results.endpoints_discovered, "endpoints"],
      [(report.exploit_results.methods || []).length, "exploits"],
      [report.persistence_results.backdoors_installed, "backdoors"],
      [report.lateral_movement_results.credentials_extracted, "credentials"],
      [report.exfiltration_results.records_stolen, "records stolen"],
      [(report.exfiltration_results.data_exfiltrated_mb || 0).toFixed(2) + " MB", "exfiltrated"],
      [report.cover_tracks_results.logs_deleted, "logs deleted"],
      [(report.total_time_seconds || 0).toFixed(1) + "s", "duration"]
    ];
    var tileBox = $("#rep-tiles");
    tileBox.innerHTML = "";
    tiles.forEach(function (t) {
      var d = document.createElement("div");
      d.className = "tile";
      d.innerHTML = '<div class="v">' + escapeHtml(t[0]) + '</div><div class="k">' + t[1] + '</div>';
      tileBox.appendChild(d);
    });

    // downloads
    $("#rep-dl-html").href = "/api/attack/" + report.run_id + "/report.html";
    $("#rep-dl-json").href = "/api/attack/" + report.run_id + "/report.json";

    modal.classList.add("open");
  }

  function closeModal() { $("#modal-backdrop").classList.remove("open"); }

  // ---------------------------------------------------------------- history

  function refreshHistory() {
    api("/api/attack/list").then(function (data) {
      var box = $("#history");
      box.innerHTML = "";
      (data.runs || []).slice(0, 12).forEach(function (r) {
        var item = document.createElement("div");
        item.className = "hist-item";
        item.title = r.target;
        var sevTxt = r.severity ? " · " + r.severity : "";
        item.innerHTML =
          '<span class="h-dot ' + r.status + '"></span>' +
          '<span class="h-id">' + r.run_id + '</span>' +
          '<span class="h-meta">' + r.preset + sevTxt + '</span>';
        item.addEventListener("click", function () {
          if (r.status === "complete") {
            api("/api/attack/" + r.run_id + "/report").then(openReport)
              .catch(function () { toast("No report available", true); });
          } else {
            toast("Run " + r.run_id + " — " + r.status);
          }
        });
        box.appendChild(item);
      });
    }).catch(function () {});
  }

  // ------------------------------------------------------------- demo stats

  function pollDemoStats() {
    var target = ($("#target-input").value || "");
    var isDemo = target.indexOf("/demo") !== -1;
    var el = $("#hud-reqs");
    if (!isDemo) { el.textContent = ""; return; }
    api("/api/demo/stats").then(function (s) {
      el.innerHTML = "◂ <b>" + s.requests + "</b> requests hit the demo target";
    }).catch(function () {});
  }

  // ------------------------------------------------------------------- init

  function buildPhaseCards() {
    var grid = $("#phase-grid");
    grid.innerHTML = "";
    Object.keys(PHASE_NAMES).forEach(function (key, i) {
      var card = document.createElement("div");
      card.className = "pcard";
      card.dataset.phase = key;
      card.innerHTML =
        '<div class="pc-top">' +
        '<span class="pc-num">0' + (i + 1) + '</span>' +
        '<span class="pc-name">' + PHASE_NAMES[key].toUpperCase() + '</span>' +
        '<span class="pc-state">PENDING</span>' +
        '</div><div class="pc-metric">&nbsp;</div>';
      grid.appendChild(card);
    });
  }

  function init() {
    buildPhaseCards();
    loadConfig().then(function () {
      $("#hud-target-label").innerHTML = "<b>" + escapeHtml(shortHost($("#target-input").value)) + "</b>";
    }).catch(function () {
      toast("Backend unreachable — is run.py running?", true);
    });

    // ---- 3D
    var ok = false;
    try { ok = window.OE3D && OE3D.init($("#bg3d"), $("#flash")); } catch (e) { ok = false; }
    if (!ok) {
      document.body.classList.add("no3d");
    } else {
      OE3D.onHover = function (key, x, y) {
        var tip = $("#stage-tooltip");
        if (!key) { tip.style.display = "none"; return; }
        var state = (state._prevPhases || {})[key] || "pending";
        tip.innerHTML =
          '<div class="tt-name">' + PHASE_NAMES[key] + '</div>' +
          '<div class="tt-state" style="color:' +
            ({ pending: "#7e8db3", running: "#22d3ee", complete: "#34d399", failed: "#f43f5e", skipped: "#55638a" }[state] || "#7e8db3") +
            '">' + state.toUpperCase() + '</div>' +
          '<div class="tt-desc">' + PHASE_DESCS[key] + '</div>';
        var stage = $("#stage").getBoundingClientRect();
        tip.style.display = "block";
        var tw = tip.offsetWidth, th = tip.offsetHeight;
        tip.style.left = Math.min(Math.max(8, x - stage.left + 16), stage.width - tw - 8) + "px";
        tip.style.top = Math.min(Math.max(8, y - stage.top - th - 12), stage.height - th - 8) + "px";
      };
      OE3D.onNodeClick = function (key) {
        OE3D.console.focusPhase(key);
        var card = $('.pcard[data-phase="' + key + '"]');
        if (card) {
          card.scrollIntoView({ behavior: "smooth", block: "nearest" });
          card.classList.add("highlight");
          setTimeout(function () { card.classList.remove("highlight"); }, 1800);
        }
      };
    }

    // ---- routing
    if (location.hash === "#/console") {
      document.body.classList.add("in-console");
      $("#view-landing").classList.add("hidden");
      $("#view-console").classList.remove("hidden");
      if (OE3D.available) OE3D.active = OE3D.console;
    }
    window.addEventListener("hashchange", function () {
      var consoleHidden = $("#view-console").classList.contains("hidden");
      var landingHidden = $("#view-landing").classList.contains("hidden");
      if (location.hash === "#/console" && consoleHidden) showConsole(false);
      else if (location.hash !== "#/console" && landingHidden) showLanding();
    });

    // ---- wiring
    $("#cta-enter").addEventListener("click", function () { showConsole(false); });
    $("#btn-back").addEventListener("click", function () {
      if (state.running && !confirm("An attack is running — leave the console anyway?")) return;
      showLanding();
    });
    $("#btn-attack").addEventListener("click", startAttack);
    $("#btn-abort").addEventListener("click", abortAttack);
    $("#btn-demo").addEventListener("click", function () {
      if (state.config && state.config.demo_target_url) {
        $("#target-input").value = state.config.demo_target_url;
        $("#target-input").classList.remove("invalid");
        $("#hud-target-label").innerHTML = "<b>" + escapeHtml(shortHost(state.config.demo_target_url)) + "</b>";
        pollDemoStats();
        toast("Target set to the built-in demo app");
      }
    });
    $("#target-input").addEventListener("input", function () { $(this).classList.remove("invalid"); });
    $("#target-input").addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" && !state.running) startAttack();
    });
    $("#modal-close").addEventListener("click", closeModal);
    $("#modal-backdrop").addEventListener("click", function (ev) {
      if (ev.target === this) closeModal();
    });
    $("#rep-again").addEventListener("click", function () {
      closeModal();
      if (!state.running) startAttack();
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") closeModal();
    });

    // stickiness of terminal
    $("#terminal").addEventListener("scroll", function () {
      var el = this;
      state.terminalStick = el.scrollTop + el.clientHeight >= el.scrollHeight - 50;
    });

    // timers
    state.tickHandle = setInterval(function () {
      if (state.running && state.runStartLocal) {
        var el = (Date.now() - state.runStartLocal) / 1000;
        $("#hud-elapsed").textContent = "⏱ " + fmtElapsed(el);
      }
    }, 500);
    state.demoHandle = setInterval(pollDemoStats, 1200);

    refreshHistory();
    setHudStatus("", "STANDBY");
    $("#hud-phase").textContent = "awaiting orders";
    $("#hud-elapsed").textContent = "⏱ 0s";
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
