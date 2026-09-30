/* ============================================================================
   OFFENSIVE EMULATOR v4.1 — application logic
   Landing → Console, attack orchestration, live terminal, network inspector,
   mission replay, director camera, archive & compare, sounds, shortcuts.
   ============================================================================ */
(function () {
  "use strict";

  var $ = function (sel, el) { return (el || document).querySelector(sel); };
  var $$ = function (sel, el) { return Array.prototype.slice.call((el || document).querySelectorAll(sel)); };

  var PHASE_KEYS = ["recon", "exploit", "persistence", "lateral_movement", "exfiltration", "cover_tracks"];
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
  var CHAIN_KEY_TO_PHASE = {
    phase_1_recon: "recon", phase_2_exploit: "exploit", phase_3_persistence: "persistence",
    phase_4_lateral_movement: "lateral_movement", phase_5_exfiltration: "exfiltration",
    phase_6_cover_tracks: "cover_tracks"
  };

  var state = {
    config: null,
    preset: "balanced",
    difficulty: "easy",
    runId: null,
    running: false,
    mode: "live",                       // 'live' | 'replay'
    logCursor: -1,
    eventCursor: -1,
    pollHandle: null,
    tickHandle: null,
    demoHandle: null,
    runStartLocal: null,
    lastPhaseStates: {},
    receivedLogs: [],                   // capped mirror for replay-exit rebuild
    netEvents: [],                      // all request events (capped)
    netStats: { total: 0, errors: 0, sumMs: 0, def: 0 },
    netFilter: "all",
    director: true,
    replay: null,                       // replay engine state
    archiveSel: [],
    lastCompletedRun: null
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

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function shortHost(url) {
    try {
      var u = new URL(url);
      return u.host + (u.pathname !== "/" ? u.pathname : "");
    } catch (e) { return url; }
  }

  function countUp(el, value, opts) {
    opts = opts || {};
    var dec = opts.dec || 0;
    var from = parseFloat(el.dataset.cu || "0") || 0;
    var to = parseFloat(value) || 0;
    el.dataset.cu = String(to);
    var t0 = performance.now();
    var dur = opts.dur || 850;
    var lastTickAt = 0;
    function frame(now) {
      var k = Math.min(1, (now - t0) / dur);
      k = 1 - Math.pow(1 - k, 3);
      var v = from + (to - from) * k;
      el.textContent = v.toFixed(dec).replace(/\B(?=(\d{3})+(?!\d))/g, ",") + (opts.suffix || "");
      if (now - lastTickAt > 90 && k < 1) { OE_Sound.play("tick"); lastTickAt = now; }
      if (k < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  // ------------------------------------------------------------------ views

  function showLanding() {
    location.hash = "#/";
    document.body.classList.remove("in-console");
    $("#view-console").classList.add("hidden");
    $("#view-landing").classList.remove("hidden");
    if (window.OE3D && OE3D.available) OE3D.backToLanding();
  }

  function showConsole(instant) {
    location.hash = "#/console";
    document.body.classList.add("in-console");
    var doSwap = function () {
      $("#view-landing").classList.add("hidden");
      $("#view-console").classList.remove("hidden");
      refreshHistory();
      if (!state._touredOnce) {
        state._touredOnce = true;
        if (window.OE_Tour) setTimeout(function () { OE_Tour.maybeStart(); }, 700);
      }
    };
    if (instant || !OE3D.available) {
      doSwap();
      if (OE3D.available) OE3D.active = OE3D.console;
      return;
    }
    OE3D.enterConsole(doSwap);
  }

  // ------------------------------------------------------------------ config

  function loadConfig() {
    return api("/api/configs").then(function (cfg) {
      state.config = cfg;

      var badge = $("#engine-badge");
      var scannerCount = Object.keys(cfg.scanners || {}).filter(function (key) {
        return cfg.scanners[key].available;
      }).length;
      badge.textContent = scannerCount ? "◈ PIPELINE: " + scannerCount + " TOOLS" :
        (cfg.engine === "real" ? "◈ ENGINE: REAL" : "◈ ENGINE: SIMULATION");
      badge.className = "engine-badge " + ((scannerCount || cfg.engine === "real") ? "real" : "sim");
      badge.title = scannerCount
        ? "Installed scanners run automatically and merge into one report"
        : (cfg.engine === "real" ? "Real HTTP workflow active" : "Simulation mode");
      var le = $("#landing-engine");
      if (le) le.textContent = scannerCount ? "MULTI-TOOL" : (cfg.engine === "real" ? "REAL" : "SIMULATION");

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
          OE_Sound.play("click");
        });
        grid.appendChild(el);
      });

      if (!$("#target-input").value) $("#target-input").value = (cfg.demo_targets || {}).easy || cfg.demo_target_url || "";
      $("#demo-open-note").textContent = "built-in target · 3 modes";
      syncDifficultyFromTarget();
      return cfg;
    });
  }

  // ------------------------------------------------------------- difficulty

  function targetMode(url) {
    if (!url) return null;
    if (url.indexOf("/demo/hardened") !== -1) return "hardened";
    if (url.indexOf("/demo/fortified") !== -1) return "fortified";
    if (url.indexOf("/demo") !== -1) return "easy";
    return null;
  }

  function syncDifficultyFromTarget() {
    var mode = targetMode($("#target-input").value);
    var box = $("#difficulty");
    $$(".diff", box).forEach(function (b) { b.classList.toggle("active", b.dataset.mode === mode); });
    box.classList.toggle("disabled", mode === null);
    if (mode) state.difficulty = mode;
  }

  function setDifficulty(mode) {
    var targets = (state.config && state.config.demo_targets) || {};
    if (targets[mode]) {
      $("#target-input").value = targets[mode];
      $("#target-input").classList.remove("invalid");
      $("#hud-target-label").innerHTML = "<b>" + escapeHtml(shortHost(targets[mode])) + "</b>";
      syncDifficultyFromTarget();
      pollDemoStats();
      toast("Target set to " + mode.toUpperCase() + " demo mode");
    }
  }

  // ----------------------------------------------------------------- attack

  function startAttack() {
    if (state.mode === "replay") exitReplay();

    var target = ($("#target-input").value || "").trim();
    if (!target) { toast("Enter a target URL first", true); $("#target-input").classList.add("invalid"); return; }
    $("#target-input").classList.remove("invalid");
    if (!/^https?:\/\//i.test(target)) target = "http://" + target;

    OE_Sound.play("launch");
    api("/api/attack/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target, preset: state.preset })
    }).then(function (run) {
      state.runId = run.run_id;
      state.running = true;
      state.logCursor = -1;
      state.eventCursor = -1;
      state.runStartLocal = Date.now();
      state.lastPhaseStates = {};
      state.receivedLogs = [];
      state.netEvents = [];
      state.netStats = { total: 0, errors: 0, sumMs: 0, def: 0 };
      state.lastCompletedRun = null;

      // reset UI
      $("#terminal").innerHTML = "";
      $("#terminal-count").textContent = "0";
      resetNetworkPanel();
      $$(".pcard").forEach(function (c) {
        c.className = "pcard";
        $(".pc-state", c).textContent = "PENDING";
        $(".pc-metric", c).innerHTML = "&nbsp;";
      });
      hideReplayBar();
      if (OE3D.available) {
        OE3D.console.resetPhases();
        OE3D.console.setRunning(true);
        OE3D.console.resetView();
        OE3D.console.setDirector(state.director);
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
    OE_Sound.play("abort");
    api("/api/attack/" + state.runId + "/cancel", { method: "POST" })
      .then(function () { toast("Abort requested — winding down…"); })
      .catch(function (e) { toast(e.message, true); });
  }

  // ------------------------------------------------------------------ polling

  function poll() {
    if (!state.runId || state.mode === "replay") return;
    api("/api/attack/" + state.runId + "/status?after=" + state.logCursor +
        "&after_event=" + state.eventCursor)
      .then(function (snap) {
        if (snap.run_id !== state.runId) return;

        state.runStartLocal = Date.now() - snap.elapsed_s * 1000;

        (snap.logs || []).forEach(appendLog);
        if (snap.log_total !== undefined) $("#terminal-count").textContent = snap.log_total;
        (snap.events || []).forEach(applyEvent);

        // phase states (drives cards + 3D + sounds)
        Object.keys(snap.phase_states || {}).forEach(function (key) {
          var st = snap.phase_states[key];
          if (state.lastPhaseStates[key] !== st) onPhaseTransition(key, st);
        });
        state.lastPhaseStates = snap.phase_states;

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
        state.lastCompletedRun = snap.run_id;
        $("#btn-attack").disabled = false;
        $("#btn-abort").classList.remove("show");
        if (OE3D.available) {
          OE3D.console.setRunning(false);
          if (state.director) OE3D.console.resetView();
        }

        if (snap.status === "complete") {
          setPill("done", "COMPLETE");
          setHudStatus("ok", "COMPLETE");
          $("#hud-pct").innerHTML = "100<small>%</small>";
          $("#hud-bar-i").style.width = "100%";
          showReplayBar();
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

  function onPhaseTransition(key, phaseState) {
    updatePhaseCard(key, phaseState);
    if (OE3D.available) OE3D.console.setPhaseState(key, phaseState);
    var idx = PHASE_KEYS.indexOf(key);
    if (phaseState === "running") OE_Sound.play("phase", idx);
    else if (phaseState === "complete") OE_Sound.play("phaseDone");
    else if (phaseState === "failed") OE_Sound.play("fail");
  }

  function applyEvent(ev) {
    if (ev.seq !== undefined && ev.seq > state.eventCursor) state.eventCursor = ev.seq;
    if (ev.kind === "request") {
      if (state.mode === "live") addNetEvent(ev);
    }
  }

  function fetchReport(runId) {
    api("/api/attack/" + runId + "/report")
      .then(function (report) {
        if (report && report.summary && report.attack_chain) {
          if (report.verdict && report.verdict.indexOf("DENIED") !== -1) OE_Sound.play("held");
          else OE_Sound.play("complete");
          openReport(report);
        }
      })
      .catch(function () { /* no report (aborted/failed early) */ });
  }

  // ------------------------------------------------------------------- logs

  function appendLog(entry) {
    if (entry.i <= state.logCursor) return;
    state.logCursor = entry.i;
    state.receivedLogs.push(entry);
    if (state.receivedLogs.length > 800) state.receivedLogs = state.receivedLogs.slice(-800);
    renderLogRow(entry);
  }

  function renderLogRow(entry) {
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
    var stick = term.scrollTop + term.clientHeight >= term.scrollHeight - 50;
    term.appendChild(row);
    while (term.children.length > 420) term.removeChild(term.firstChild);
    if (stick) term.scrollTop = term.scrollHeight;
  }

  // ------------------------------------------------------------ network panel

  function addNetEvent(ev) {
    state.netEvents.push(ev);
    if (state.netEvents.length > 1200) state.netEvents = state.netEvents.slice(-1200);
    var s = state.netStats;
    s.total++;
    if (ev.status >= 400 || ev.status === 0) s.errors++;
    s.sumMs += (ev.ms || 0);
    if (ev.defense) s.def++;
    if (netRowMatchesFilter(ev)) renderNetRow(ev);
    updateNetStats();
  }

  function netRowMatchesFilter(ev) {
    var f = state.netFilter;
    if (f === "all") return true;
    if (f === "def") return !!ev.defense;
    if (f === "2xx") return ev.status >= 200 && ev.status < 300;
    if (f === "4xx") return ev.status >= 400 && ev.status < 500;
    return true;
  }

  function renderNetRow(ev) {
    var table = $("#net-table");
    var empty = $(".net-empty", table);
    if (empty) empty.remove();
    var row = document.createElement("div");
    row.className = "net-row" + (ev.defense ? " def" : "");
    var cls = ev.status >= 200 && ev.status < 300 ? "s2" :
              ev.status >= 300 && ev.status < 400 ? "s3" :
              ev.status >= 400 && ev.status < 500 ? "s4" : "s5";
    row.innerHTML =
      '<span class="m ' + escapeHtml(ev.method) + '">' + escapeHtml(ev.method) + '</span>' +
      '<span class="p" title="' + escapeHtml(ev.path) + (ev.defense ? "  [🛡 " + escapeHtml(ev.defense) + "]" : "") + '">' +
        escapeHtml(ev.path) + (ev.defense ? '  <span style="color:#fbbf24">🛡' + escapeHtml(ev.defense) + '</span>' : "") + '</span>' +
      '<span class="s ' + cls + '">' + (ev.status || "ERR") + '</span>' +
      '<span class="ms">' + Math.round(ev.ms || 0) + 'ms</span>';
    table.appendChild(row);
    while (table.children.length > 400) table.removeChild(table.firstChild);
    table.scrollTop = table.scrollHeight;
  }

  function updateNetStats() {
    var s = state.netStats;
    $("#ns-total").textContent = s.total;
    $("#ns-errors").textContent = s.errors;
    $("#ns-avg").textContent = s.total ? Math.round(s.sumMs / s.total) : 0;
    $("#ns-def").textContent = s.def;
    $("#net-count").textContent = s.total;
  }

  function resetNetworkPanel() {
    $("#net-table").innerHTML = '<div class="net-empty">no traffic yet — requests stream here during a run</div>';
    state.netStats = { total: 0, errors: 0, sumMs: 0, def: 0 };
    updateNetStats();
  }

  function rebuildNetworkPanel() {
    $("#net-table").innerHTML = "";
    var shown = 0;
    state.netEvents.forEach(function (ev) {
      if (netRowMatchesFilter(ev) && shown < 400) { renderNetRow(ev); shown++; }
    });
    if (!shown) $("#net-table").innerHTML = '<div class="net-empty">no traffic matches this filter</div>';
    updateNetStats();
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

  function setLiveChip(mode) {
    var chip = $("#hud-livechip");
    if (mode === "replay") { chip.textContent = "REPLAY"; chip.classList.add("replay"); }
    else { chip.textContent = "LIVE"; chip.classList.remove("replay"); }
  }

  // ------------------------------------------------------------------ replay

  function showReplayBar() {
    $("#replay-bar").classList.remove("hidden");
  }
  function hideReplayBar() {
    $("#replay-bar").classList.add("hidden");
  }

  function enterReplay() {
    if (!state.lastCompletedRun && !state.runId) { toast("No completed run to replay yet"); return; }
    var runId = state.lastCompletedRun || state.runId;
    api("/api/attack/" + runId + "/status?after=-1&after_event=-1&report=1")
      .then(function (snap) {
        if (!snap.events || !snap.events.length) { toast("No recorded events for this run"); return; }
        var logs = (snap.logs || []).slice().sort(function (a, b) { return a.t - b.t; });
        var events = snap.events.slice();
        var tStart = snap.started_at || (logs.length ? logs[0].t : events[0].t);
        var tEnd = snap.finished_at || (events.length ? events[events.length - 1].t : tStart + 1);
        if (tEnd <= tStart) tEnd = tStart + 1;

        state.mode = "replay";
        state.replay = {
          runId: runId,
          logs: logs, events: events,
          tStart: tStart, tEnd: tEnd,
          playT: tStart, speed: 1, playing: false,
          logPtr: 0, evPtr: 0,
          handle: null
        };
        // reset view surfaces
        $("#terminal").innerHTML = "";
        $("#terminal-count").textContent = snap.log_total || logs.length;
        resetNetworkPanel();
        $$(".pcard").forEach(function (c) {
          c.className = "pcard";
          $(".pc-state", c).textContent = "PENDING";
          $(".pc-metric", c).innerHTML = "&nbsp;";
        });
        if (OE3D.available) OE3D.console.resetPhases();
        setPill("running", "REPLAY · " + runId);
        setLiveChip("replay");
        showReplayBar();
        $("#replay-slider").value = 0;
        $("#replay-time").textContent = "0.0s";
        setReplayPlayIcon(false);
        rebuildReplayTo(state.replay.playT);
        replayPlay(true);
        OE_Sound.play("replay");
        switchTab("terminal");
      })
      .catch(function (e) { toast("Replay failed: " + e.message, true); });
  }

  function setReplayPlayIcon(playing) {
    $("#replay-play").textContent = playing ? "⏸" : "⏵";
  }

  function replayPlay(force) {
    var r = state.replay;
    if (!r) return;
    r.playing = (force === true) ? true : !r.playing;
    setReplayPlayIcon(r.playing);
    if (r.handle) { clearInterval(r.handle); r.handle = null; }
    if (r.playing) {
      r.handle = setInterval(function () {
        var r2 = state.replay;
        if (!r2) return;
        r2.playT += 0.1 * r2.speed;
        if (r2.playT >= r2.tEnd) {
          r2.playT = r2.tEnd;
          replayPlay(false);
        }
        advanceReplay(r2.playT);
        syncReplayUI();
      }, 100);
    }
  }

  // incremental advance (fast path while playing)
  function advanceReplay(playT) {
    var r = state.replay;
    if (!r) return;
    while (r.logPtr < r.logs.length && r.logs[r.logPtr].t <= playT) {
      renderLogRow(r.logs[r.logPtr]); r.logPtr++;
    }
    while (r.evPtr < r.events.length && r.events[r.evPtr].t <= playT) {
      var ev = r.events[r.evPtr]; r.evPtr++;
      if (ev.kind === "request") addNetEvent(ev);
      else if (ev.kind === "phase" && ev.state) {
        updatePhaseCard(ev.phase, ev.state);
        if (OE3D.available) OE3D.console.setPhaseState(ev.phase, ev.state);
        if (ev.state === "complete") OE_Sound.play("phaseDone");
      }
    }
    // HUD progress from phase states seen so far
    var phasesDone = 0;
    $$(".pc-state").forEach(function (e) {
      var t = e.textContent;
      if (t === "COMPLETE" || t === "FAILED" || t === "SKIPPED") phasesDone++;
    });
    var pct = Math.round(phasesDone / 6 * 100);
    $("#hud-pct").innerHTML = pct + "<small>%</small>";
    $("#hud-bar-i").style.width = pct + "%";
  }

  // full rebuild (scrub jump)
  function rebuildReplayTo(playT) {
    var r = state.replay;
    if (!r) return;
    $("#terminal").innerHTML = "";
    resetNetworkPanel();
    $$(".pcard").forEach(function (c) {
      c.className = "pcard";
      $(".pc-state", c).textContent = "PENDING";
      $(".pc-metric", c).innerHTML = "&nbsp;";
    });
    if (OE3D.available) OE3D.console.resetPhases();
    r.logPtr = 0; r.evPtr = 0;
    advanceReplay(playT);
  }

  function syncReplayUI() {
    var r = state.replay;
    if (!r) return;
    var k = Math.max(0, Math.min(1, (r.playT - r.tStart) / (r.tEnd - r.tStart)));
    $("#replay-slider").value = Math.round(k * 1000);
    $("#replay-time").textContent = (r.playT - r.tStart).toFixed(1) + "s";
  }

  function exitReplay() {
    var r = state.replay;
    if (!r) return;
    if (r.handle) clearInterval(r.handle);
    state.replay = null;
    state.mode = "live";
    setLiveChip("live");
    hideReplayBar();

    // restore the live final state of the last run
    $("#terminal").innerHTML = "";
    state.receivedLogs.slice(-420).forEach(renderLogRow);
    var term = $("#terminal");
    term.scrollTop = term.scrollHeight;
    rebuildNetworkPanel();
    Object.keys(state.lastPhaseStates).forEach(function (key) {
      updatePhaseCard(key, state.lastPhaseStates[key]);
      if (OE3D.available) OE3D.console.setPhaseState(key, state.lastPhaseStates[key]);
    });
    setPill("done", "COMPLETE");
    setHudStatus("ok", "COMPLETE");
    $("#hud-pct").innerHTML = "100<small>%</small>";
    $("#hud-bar-i").style.width = "100%";
  }

  // ------------------------------------------------------------------ modal

  function openReport(report) {
    fillPhaseMetrics(report);
    var s = report.summary || {};
    var modal = $("#modal-backdrop");
    $("#modal-run").textContent = "run " + (report.run_id || "—") + " · post-mission assessment";

    var sev = s.severity || "Low";
    $("#rep-sev").textContent = "SEVERITY: " + sev.toUpperCase();
    $("#rep-sev").className = "sev-chip sev-" + sev;
    $("#rep-verdict").textContent = report.verdict || "";
    $("#rep-v-target").textContent = report.target;
    $("#rep-v-run").textContent = report.run_id;
    var engineText = report.engine === "real" ? "real HTTP workflow" :
      (report.engine === "zap-baseline" ? "OWASP ZAP baseline" : "simulation");
    if ((report.tools_run || []).length) engineText += " + " + report.tools_run.join(", ");
    $("#rep-v-engine").textContent = engineText;
    $("#rep-v-time").textContent = (report.total_time_seconds || 0).toFixed(2) + "s · " +
      new Date(report.timestamp || Date.now()).toLocaleString();

    // success ring
    var isZap = report.engine === "zap-baseline";
    var pct = parseFloat(s.attack_success_rate) || 0;
    var C = 2 * Math.PI * 48;
    var arc = $("#ring-arc");
    arc.style.strokeDasharray = C.toFixed(1);
    arc.style.strokeDashoffset = C.toFixed(1);
    $("#ring-num").textContent = isZap ? "0" : "0%";
    $("#ring-cap").textContent = isZap ? "ALERTS FOUND" : "CHAIN SUCCESS";
    setTimeout(function () {
      arc.style.strokeDashoffset = isZap ? (s.alerts_total ? 0 : C.toFixed(1)) : (C * (1 - pct / 100)).toFixed(1);
    }, 80);
    countUp($("#ring-num"), isZap ? (s.alerts_total || 0) : pct,
      { dec: 0, suffix: isZap ? "" : "%", dur: 1100 });

    // chain + MITRE chips
    var mitre = (state.config && state.config.mitre) || report.mitre || {};
    var icons = { phase_1_recon: "◉", phase_2_exploit: "⚡", phase_3_persistence: "🔓",
                  phase_4_lateral_movement: "⇄", phase_5_exfiltration: "▤", phase_6_cover_tracks: "☄" };
    var timings = report.phase_timings || {};
    var tkeys = ["recon", "exploit", "persistence", "lateral_movement", "exfiltration", "cover_tracks"];
    var chainBox = $("#rep-chain");
    chainBox.innerHTML = "";
    Object.keys(report.attack_chain || {}).forEach(function (k, idx) {
      var ok = report.attack_chain[k];
      var row = document.createElement("div");
      var t = timings[tkeys[idx]];
      var cls = ok ? "ok" : (t !== undefined && t > 0 ? "bad" : "skip");
      var phaseKey = CHAIN_KEY_TO_PHASE[k];
      var chips = "";
      (mitre[phaseKey] || []).forEach(function (tech) {
        chips += '<a class="mchip" target="_blank" rel="noopener" title="' + escapeHtml(tech.name) +
                 '" href="https://attack.mitre.org/techniques/' + escapeHtml(tech.id.replace(/\./g, "/")) + '/">' +
                 escapeHtml(tech.id) + "</a>";
      });
      row.className = "chain-row " + cls;
      row.innerHTML =
        '<span class="c-ico">' + icons[k] + '</span>' +
        '<span class="c-name">' + PHASE_NAMES[phaseKey] + '</span>' +
        '<span class="c-mitre">' + chips + '</span>' +
        '<span class="c-time">' + (ok ? (t !== undefined ? t.toFixed(2) + "s" : "✓") : (cls === "skip" ? "skipped" : "failed")) + '</span>';
      chainBox.appendChild(row);
    });

    // defense posture
    var defense = report.defense || {};
    if (defense.total_blocks) {
      $("#rep-defense-section").style.display = "";
      $("#rep-defense-note").textContent =
        defense.total_blocks + " attack requests were blocked by target defenses.";
      var chips2 = "";
      Object.keys(defense.by_type || {}).forEach(function (k2) {
        chips2 += '<span class="dchip">' + escapeHtml(k2) + " × " + defense.by_type[k2] + "</span>";
      });
      $("#rep-defense-chips").innerHTML = chips2;
    } else {
      $("#rep-defense-section").style.display = "none";
    }

    // findings
    var fl = $("#rep-findings");
    fl.innerHTML = "";
    (s.key_findings || []).forEach(function (f) {
      var li = document.createElement("li");
      li.textContent = f;
      fl.appendChild(li);
    });

    // recommendations
    var recBox = $("#rep-recs");
    recBox.innerHTML = "";
    (report.recommendations || []).forEach(function (r) {
      var d = document.createElement("div");
      d.className = "rec";
      d.innerHTML =
        '<div class="rec-head">' +
        '<span class="rec-pr ' + escapeHtml(r.priority) + '">' + escapeHtml((r.priority || "").toUpperCase()) + "</span>" +
        '<span class="rec-area">' + escapeHtml(r.area) + "</span>" +
        '<span class="rec-title">' + escapeHtml(r.title) + "</span></div>" +
        '<div class="rec-fix">' + escapeHtml(r.fix) + "</div>";
      recBox.appendChild(d);
    });

    // tiles (with count-ups)
    var rr = report.recon_results || {}, er = report.exploit_results || {},
        pr = report.persistence_results || {}, lr = report.lateral_movement_results || {},
        xr = report.exfiltration_results || {}, cr = report.cover_tracks_results || {};
    var tiles;
    if (report.engine === "zap-baseline") {
      var risks = s.alerts_by_risk || {};
      tiles = [
        [s.alerts_total || 0, "alerts"],
        [risks.High || 0, "high"],
        [risks.Medium || 0, "medium"],
        [risks.Low || 0, "low"],
        [risks.Informational || 0, "informational"],
        [rr.endpoints_discovered || 0, "affected URLs"],
        ["baseline", "scan type"],
        [(report.total_time_seconds || 0).toFixed(1) + "s", "duration"]
      ];
    } else {
      tiles = [
        [rr.endpoints_discovered || 0, "endpoints"],
        [s.scanner_findings || 0, "scanner findings"],
        [(er.methods || []).length, "exploits"],
        [pr.backdoors_installed || 0, "backdoors"],
        [lr.credentials_extracted || 0, "credentials"],
        [xr.records_stolen || 0, "records stolen"],
        [(xr.data_exfiltrated_mb || 0).toFixed(2) + " MB", "exfiltrated"],
        [cr.logs_deleted || 0, "logs deleted"],
        [(report.total_time_seconds || 0).toFixed(1) + "s", "duration"]
      ];
    }
    var tileBox = $("#rep-tiles");
    tileBox.innerHTML = "";
    tiles.forEach(function (t) {
      var d = document.createElement("div");
      d.className = "tile";
      d.innerHTML = '<div class="v">0</div><div class="k">' + t[1] + "</div>";
      tileBox.appendChild(d);
      var v = d.querySelector(".v");
      if (typeof t[0] === "number") countUp(v, t[0], {});
      else v.textContent = t[0];
    });

    // action links
    $("#rep-dl-html").href = "/api/attack/" + report.run_id + "/report.html";
    $("#rep-dl-json").href = "/api/attack/" + report.run_id + "/report.json";
    $("#rep-print").href = "/api/attack/" + report.run_id + "/report.html?print=1";
    state.lastCompletedRun = report.run_id;

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
        item.title = r.target + (r.archived ? " (archived)" : "");
        var sevTxt = r.severity ? " · " + r.severity : "";
        item.innerHTML =
          '<span class="h-dot ' + r.status + '"></span>' +
          '<span class="h-id">' + r.run_id + "</span>" +
          '<span class="h-meta">' + r.preset + sevTxt + "</span>";
        item.addEventListener("click", function () {
          if (r.status === "complete") {
            api("/api/attack/" + r.run_id + "/report").then(function (rep) {
              state.lastCompletedRun = r.run_id;
              openReport(rep);
              showReplayBar();
            }).catch(function () { toast("No report available", true); });
          } else {
            toast("Run " + r.run_id + " — " + r.status);
          }
        });
        box.appendChild(item);
      });
    }).catch(function () {});
  }

  // ---------------------------------------------------------------- archive

  function openArchive() {
    state.archiveSel = [];
    renderCompare();
    $("#btn-compare").disabled = true;
    api("/api/attack/list").then(function (data) {
      var table = $("#archive-table");
      table.innerHTML =
        '<div class="arch-headrow"><span></span><span>RUN</span><span>TARGET</span>' +
        "<span>PROFILE</span><span>SEVERITY</span><span>CHAIN</span><span>WHEN</span></div>";
      var runs = (data.runs || []).filter(function (r) { return r.status === "complete"; });
      if (!runs.length) {
        table.innerHTML += '<div class="net-empty">no completed runs yet</div>';
      }
      runs.forEach(function (r) {
        var row = document.createElement("div");
        row.className = "arch-row";
        row.dataset.id = r.run_id;
        var chain = PHASE_KEYS.map(function (k) {
          var st = (r.phase_states || {})[k];
          return st === "complete" ? "✓" : st === "running" ? "◐" : "✗";
        }).join("");
        var d = new Date((r.created_at || 0) * 1000);
        row.innerHTML =
          '<span class="a-sel"></span>' +
          '<span class="a-id">' + r.run_id + "</span>" +
          '<span class="a-tgt" title="' + escapeHtml(r.target) + '">' + escapeHtml(shortHost(r.target)) + "</span>" +
          "<span>" + escapeHtml(r.preset) + "</span>" +
          '<span class="sev-mini ' + (r.severity || "none").toLowerCase() + '">' + (r.severity || "—") + "</span>" +
          '<span class="chain-mini">' + chain + "</span>" +
          '<span class="a-date">' + d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + "</span>";
        row.addEventListener("click", function () { toggleArchiveSel(r.run_id, row); });
        table.appendChild(row);
      });
      $("#archive-backdrop").classList.add("open");
    });
  }

  function toggleArchiveSel(id, rowEl) {
    var i = state.archiveSel.indexOf(id);
    if (i >= 0) { state.archiveSel.splice(i, 1); }
    else {
      state.archiveSel.push(id);
      if (state.archiveSel.length > 2) state.archiveSel.shift();
    }
    $$(".arch-row").forEach(function (r2) {
      r2.classList.toggle("sel1", r2.dataset.id === state.archiveSel[0]);
      r2.classList.toggle("sel2", r2.dataset.id === state.archiveSel[1]);
    });
    $("#btn-compare").disabled = state.archiveSel.length !== 2;
    if (state.archiveSel.length !== 2) renderCompare();
  }

  function renderCompare() {
    $("#archive-compare").classList.add("hidden");
    $("#archive-compare").innerHTML = "";
  }

  function runCompare() {
    if (state.archiveSel.length !== 2) return;
    var ids = state.archiveSel.slice();
    Promise.all(ids.map(function (id) {
      return Promise.all([
        api("/api/attack/" + id + "/report"),
        api("/api/attack/" + id + "/status")
      ]).then(function (pair) {
        pair[0].preset = pair[1].preset;
        pair[0].engineMode = pair[1].engine;
        return pair[0];
      });
    }))
      .then(function (reports) {
        var box = $("#archive-compare");
        var A = reports[0], B = reports[1];
        function g(r, path, dflt) {
          var cur = r;
          for (var i = 0; i < path.length; i++) { cur = (cur || {})[path[i]]; }
          return cur === undefined || cur === null ? dflt : cur;
        }
        var sevRank = { Low: 1, Medium: 2, High: 3, Critical: 4 };
        var rows = [
          ["Target", shortHost(A.target || ""), shortHost(B.target || ""), null],
          ["Profile", A.preset || "—", B.preset || "—", null],
          ["Severity", A.summary.severity, B.summary.severity,
            (sevRank[B.summary.severity] || 0) - (sevRank[A.summary.severity] || 0)],
          ["Chain success", A.summary.attack_success_rate, B.summary.attack_success_rate, null],
          ["Endpoints", g(A, ["recon_results", "endpoints_discovered"], 0), g(B, ["recon_results", "endpoints_discovered"], 0),
            g(A, ["recon_results", "endpoints_discovered"], 0) - g(B, ["recon_results", "endpoints_discovered"], 0)],
          ["Exploits", (g(A, ["exploit_results", "methods"], []) || []).length, (g(B, ["exploit_results", "methods"], []) || []).length,
            (g(A, ["exploit_results", "methods"], []) || []).length - (g(B, ["exploit_results", "methods"], []) || []).length],
          ["Backdoors", g(A, ["persistence_results", "backdoors_installed"], 0), g(B, ["persistence_results", "backdoors_installed"], 0),
            g(A, ["persistence_results", "backdoors_installed"], 0) - g(B, ["persistence_results", "backdoors_installed"], 0)],
          ["Credentials", g(A, ["lateral_movement_results", "credentials_extracted"], 0), g(B, ["lateral_movement_results", "credentials_extracted"], 0),
            g(A, ["lateral_movement_results", "credentials_extracted"], 0) - g(B, ["lateral_movement_results", "credentials_extracted"], 0)],
          ["Records stolen", g(A, ["exfiltration_results", "records_stolen"], 0), g(B, ["exfiltration_results", "records_stolen"], 0),
            g(A, ["exfiltration_results", "records_stolen"], 0) - g(B, ["exfiltration_results", "records_stolen"], 0)],
          ["Data exfiltrated", g(A, ["exfiltration_results", "data_exfiltrated_mb"], 0).toFixed(2) + " MB",
            g(B, ["exfiltration_results", "data_exfiltrated_mb"], 0).toFixed(2) + " MB", null],
          ["Logs deleted", g(A, ["cover_tracks_results", "logs_deleted"], 0), g(B, ["cover_tracks_results", "logs_deleted"], 0),
            g(A, ["cover_tracks_results", "logs_deleted"], 0) - g(B, ["cover_tracks_results", "logs_deleted"], 0)],
          ["Defense blocks", (A.defense || {}).total_blocks || 0, (B.defense || {}).total_blocks || 0,
            ((B.defense || {}).total_blocks || 0) - ((A.defense || {}).total_blocks || 0)],
          ["Duration", (A.total_time_seconds || 0).toFixed(1) + "s", (B.total_time_seconds || 0).toFixed(1) + "s", null]
        ];
        var html = '<div class="cmp-title">⇄ COMPARE — green means the second run is better defended</div>';
        html += '<div class="cmp-grid">';
        html += '<div class="h">METRIC</div><div class="h">A · ' + ids[0] + "</div><div class=\"h\">B · " + ids[1] + "</div>";
        rows.forEach(function (r) {
          var delta = r[3];
          var clsB = "";
          if (delta !== null && delta !== 0) clsB = delta > 0 ? "win" : "lose";
          html += '<div class="k">' + r[0] + "</div><div class=\"v\">" + escapeHtml(String(r[1])) +
                  '</div><div class="v ' + clsB + '">' + escapeHtml(String(r[2])) +
                  (delta ? ' <span style="opacity:.7">(' + (delta > 0 ? "+" : "") + delta + ")</span>" : "") + "</div>";
        });
        html += "</div>";
        box.innerHTML = html;
        box.classList.remove("hidden");
      })
      .catch(function (e) { toast("Compare failed: " + e.message, true); });
  }

  // ------------------------------------------------------------- demo stats

  function pollDemoStats() {
    var mode = targetMode($("#target-input").value);
    var el = $("#hud-reqs");
    if (!mode) { el.textContent = ""; return; }
    api("/api/demo/stats").then(function (s) {
      var m = s[mode] || {};
      var defenses = 0;
      Object.keys(m.defenses || {}).forEach(function (k) { defenses += m.defenses[k]; });
      el.innerHTML = "◂ <b>" + (m.requests || 0) + "</b> requests hit the demo target" +
        (defenses ? " · <b>" + defenses + "</b> 🛡 blocked" : "");
    }).catch(function () {});
  }

  // ------------------------------------------------------------------ tabs

  function switchTab(which) {
    var isTerm = which === "terminal";
    $("#tab-terminal").classList.toggle("active", isTerm);
    $("#tab-network").classList.toggle("active", !isTerm);
    $("#terminal-wrap").classList.toggle("hidden", !isTerm);
    $("#network-wrap").classList.toggle("hidden", isTerm);
  }

  // --------------------------------------------------------------- director

  function setDirector(on) {
    state.director = on;
    if (OE3D.available) OE3D.console.setDirector(on);
    var b = $("#btn-director");
    b.textContent = on ? "CAM: AUTO" : "CAM: MANUAL";
    b.classList.toggle("off", !on);
  }

  // --------------------------------------------------------------- mute btn

  function syncMuteButton() {
    $("#btn-mute").textContent = OE_Sound.isMuted() ? "♪ MUTED" : "♪ SOUND ON";
  }

  // ------------------------------------------------------------------- init

  function buildPhaseCards() {
    var grid = $("#phase-grid");
    grid.innerHTML = "";
    PHASE_KEYS.forEach(function (key, i) {
      var card = document.createElement("div");
      card.className = "pcard";
      card.dataset.phase = key;
      card.innerHTML =
        '<div class="pc-top">' +
        '<span class="pc-num">0' + (i + 1) + "</span>" +
        "<span class=\"pc-name\">" + PHASE_NAMES[key].toUpperCase() + "</span>" +
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
      $("#btn-director").style.display = "none";
    } else {
      OE3D.onHover = function (key, x, y) {
        var tip = $("#stage-tooltip");
        if (!key) { tip.style.display = "none"; return; }
        var stt = (state.mode === "replay")
          ? ($('.pcard[data-phase="' + key + '"] .pc-state') || { textContent: "PENDING" }).textContent.toLowerCase()
          : ((state.lastPhaseStates || {})[key] || "pending");
        tip.innerHTML =
          '<div class="tt-name">' + PHASE_NAMES[key] + "</div>" +
          '<div class="tt-state" style="color:' +
            ({ pending: "#7e8db3", running: "#22d3ee", complete: "#34d399", failed: "#f43f5e", skipped: "#55638a" }[stt] || "#7e8db3") +
            '">' + String(stt).toUpperCase() + "</div>" +
          '<div class="tt-desc">' + PHASE_DESCS[key] + "</div>";
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
      OE3D.onDirectorChange = function (on) {
        state.director = on;
        var b = $("#btn-director");
        b.textContent = on ? "CAM: AUTO" : "CAM: MANUAL";
        b.classList.toggle("off", !on);
      };
    }
    setDirector(true);

    // ---- sound unlock on first gesture
    document.addEventListener("pointerdown", function () { OE_Sound.unlock(); }, { once: true });
    syncMuteButton();

    // ---- routing
    if (location.hash === "#/console") {
      document.body.classList.add("in-console");
      $("#view-landing").classList.add("hidden");
      $("#view-console").classList.remove("hidden");
      if (OE3D.available) OE3D.active = OE3D.console;
      state._touredOnce = true;
    }
    window.addEventListener("hashchange", function () {
      var consoleHidden = $("#view-console").classList.contains("hidden");
      var landingHidden = $("#view-landing").classList.contains("hidden");
      if (location.hash === "#/console" && consoleHidden) showConsole(false);
      else if (location.hash !== "#/console" && landingHidden) showLanding();
    });

    // ---- wiring
    $("#cta-enter").addEventListener("click", function () { OE_Sound.play("click"); showConsole(false); });
    $("#btn-back").addEventListener("click", function () {
      if (state.running && !confirm("An attack is running — leave the console anyway?")) return;
      showLanding();
    });
    $("#btn-attack").addEventListener("click", startAttack);
    $("#btn-abort").addEventListener("click", abortAttack);
    $("#btn-demo").addEventListener("click", function () { setDifficulty(state.difficulty || "easy"); });
    $("#btn-mute").addEventListener("click", function () { OE_Sound.toggle(); syncMuteButton(); });
    $("#btn-help").addEventListener("click", function () { $("#help-backdrop").classList.add("open"); });
    $("#help-close").addEventListener("click", function () { $("#help-backdrop").classList.remove("open"); });
    $("#help-tour").addEventListener("click", function () {
      $("#help-backdrop").classList.remove("open");
      if (window.OE_Tour) OE_Tour.start(0);
    });
    $("#btn-director").addEventListener("click", function () { setDirector(!state.director); });

    // difficulty buttons
    $$("#difficulty .diff").forEach(function (b) {
      b.addEventListener("click", function () { OE_Sound.play("click"); setDifficulty(b.dataset.mode); });
    });

    // tabs
    $("#tab-terminal").addEventListener("click", function () { switchTab("terminal"); });
    $("#tab-network").addEventListener("click", function () { switchTab("network"); });
    $$(".nf").forEach(function (b) {
      b.addEventListener("click", function () {
        $$(".nf").forEach(function (x) { x.classList.remove("active"); });
        b.classList.add("active");
        state.netFilter = b.dataset.f;
        rebuildNetworkPanel();
      });
    });

    // target input
    $("#target-input").addEventListener("input", function () {
      $(this).classList.remove("invalid");
      syncDifficultyFromTarget();
    });
    $("#target-input").addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" && !state.running) startAttack();
    });

    // modal
    $("#modal-close").addEventListener("click", closeModal);
    $("#modal-backdrop").addEventListener("click", function (ev) {
      if (ev.target === this) closeModal();
    });
    $("#rep-again").addEventListener("click", function () { closeModal(); if (!state.running) startAttack(); });
    $("#rep-replay").addEventListener("click", function (ev) {
      ev.preventDefault();
      closeModal();
      enterReplay();
    });

    // archive
    $("#btn-archive").addEventListener("click", function (ev) { ev.preventDefault(); openArchive(); });
    $("#archive-close").addEventListener("click", function () { $("#archive-backdrop").classList.remove("open"); });
    $("#archive-backdrop").addEventListener("click", function (ev) {
      if (ev.target === this) $("#archive-backdrop").classList.remove("open");
    });
    $("#archive-clear").addEventListener("click", function () {
      state.archiveSel = [];
      $$(".arch-row").forEach(function (r2) { r2.classList.remove("sel1", "sel2"); });
      $("#btn-compare").disabled = true;
      renderCompare();
    });
    $("#btn-compare").addEventListener("click", runCompare);

    // replay transport
    $("#replay-play").addEventListener("click", function () { replayPlay(); });
    $("#replay-exit").addEventListener("click", exitReplay);
    $("#replay-speed").addEventListener("click", function () {
      var r = state.replay; if (!r) return;
      r.speed = (r.speed === 1 ? 2 : r.speed === 2 ? 4 : 1);
      this.textContent = r.speed + "×";
    });
    $("#replay-slider").addEventListener("input", function () {
      var r = state.replay; if (!r) return;
      var k = this.value / 1000;
      r.playT = r.tStart + k * (r.tEnd - r.tStart);
      rebuildReplayTo(r.playT);
      syncReplayUI();
    });

    // keyboard shortcuts
    document.addEventListener("keydown", function (ev) {
      var typing = ev.target && (ev.target.tagName === "INPUT" || ev.target.tagName === "TEXTAREA");
      if (ev.key === "Escape") {
        closeModal();
        $("#help-backdrop").classList.remove("open");
        $("#archive-backdrop").classList.remove("open");
        if (state.mode === "replay") exitReplay();
        return;
      }
      if (typing) return;
      if (ev.key === "Enter") {
        if (!$("#view-console").classList.contains("hidden") && !state.running &&
            !$("#modal-backdrop").classList.contains("open") && state.mode === "live") startAttack();
      } else if (ev.key >= "1" && ev.key <= "6") {
        if ($("#view-console").classList.contains("hidden")) return;
        var key = PHASE_KEYS[parseInt(ev.key, 10) - 1];
        if (OE3D.available) OE3D.console.focusPhase(key);
      } else if (ev.key === "d" || ev.key === "D") {
        setDirector(!state.director);
      } else if (ev.key === "r" || ev.key === "R") {
        if (state.mode === "replay") exitReplay();
        else if (!state.running) enterReplay();
      } else if (ev.key === "m" || ev.key === "M") {
        OE_Sound.toggle(); syncMuteButton();
      } else if (ev.key === "?") {
        $("#help-backdrop").classList.add("open");
      }
    });

    // timers
    state.tickHandle = setInterval(function () {
      if (state.running && state.runStartLocal && state.mode === "live") {
        $("#hud-elapsed").textContent = "⏱ " + fmtElapsed((Date.now() - state.runStartLocal) / 1000);
      }
    }, 500);
    state.demoHandle = setInterval(pollDemoStats, 1500);

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
