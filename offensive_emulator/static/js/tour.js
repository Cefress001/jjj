/* ============================================================================
   OFFENSIVE EMULATOR v4 — onboarding spotlight tour
   A dimmed overlay with a cut-out that highlights real UI elements.
   Auto-runs on the first console visit (localStorage flag); restartable.
   ============================================================================ */
(function () {
  "use strict";

  var STEPS = [
    {
      sel: "#target-input",
      title: "1 · Pick your target",
      body: "The built-in demo app is pre-filled. Switch difficulty with EASY / HARDENED / FORTIFIED, or type any target you own.",
      position: "right"
    },
    {
      sel: "#preset-grid",
      title: "2 · Choose a profile",
      body: "Stealth is slow and quiet. Maximum is a firehose. Balanced is recommended for a first run.",
      position: "right"
    },
    {
      sel: "#btn-attack",
      title: "3 · Initiate the attack",
      body: "Six phases fire in sequence — recon, exploit, persistence, lateral movement, exfiltration, cover tracks. Press Enter anytime.",
      position: "right"
    },
    {
      sel: "#stage",
      title: "4 · Watch the kill chain",
      body: "Drag to orbit, scroll to zoom, click a node to focus. The director camera follows the live phase — press D to toggle it.",
      position: "left"
    },
    {
      sel: "#tab-network",
      title: "5 · Inspect the traffic",
      body: "Every request the engines fire streams here — method, path, status, latency — plus every defense the target threw back.",
      position: "left"
    },
    {
      sel: "#terminal-wrap",
      title: "6 · Read the aftermath",
      body: "Live engine logs, then a full threat report with MITRE mapping and remediation advice. Replay any run with R. Press ? for shortcuts.",
      position: "left"
    }
  ];

  var state = { idx: 0, active: false, nodes: null };

  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }

  function build() {
    if (state.nodes) return;
    var root = el("div", "tour-root");
    root.innerHTML =
      '<div class="tour-shade"></div>' +
      '<div class="tour-spotlight"></div>' +
      '<div class="tour-card">' +
      '  <div class="tour-step"><span class="tour-n"></span> / ' + STEPS.length + '</div>' +
      '  <h3 class="tour-title"></h3>' +
      '  <p class="tour-body"></p>' +
      '  <div class="tour-actions">' +
      '    <button class="tour-skip">SKIP TOUR</button>' +
      '    <button class="tour-back">BACK</button>' +
      '    <button class="tour-next">NEXT ▸</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(root);
    state.nodes = {
      root: root,
      shade: root.querySelector(".tour-shade"),
      spot: root.querySelector(".tour-spotlight"),
      card: root.querySelector(".tour-card"),
      n: root.querySelector(".tour-n"),
      title: root.querySelector(".tour-title"),
      body: root.querySelector(".tour-body"),
      next: root.querySelector(".tour-next"),
      back: root.querySelector(".tour-back"),
      skip: root.querySelector(".tour-skip")
    };
    state.nodes.next.addEventListener("click", function () { OE_Sound.play("click"); next(); });
    state.nodes.back.addEventListener("click", function () { OE_Sound.play("click"); back(); });
    state.nodes.skip.addEventListener("click", function () { OE_Sound.play("click"); stop(true); });
    window.addEventListener("resize", function () { if (state.active) position(); });
  }

  function position() {
    var step = STEPS[state.idx];
    var target = document.querySelector(step.sel);
    if (!target || !state.nodes) { stop(true); return; }
    var r = target.getBoundingClientRect();
    var pad = 10;

    state.nodes.spot.style.left = (r.left - pad) + "px";
    state.nodes.spot.style.top = (r.top - pad) + "px";
    state.nodes.spot.style.width = (r.width + pad * 2) + "px";
    state.nodes.spot.style.height = (r.height + pad * 2) + "px";

    state.nodes.n.textContent = (state.idx + 1);
    state.nodes.title.textContent = step.title;
    state.nodes.body.textContent = step.body;

    // place the card beside the target, flipping to fit the viewport
    var card = state.nodes.card;
    var cw = Math.min(320, window.innerWidth - 32);
    card.style.width = cw + "px";
    var cy = Math.min(Math.max(16, r.top + r.height / 2 - 90), window.innerHeight - 240);
    card.style.top = cy + "px";
    if (step.position === "left" && r.left - cw - 40 > 16) {
      card.style.left = (r.left - cw - 28) + "px";
      card.style.right = "auto";
    } else if (r.right + cw + 40 < window.innerWidth) {
      card.style.left = (r.right + 28) + "px";
      card.style.right = "auto";
    } else {
      card.style.left = "auto";
      card.style.right = "16px";
    }

    state.nodes.back.style.visibility = state.idx === 0 ? "hidden" : "visible";
    state.nodes.next.textContent = state.idx === STEPS.length - 1 ? "DONE ✓" : "NEXT ▸";
  }

  function next() {
    if (state.idx >= STEPS.length - 1) { stop(true); return; }
    state.idx++;
    position();
  }

  function back() {
    if (state.idx > 0) { state.idx--; position(); }
  }

  function start(atStep) {
    build();
    state.idx = atStep || 0;
    state.active = true;
    state.nodes.root.classList.add("open");
    position();
  }

  function stop(markSeen) {
    if (!state.nodes) return;
    state.active = false;
    state.nodes.root.classList.remove("open");
    if (markSeen) {
      try { window.localStorage.setItem("oe_toured", "1"); } catch (e) {}
    }
  }

  window.OE_Tour = {
    start: start,
    stop: stop,
    maybeStart: function () {
      var seen = false;
      try { seen = window.localStorage.getItem("oe_toured") === "1"; } catch (e) {}
      if (!seen) start(0);
    },
    isActive: function () { return state.active; }
  };
})();
