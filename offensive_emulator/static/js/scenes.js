/* ============================================================================
   OFFENSIVE EMULATOR v4 — 3D scenes (Three.js r97, vendored)
   ----------------------------------------------------------------------------
   One WebGL renderer, two scenes:
     • LandingScene   — rotating attack core, orbiting phase nodes, starfield
     • ConsoleScene   — interactive 3D kill-chain (orbit / zoom / hover / click)
   Plus the cinematic warp transition between them.
   ============================================================================ */
(function () {
  "use strict";

  var PHASES = [
    { key: "recon",            num: "01", name: "RECON" },
    { key: "exploit",          num: "02", name: "EXPLOIT" },
    { key: "persistence",      num: "03", name: "PERSIST" },
    { key: "lateral_movement", num: "04", name: "LATERAL" },
    { key: "exfiltration",     num: "05", name: "EXFIL" },
    { key: "cover_tracks",     num: "06", name: "COVER" }
  ];

  var STATE_COLORS = {
    pending:  0x3d4e74,
    running:  0x22d3ee,
    complete: 0x34d399,
    failed:   0xf43f5e,
    skipped:  0x47536b
  };

  function lerp(a, b, t) { return a + (b - a) * t; }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  function easeInCubic(t) { return t * t * t; }
  function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

  // ------------------------------------------------------------- textures

  function glowTexture() {
    var c = document.createElement("canvas");
    c.width = c.height = 128;
    var ctx = c.getContext("2d");
    var g = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
    g.addColorStop(0, "rgba(255,255,255,1)");
    g.addColorStop(0.25, "rgba(255,255,255,.55)");
    g.addColorStop(0.55, "rgba(255,255,255,.16)");
    g.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, 128, 128);
    return new THREE.CanvasTexture(c);
  }

  function labelTexture(text, opts) {
    opts = opts || {};
    var fontSize = opts.fontSize || 58;
    var pad = 24;
    var c = document.createElement("canvas");
    var ctx = c.getContext("2d");
    var font = "700 " + fontSize + "px " + (opts.font || "'Rajdhani','Segoe UI',sans-serif");
    ctx.font = font;
    var w = Math.ceil(ctx.measureText(text).width) + pad * 2;
    var h = Math.ceil(fontSize * 1.35);
    c.width = Math.max(w, 8);
    c.height = h;
    ctx = c.getContext("2d");
    ctx.font = font;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    if (opts.glow !== false) {
      ctx.shadowColor = opts.glowColor || "rgba(103,232,249,.85)";
      ctx.shadowBlur = 18;
    }
    ctx.fillStyle = opts.color || "#dff3ff";
    ctx.fillText(text, c.width / 2, c.height / 2 + fontSize * 0.05);
    var tex = new THREE.CanvasTexture(c);
    tex.minFilter = THREE.LinearFilter;
    return { texture: tex, aspect: c.width / c.height };
  }

  function makeLabel(text, worldH, opts) {
    var lt = labelTexture(text, opts);
    var mat = new THREE.SpriteMaterial({ map: lt.texture, transparent: true, depthWrite: false });
    var spr = new THREE.Sprite(mat);
    spr.scale.set(worldH * lt.aspect, worldH, 1);
    return spr;
  }

  // ------------------------------------------------------------- shared bg

  function makeStars(count, spread, size, color, opacity) {
    var geo = new THREE.BufferGeometry();
    var arr = new Float32Array(count * 3);
    for (var i = 0; i < count; i++) {
      var r = spread * (0.35 + Math.random() * 0.65);
      var th = Math.random() * Math.PI * 2;
      var ph = Math.acos(2 * Math.random() - 1);
      arr[i * 3] = r * Math.sin(ph) * Math.cos(th);
      arr[i * 3 + 1] = r * Math.cos(ph) * 0.6;
      arr[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
    }
    geo.addAttribute("position", new THREE.Float32BufferAttribute(arr, 3));
    var mat = new THREE.PointsMaterial({
      color: color, size: size, sizeAttenuation: true,
      transparent: true, opacity: opacity,
      blending: THREE.AdditiveBlending, depthWrite: false
    });
    return new THREE.Points(geo, mat);
  }

  function makeGrid() {
    var grid = new THREE.GridHelper(90, 56, 0x14365c, 0x0b1e38);
    grid.position.y = -4.8;
    grid.material.transparent = true;
    grid.material.opacity = 0.3;
    return grid;
  }

  // ============================================================================
  // Landing scene
  // ============================================================================

  function LandingScene() {
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x04070f, 0.024);
    this.camera = new THREE.PerspectiveCamera(62, 1, 0.1, 200);
    this.camera.position.set(0, 0.7, 9.4);
    this.camera.lookAt(0, 0, 0);

    this.root = new THREE.Group();
    this.scene.add(this.root);

    // background
    this.starsA = makeStars(1900, 46, 0.14, 0x9fd8ff, 0.75);
    this.starsB = makeStars(260, 46, 0.34, 0x67e8f9, 0.9);
    this.scene.add(this.starsA);
    this.scene.add(this.starsB);
    this.root.add(makeGrid());

    // ---- central core
    var outer = new THREE.LineSegments(
      new THREE.WireframeGeometry(new THREE.IcosahedronBufferGeometry(2.35, 1)),
      new THREE.LineBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.42 })
    );
    var mid = new THREE.LineSegments(
      new THREE.WireframeGeometry(new THREE.IcosahedronBufferGeometry(1.45, 0)),
      new THREE.LineBasicMaterial({ color: 0x2dd4bf, transparent: true, opacity: 0.34 })
    );
    this.nucleus = new THREE.Mesh(
      new THREE.SphereBufferGeometry(0.6, 26, 26),
      new THREE.MeshBasicMaterial({ color: 0xf43f5e })
    );
    this.nucleusGlow = new THREE.Sprite(new THREE.SpriteMaterial({
      map: SM.glow, color: 0xf43f5e, transparent: true, opacity: 0.85,
      blending: THREE.AdditiveBlending, depthWrite: false
    }));
    this.nucleusGlow.scale.set(3.4, 3.4, 1);

    this.core = new THREE.Group();
    this.core.add(outer, mid, this.nucleus, this.nucleusGlow);
    this.root.add(this.core);
    this.coreOuter = outer;
    this.coreMid = mid;

    // ---- orbiting phase nodes on three tilted rings
    this.orbits = [];
    var ringDefs = [
      { r: 3.3, tilt: 0.42, spin: 0.16, color: 0x22d3ee },
      { r: 4.0, tilt: -0.55, spin: -0.11, color: 0xa78bfa },
      { r: 4.7, tilt: 0.95, spin: 0.08, color: 0x2dd4bf }
    ];
    var nodeIdx = 0;
    var nodeColors = [0x22d3ee, 0xf43f5e, 0x2dd4bf, 0xa78bfa, 0xfbbf24, 0x67e8f9];
    for (var ri = 0; ri < ringDefs.length; ri++) {
      var def = ringDefs[ri];
      var ringGroup = new THREE.Group();
      ringGroup.rotation.x = def.tilt;

      // ring line
      var pts = [];
      for (var a = 0; a <= 64; a++) {
        var ang = (a / 64) * Math.PI * 2;
        pts.push(new THREE.Vector3(Math.cos(ang) * def.r, 0, Math.sin(ang) * def.r));
      }
      var ringGeo = new THREE.BufferGeometry().setFromPoints(pts);
      var ring = new THREE.Line(ringGeo, new THREE.LineBasicMaterial({
        color: def.color, transparent: true, opacity: 0.16
      }));
      ringGroup.add(ring);

      // two nodes per ring
      for (var n = 0; n < 2; n++) {
        var col = nodeColors[nodeIdx % nodeColors.length];
        var node = new THREE.Group();
        var body = new THREE.Mesh(
          new THREE.IcosahedronBufferGeometry(0.17, 0),
          new THREE.MeshBasicMaterial({ color: col })
        );
        var glow = new THREE.Sprite(new THREE.SpriteMaterial({
          map: SM.glow, color: col, transparent: true, opacity: 0.8,
          blending: THREE.AdditiveBlending, depthWrite: false
        }));
        glow.scale.set(1.15, 1.15, 1);
        var lab = makeLabel(PHASES[nodeIdx].num + " " + PHASES[nodeIdx].name, 0.30,
          { fontSize: 46, glowColor: "rgba(103,232,249,.55)" });
        lab.position.set(0, 0.52, 0);
        node.add(body, glow, lab);
        var ang2 = (n / 2) * Math.PI * 2 + ri * 1.1;
        node.position.set(Math.cos(ang2) * def.r, 0, Math.sin(ang2) * def.r);
        node.userData.phaseKey = PHASES[nodeIdx].key;
        ringGroup.add(node);
        nodeIdx++;
      }

      this.root.add(ringGroup);
      this.orbits.push({ group: ringGroup, spin: def.spin });
    }

    // parallax
    this.parX = 0; this.parY = 0;
    this._mx = 0; this._my = 0;

    this.time = 0;
  }

  LandingScene.prototype.update = function (dt) {
    this.time += dt;
    var t = this.time;

    this.coreOuter.rotation.y += dt * 0.12;
    this.coreOuter.rotation.x = Math.sin(t * 0.18) * 0.16;
    this.coreMid.rotation.y -= dt * 0.3;
    this.coreMid.rotation.z += dt * 0.1;

    var pulse = 1 + Math.sin(t * 2.1) * 0.07;
    this.nucleus.scale.set(pulse, pulse, pulse);
    this.nucleusGlow.material.opacity = 0.6 + Math.sin(t * 2.1) * 0.22;
    var gs = 3.4 * (1 + Math.sin(t * 2.1) * 0.1);
    this.nucleusGlow.scale.set(gs, gs, 1);

    for (var i = 0; i < this.orbits.length; i++) {
      var o = this.orbits[i];
      o.group.rotation.y += dt * o.spin;
    }

    this.starsA.rotation.y += dt * 0.006;
    this.starsB.rotation.y -= dt * 0.01;

    // mouse parallax (eased)
    this.parX = lerp(this.parX, this._mx, 0.045);
    this.parY = lerp(this.parY, this._my, 0.045);
    this.root.rotation.y = this.parX * 0.22;
    this.root.rotation.x = this.parY * 0.14;
    this.camera.position.x = this.parX * 0.55;
    this.camera.position.y = 0.7 - this.parY * 0.4;
    this.camera.lookAt(0, 0, 0);
  };

  LandingScene.prototype.onPointerMove = function (nx, ny) {
    this._mx = nx; this._my = ny;
  };

  // ============================================================================
  // Console scene — interactive 3D kill chain
  // ============================================================================

  function ConsoleScene() {
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x04070f, 0.03);
    this.camera = new THREE.PerspectiveCamera(50, 1, 0.1, 200);

    this.root = new THREE.Group();
    this.scene.add(this.root);

    this.scene.add(makeStars(1300, 44, 0.13, 0x9fd8ff, 0.65));
    this.scene.add(makeStars(160, 44, 0.3, 0x67e8f9, 0.85));
    this.root.add(makeGrid());

    this.nodes = {};
    this.nodeMeshes = [];
    this.edges = [];
    this.time = 0;
    this.running = false;
    this.impactT = -1;

    // ---- center target core
    this.targetWire = new THREE.LineSegments(
      new THREE.WireframeGeometry(new THREE.IcosahedronBufferGeometry(1.02, 1)),
      new THREE.LineBasicMaterial({ color: 0xf43f5e, transparent: true, opacity: 0.55 })
    );
    this.targetInner = new THREE.Mesh(
      new THREE.IcosahedronBufferGeometry(0.46, 0),
      new THREE.MeshBasicMaterial({ color: 0x9f1239 })
    );
    this.targetGlow = new THREE.Sprite(new THREE.SpriteMaterial({
      map: SM.glow, color: 0xf43f5e, transparent: true, opacity: 0.5,
      blending: THREE.AdditiveBlending, depthWrite: false
    }));
    this.targetGlow.scale.set(3.1, 3.1, 1);
    this.targetLabel = makeLabel("TARGET", 0.34, { color: "#ffd9e0", glowColor: "rgba(244,63,94,.8)" });
    this.targetLabel.position.set(0, -1.55, 0);
    this.targetCore = new THREE.Group();
    this.targetCore.add(this.targetWire, this.targetInner, this.targetGlow, this.targetLabel);
    this.root.add(this.targetCore);

    // ---- 6 phase nodes on a ring
    var R = 3.55;
    var ys = [0.55, -0.35, 0.75, -0.6, 0.4, -0.7];
    var positions = [];
    for (var i = 0; i < PHASES.length; i++) {
      var ang = (i / PHASES.length) * Math.PI * 2 - Math.PI / 2;
      positions.push(new THREE.Vector3(Math.cos(ang) * R, ys[i], Math.sin(ang) * R));
    }

    for (var j = 0; j < PHASES.length; j++) {
      var def = PHASES[j];
      var node = new THREE.Group();
      node.position.copy(positions[j]);

      var hit = new THREE.Mesh(
        new THREE.SphereBufferGeometry(0.62, 10, 10),
        new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false })
      );
      var core = new THREE.Mesh(
        new THREE.SphereBufferGeometry(0.27, 22, 22),
        new THREE.MeshBasicMaterial({ color: STATE_COLORS.pending })
      );
      var shell = new THREE.LineSegments(
        new THREE.WireframeGeometry(new THREE.IcosahedronBufferGeometry(0.48, 0)),
        new THREE.LineBasicMaterial({ color: STATE_COLORS.pending, transparent: true, opacity: 0.5 })
      );
      var glow = new THREE.Sprite(new THREE.SpriteMaterial({
        map: SM.glow, color: STATE_COLORS.pending, transparent: true, opacity: 0.28,
        blending: THREE.AdditiveBlending, depthWrite: false
      }));
      glow.scale.set(1.7, 1.7, 1);
      var label = makeLabel(def.num + " · " + def.name, 0.30, {
        fontSize: 46, glowColor: "rgba(103,232,249,.5)"
      });
      label.position.set(0, 0.86, 0);

      node.add(hit, core, shell, glow, label);
      node.userData = {
        phaseKey: def.key, state: "pending", core: core, shell: shell,
        glow: glow, label: label, baseY: positions[j].y, phase: 0
      };
      hit.userData.phaseKey = def.key;
      this.root.add(node);
      this.nodes[def.key] = node;
      this.nodeMeshes.push(hit);
    }

    // ---- edges (bezier arcs) + flow particles
    for (var e = 0; e < PHASES.length; e++) {
      var a = positions[e];
      var b = positions[(e + 1) % PHASES.length];
      var mid = a.clone().add(b).multiplyScalar(0.5);
      mid.y += 0.85;
      var curve = new THREE.QuadraticBezierCurve3(a, mid, b);
      var pts2 = curve.getPoints(44);
      var line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(pts2),
        new THREE.LineBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.16 })
      );
      this.root.add(line);

      var N = 12;
      var fgeo = new THREE.BufferGeometry();
      fgeo.addAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(N * 3), 3));
      var fmat = new THREE.PointsMaterial({
        color: 0x67e8f9, size: 0.1, transparent: true, opacity: 0.9,
        blending: THREE.AdditiveBlending, depthWrite: false
      });
      var flow = new THREE.Points(fgeo, fmat);
      flow.visible = false;
      this.root.add(flow);

      this.edges.push({
        from: PHASES[e].key, to: PHASES[(e + 1) % PHASES.length].key,
        curve: curve, line: line, flow: flow, n: N
      });
    }

    // ---- data motes streaming into the target while running
    var M = 90;
    var mgeo = new THREE.BufferGeometry();
    this.motePos = new Float32Array(M * 3);
    this.moteSpd = new Float32Array(M);
    for (var m = 0; m < M; m++) this._respawnMote(m, true);
    mgeo.addAttribute("position", new THREE.Float32BufferAttribute(this.motePos, 3));
    this.motes = new THREE.Points(mgeo, new THREE.PointsMaterial({
      color: 0x22d3ee, size: 0.085, transparent: true, opacity: 0.55,
      blending: THREE.AdditiveBlending, depthWrite: false
    }));
    this.motes.visible = false;
    this.root.add(this.motes);

    // ---- camera orbit state
    this.orbit = { theta: 0.85, phi: 1.18, radius: 8.8, target: new THREE.Vector3(0, 0.05, 0) };
    this.orbitGoal = { theta: 0.85, phi: 1.18, radius: 8.8 };
    this.lastInteract = -10;
    this.hovered = null;

    this._applyCamera(1);
  }

  ConsoleScene.prototype._respawnMote = function (i, anywhere) {
    var r = anywhere ? (2 + Math.random() * 7) : (5.5 + Math.random() * 3.5);
    var th = Math.random() * Math.PI * 2;
    var ph = Math.acos(2 * Math.random() - 1);
    this.motePos[i * 3] = r * Math.sin(ph) * Math.cos(th);
    this.motePos[i * 3 + 1] = r * Math.cos(ph) * 0.7;
    this.motePos[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
    this.moteSpd[i] = 0.65 + Math.random() * 1.1;
  };

  ConsoleScene.prototype._applyCamera = function (k) {
    var o = this.orbit, g = this.orbitGoal;
    o.theta = lerp(o.theta, g.theta, k);
    o.phi = lerp(o.phi, g.phi, k);
    o.radius = lerp(o.radius, g.radius, k);
    var sp = Math.sin(o.phi), cp = Math.cos(o.phi);
    this.camera.position.set(
      o.target.x + o.radius * sp * Math.cos(o.theta),
      o.target.y + o.radius * cp,
      o.target.z + o.radius * sp * Math.sin(o.theta)
    );
    this.camera.lookAt(o.target);
  };

  ConsoleScene.prototype.update = function (dt) {
    this.time += dt;
    var t = this.time;

    // target core
    var spin = this.running ? 0.55 : 0.16;
    this.targetWire.rotation.y += dt * spin;
    this.targetWire.rotation.x += dt * spin * 0.4;
    this.targetInner.rotation.y -= dt * spin * 1.4;
    var tp = this.running ? 1 + Math.sin(t * 5) * 0.1 : 1 + Math.sin(t * 1.6) * 0.045;
    this.targetInner.scale.set(tp, tp, tp);
    var tgl = this.running ? 0.62 + Math.sin(t * 5) * 0.2 : 0.4;
    this.targetGlow.material.opacity = tgl;
    if (this.impactT >= 0) {
      this.impactT += dt;
      var it = this.impactT / 0.9;
      if (it >= 1) { this.impactT = -1; }
      else {
        var burst = 3.1 + Math.sin(it * Math.PI) * 3.4;
        this.targetGlow.scale.set(burst, burst, 1);
        this.targetGlow.material.opacity = 0.9 * (1 - it);
      }
    } else {
      this.targetGlow.scale.set(3.1, 3.1, 1);
    }

    // nodes
    for (var key in this.nodes) {
      var node = this.nodes[key];
      var u = node.userData;
      var isRun = u.state === "running";
      u.phase += dt * (isRun ? 5.5 : 0.7);
      var s = 1;
      if (isRun) s = 1 + Math.sin(u.phase) * 0.13;
      else if (u.state === "complete") s = 1.06;
      else if (u.state === "failed") s = 1 + Math.sin(t * 3) * 0.05;
      node.scale.set(s, s, s);
      node.position.y = u.baseY + (isRun ? Math.sin(t * 2.2) * 0.09 : 0);
      u.shell.rotation.y += dt * (isRun ? 2.6 : 0.5);
      u.shell.rotation.x += dt * (isRun ? 1.1 : 0.2);
      var glowOp = { pending: 0.24, running: 0.95, complete: 0.55, failed: 0.7, skipped: 0.12 }[u.state];
      u.glow.material.opacity = lerp(u.glow.material.opacity, glowOp, 0.12);
      var gscale = (isRun ? 2.1 : 1.7) * s;
      u.glow.scale.set(gscale, gscale, 1);
      if (this.hovered === key) { node.scale.multiplyScalar(1.16); }
    }

    // edges + flows
    for (var i = 0; i < this.edges.length; i++) {
      var e = this.edges[i];
      var fromState = this.nodes[e.from].userData.state;
      var active = (fromState === "running" || fromState === "complete");
      e.flow.visible = active && (this.running || fromState === "complete");
      if (fromState === "running") {
        e.line.material.opacity = 0.42;
        e.line.material.color.setHex(0x22d3ee);
        e.flow.material.color.setHex(0x67e8f9);
      } else if (fromState === "complete") {
        e.line.material.opacity = 0.26;
        e.line.material.color.setHex(0x34d399);
        e.flow.material.color.setHex(0x6ee7b7);
      } else {
        e.line.material.opacity = 0.13;
        e.line.material.color.setHex(0x2a3a5e);
      }
      if (e.flow.visible) {
        var attr = e.flow.geometry.attributes.position;
        for (var p = 0; p < e.n; p++) {
          var ft = (p / e.n + t * 0.22) % 1;
          var pt = e.curve.getPoint(ft);
          attr.array[p * 3] = pt.x;
          attr.array[p * 3 + 1] = pt.y;
          attr.array[p * 3 + 2] = pt.z;
        }
        attr.needsUpdate = true;
      }
    }

    // motes streaming in
    if (this.motes.visible) {
      var mattr = this.motes.geometry.attributes.position;
      for (var m = 0; m < this.moteSpd.length; m++) {
        var x = mattr.array[m * 3], y = mattr.array[m * 3 + 1], z = mattr.array[m * 3 + 2];
        var d = Math.sqrt(x * x + y * y + z * z) || 1;
        var step = dt * this.moteSpd[m];
        mattr.array[m * 3] = x - (x / d) * step;
        mattr.array[m * 3 + 1] = y - (y / d) * step;
        mattr.array[m * 3 + 2] = z - (z / d) * step;
        if (d - step < 1.25) this._respawnMote(m, false);
      }
      mattr.needsUpdate = true;
    }

    // auto rotate when idle
    if (t - this.lastInteract > 3.5) {
      this.orbitGoal.theta += dt * 0.07;
    }
    this._applyCamera(0.085);
  };

  ConsoleScene.prototype.setPhaseState = function (key, state) {
    var node = this.nodes[key];
    if (!node) return;
    node.userData.state = state;
    var col = STATE_COLORS[state] || STATE_COLORS.pending;
    node.userData.core.material.color.setHex(col);
    node.userData.shell.material.color.setHex(col);
    node.userData.glow.material.color.setHex(col);
    if (state === "complete") this.impactT = 0;
  };

  ConsoleScene.prototype.resetPhases = function () {
    for (var key in this.nodes) this.setPhaseState(key, "pending");
  };

  ConsoleScene.prototype.setRunning = function (on) {
    this.running = on;
    this.motes.visible = on;
  };

  ConsoleScene.prototype.setTargetLabel = function (text) {
    var parent = this.targetLabel.parent || this.targetCore;
    var pos = this.targetLabel.position.clone();
    if (this.targetLabel.parent) parent.remove(this.targetLabel);
    this.targetLabel = makeLabel(text, 0.3, { color: "#ffd9e0", glowColor: "rgba(244,63,94,.8)", fontSize: 44 });
    this.targetLabel.position.copy(pos);
    parent.add(this.targetLabel);
  };

  ConsoleScene.prototype.raycast = function (nx, ny) {
    SM.raycaster.setFromCamera({ x: nx, y: ny }, this.camera);
    var hits = SM.raycaster.intersectObjects(this.nodeMeshes);
    return hits.length ? hits[0].object.userData.phaseKey : null;
  };

  ConsoleScene.prototype.focusPhase = function (key) {
    var node = this.nodes[key];
    if (!node) return;
    var o = this.orbitGoal;
    o.theta = Math.atan2(node.position.z, node.position.x);
    o.phi = 1.25;
    o.radius = 5.6;
    this.lastInteract = this.time;
  };

  ConsoleScene.prototype.resetView = function () {
    this.orbitGoal.theta = 0.85;
    this.orbitGoal.phi = 1.18;
    this.orbitGoal.radius = 8.8;
  };

  // ============================================================================
  // Scene manager + renderer + warp transition
  // ============================================================================

  var SM = {
    available: false,
    renderer: null,
    active: null,
    landing: null,
    console: null,
    raycaster: new THREE.Raycaster(),
    glow: null,
    transition: null,
    reducedMotion: false,

    init: function (canvas, flashEl) {
      if (!window.THREE) return false;
      this.reducedMotion = window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      try {
        this.renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true });
      } catch (e) {
        return false;
      }
      this.renderer.setClearColor(0x04070f, 1);
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      this.flashEl = flashEl;
      this.glow = glowTexture();

      this.landing = new LandingScene();
      this.console = new ConsoleScene();
      this.active = this.landing;
      this.available = true;

      this._resize();
      window.addEventListener("resize", this._resize.bind(this));

      this._bindPointer(canvas);
      this._bindOrbit(canvas);

      var last = performance.now();
      var self = this;
      (function loop(now) {
        requestAnimationFrame(loop);
        var dt = Math.min((now - last) / 1000, 0.05);
        last = now;
        if (document.hidden) return;
        if (self.transition) { self._updateTransition(dt); return; }
        self.active.update(dt);
        self.renderer.render(self.active.scene, self.active.camera);
      })(last);

      return true;
    },

    _resize: function () {
      if (!this.renderer) return;
      var w = window.innerWidth, h = window.innerHeight;
      this.renderer.setSize(w, h, false);
      this.landing.camera.aspect = w / h;
      this.landing.camera.updateProjectionMatrix();
      this.console.camera.aspect = w / h;
      this.console.camera.updateProjectionMatrix();
    },

    // ---------------- landing parallax + console hover/click
    _bindPointer: function (canvas) {
      var self = this;
      window.addEventListener("pointermove", function (ev) {
        if (!self.available) return;
        var nx = (ev.clientX / window.innerWidth) * 2 - 1;
        var ny = (ev.clientY / window.innerHeight) * 2 - 1;
        if (self.active === self.landing) {
          self.landing.onPointerMove(nx, ny);
        } else if (self.active === self.console) {
          var key = self.console.raycast(nx, ny);
          if (key !== self.console.hovered) {
            self.console.hovered = key;
            canvas.style.cursor = key ? "pointer" : "grab";
            if (self.onHover) self.onHover(key, ev.clientX, ev.clientY);
          } else if (key && self.onHover) {
            self.onHover(key, ev.clientX, ev.clientY);
          }
        }
      });
      canvas.addEventListener("click", function (ev) {
        if (self.active !== self.console || self.transition) return;
        if (self._dragged) return;               // ignore click after drag
        var nx = (ev.clientX / window.innerWidth) * 2 - 1;
        var ny = (ev.clientY / window.innerHeight) * 2 - 1;
        var key = self.console.raycast(nx, ny);
        if (key && self.onNodeClick) self.onNodeClick(key);
      });
    },

    // ---------------- orbit drag / wheel zoom (console)
    _bindOrbit: function (canvas) {
      var self = this;
      var dragging = false, lastX = 0, lastY = 0, moved = 0;

      function down(x, y) {
        if (self.active !== self.console || self.transition) return;
        dragging = true; moved = 0; lastX = x; lastY = y;
        canvas.classList.add("dragging");
      }
      function move(x, y) {
        if (!dragging) return;
        var dx = x - lastX, dy = y - lastY;
        moved += Math.abs(dx) + Math.abs(dy);
        lastX = x; lastY = y;
        var g = self.console.orbitGoal;
        g.theta -= dx * 0.0055;
        g.phi = clamp(g.phi - dy * 0.0045, 0.3, 2.55);
        self.console.lastInteract = self.console.time;
      }
      function up() {
        dragging = false;
        self._dragged = moved > 6;
        canvas.classList.remove("dragging");
        setTimeout(function () { self._dragged = false; }, 60);
      }

      canvas.addEventListener("mousedown", function (ev) { down(ev.clientX, ev.clientY); });
      window.addEventListener("mousemove", function (ev) { move(ev.clientX, ev.clientY); });
      window.addEventListener("mouseup", up);
      canvas.addEventListener("touchstart", function (ev) {
        if (ev.touches[0]) down(ev.touches[0].clientX, ev.touches[0].clientY);
      }, { passive: true });
      canvas.addEventListener("touchmove", function (ev) {
        if (ev.touches[0]) move(ev.touches[0].clientX, ev.touches[0].clientY);
      }, { passive: true });
      canvas.addEventListener("touchend", up);

      canvas.addEventListener("wheel", function (ev) {
        if (self.active !== self.console || self.transition) return;
        ev.preventDefault();
        var g = self.console.orbitGoal;
        g.radius = clamp(g.radius * (1 + Math.sign(ev.deltaY) * 0.09), 4.2, 16);
        self.console.lastInteract = self.console.time;
      }, { passive: false });
    },

    // ---------------- warp transition landing → console
    enterConsole: function (onDone) {
      if (!this.available) { if (onDone) onDone(); return; }
      if (this.active === this.console || this.transition) { if (onDone) onDone(); return; }

      if (this.reducedMotion) {
        this.active = this.console;
        if (onDone) onDone();
        return;
      }

      var self = this;
      this.transition = {
        t: 0, dur: 1.35, onDone: onDone,
        startFov: this.landing.camera.fov
      };
    },

    backToLanding: function () {
      if (!this.available || this.transition) return;
      this.active = this.landing;
      this.landing.camera.fov = 62;
      this.landing.camera.updateProjectionMatrix();
    },

    _updateTransition: function (dt) {
      var tr = this.transition;
      tr.t += dt;
      var t = clamp(tr.t / tr.dur, 0, 1);

      if (t < 0.72) {
        // dive into the core
        var k = easeInCubic(t / 0.72);
        var cam = this.landing.camera;
        cam.position.z = lerp(9.4, 0.12, k);
        cam.position.x = lerp(cam.position.x, 0, k * 0.4);
        cam.position.y = lerp(cam.position.y, 0, k * 0.4);
        cam.fov = lerp(tr.startFov, 98, k);
        cam.updateProjectionMatrix();
        this.landing.starsA.rotation.y += dt * (0.05 + k * 1.4);
        this.landing.starsB.rotation.y -= dt * (0.08 + k * 2.0);
        this.landing.core.rotation.z += dt * k * 2.2;
        if (this.flashEl) this.flashEl.style.opacity = String(Math.pow(k, 4) * 0.9);
        this.active.update(dt * 0.15);
      } else {
        // through the other side → console settles in
        if (this.active !== this.console) {
          this.active = this.console;
          this.console.orbit.radius = 15.5;
          this.console.orbitGoal.radius = 8.8;
          this.console.orbitGoal.theta = 0.85;
          this.console.orbitGoal.phi = 1.18;
          if (this.flashEl) this.flashEl.style.opacity = "0.9";
        }
        var k2 = easeOutCubic((t - 0.72) / 0.28);
        if (this.flashEl) this.flashEl.style.opacity = String(0.9 * (1 - k2));
        this.console.update(dt);
      }

      this.renderer.render(this.active.scene, this.active.camera);

      if (t >= 1) {
        if (this.flashEl) this.flashEl.style.opacity = "0";
        this.transition = null;
        if (tr.onDone) tr.onDone();
      }
    }
  };

  window.OE3D = SM;
})();
