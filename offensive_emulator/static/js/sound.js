/* ============================================================================
   OFFENSIVE EMULATOR v4 — sound design (WebAudio, zero assets)
   All sounds are synthesized: oscillators + noise + envelopes.
   Muted state persists in localStorage. AudioContext is created lazily on
   the first user gesture (autoplay policy).
   ============================================================================ */
(function () {
  "use strict";

  var ctx = null;
  var master = null;
  var muted = false;
  try { muted = window.localStorage.getItem("oe_muted") === "1"; } catch (e) {}

  var BASE_GAIN = 0.22;

  function ensure() {
    if (ctx) {
      if (ctx.state === "suspended") { try { ctx.resume(); } catch (e) {} }
      return true;
    }
    try {
      var AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return false;
      ctx = new AC();
      master = ctx.createGain();
      master.gain.value = BASE_GAIN;
      master.connect(ctx.destination);
      return true;
    } catch (e) {
      ctx = null;
      return false;
    }
  }

  function tone(opts) {
    // {f, f2, dur, type, gain, delay, attack}
    if (!ctx) return;
    var t0 = ctx.currentTime + (opts.delay || 0);
    var osc = ctx.createOscillator();
    var g = ctx.createGain();
    osc.type = opts.type || "sine";
    osc.frequency.setValueAtTime(opts.f, t0);
    if (opts.f2) osc.frequency.exponentialRampToValueAtTime(opts.f2, t0 + opts.dur);
    var peak = (opts.gain || 0.5);
    var atk = opts.attack || 0.008;
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(peak, t0 + atk);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + opts.dur);
    osc.connect(g); g.connect(master);
    osc.start(t0); osc.stop(t0 + opts.dur + 0.05);
  }

  function noise(opts) {
    // {dur, gain, freq, delay}
    if (!ctx) return;
    var t0 = ctx.currentTime + (opts.delay || 0);
    var len = Math.max(1, Math.floor(ctx.sampleRate * opts.dur));
    var buf = ctx.createBuffer(1, len, ctx.sampleRate);
    var data = buf.getChannelData(0);
    var last = 0;
    for (var i = 0; i < len; i++) {
      // brown-ish noise: integrated white noise, low-passed by construction
      var w = Math.random() * 2 - 1;
      last = (last + 0.02 * w) / 1.02;
      data[i] = last * 3.5;
    }
    var src = ctx.createBufferSource();
    src.buffer = buf;
    var filt = ctx.createBiquadFilter();
    filt.type = "lowpass";
    filt.frequency.setValueAtTime(opts.freq || 400, t0);
    if (opts.freq2) filt.frequency.exponentialRampToValueAtTime(opts.freq2, t0 + opts.dur);
    var g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(opts.gain || 0.4, t0 + (opts.attack || 0.02));
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + opts.dur);
    src.connect(filt); filt.connect(g); g.connect(master);
    src.start(t0); src.stop(t0 + opts.dur + 0.05);
  }

  var SOUNDS = {
    // small UI tick
    click: function () {
      tone({ f: 880, f2: 660, dur: 0.06, type: "triangle", gain: 0.18 });
    },
    // launch: rising sub rumble
    launch: function () {
      noise({ dur: 1.5, gain: 0.5, freq: 120, freq2: 900, attack: 0.15 });
      tone({ f: 55, f2: 220, dur: 1.2, type: "sawtooth", gain: 0.16, attack: 0.2 });
      tone({ f: 220, f2: 440, dur: 0.5, type: "sine", gain: 0.1, delay: 0.9 });
    },
    // phase engaged: tick rising with phase index (arg 0..5)
    phase: function (i) {
      var base = 520 + (i || 0) * 90;
      tone({ f: base, dur: 0.09, type: "square", gain: 0.12 });
      tone({ f: base * 1.5, dur: 0.12, type: "sine", gain: 0.14, delay: 0.07 });
    },
    // phase objective achieved
    phaseDone: function () {
      tone({ f: 660, dur: 0.1, type: "sine", gain: 0.16 });
      tone({ f: 990, dur: 0.14, type: "sine", gain: 0.14, delay: 0.08 });
    },
    // phase failed / aborted
    fail: function () {
      tone({ f: 160, f2: 70, dur: 0.35, type: "sawtooth", gain: 0.2 });
    },
    // defense fired on the target
    defense: function () {
      tone({ f: 1200, dur: 0.05, type: "square", gain: 0.1 });
      tone({ f: 1200, dur: 0.05, type: "square", gain: 0.1, delay: 0.09 });
    },
    // mission complete: little major arpeggio
    complete: function () {
      tone({ f: 523.25, dur: 0.16, type: "triangle", gain: 0.2 });
      tone({ f: 659.25, dur: 0.16, type: "triangle", gain: 0.2, delay: 0.12 });
      tone({ f: 783.99, dur: 0.16, type: "triangle", gain: 0.2, delay: 0.24 });
      tone({ f: 1046.5, dur: 0.34, type: "triangle", gain: 0.22, delay: 0.36 });
    },
    // target held (mission over, defenses won)
    held: function () {
      tone({ f: 392, dur: 0.2, type: "triangle", gain: 0.18 });
      tone({ f: 523.25, dur: 0.2, type: "triangle", gain: 0.18, delay: 0.15 });
      tone({ f: 392, dur: 0.3, type: "sine", gain: 0.16, delay: 0.32 });
    },
    abort: function () {
      tone({ f: 440, f2: 110, dur: 0.5, type: "sawtooth", gain: 0.16 });
    },
    // replay transport
    replay: function () {
      tone({ f: 330, f2: 660, dur: 0.18, type: "sine", gain: 0.14 });
    },
    // count-up tick
    tick: function () {
      tone({ f: 1400 + Math.random() * 300, dur: 0.03, type: "sine", gain: 0.05 });
    }
  };

  window.OE_Sound = {
    play: function (name, arg) {
      if (muted) return;
      if (!ensure()) return;
      try { if (SOUNDS[name]) SOUNDS[name](arg); } catch (e) {}
    },
    isMuted: function () { return muted; },
    setMuted: function (m) {
      muted = !!m;
      try { window.localStorage.setItem("oe_muted", muted ? "1" : "0"); } catch (e) {}
      return muted;
    },
    toggle: function () { return OE_Sound.setMuted(!muted); },
    // call once from a user gesture to unlock audio
    unlock: function () { if (!muted) ensure(); }
  };
})();
