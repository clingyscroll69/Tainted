# 003 — Make the marine snow frame-rate independent

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (not a git repository; verify with `shasum -a 256 surfaces/website/frontend/index.html`)
- **Severity**: HIGH
- **Category**: 5 — Performance
- **Estimated scope**: 1 file, one function, ~8 changed lines

## Problem

Both ambient particulate fields advance their flakes **once per animation frame with no regard
for how long that frame took**:

```js
/* surfaces/website/frontend/index.html:1473–1485 — current */
    function paint(){
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = ink;
      for(const f of flakes){
        ctx.globalAlpha = f.a;
        ctx.beginPath(); ctx.arc(f.x, f.y, f.r, 0, 6.283); ctx.fill();
        f.y += f.v; f.x += f.d;
        if(f.y > H + 2){ f.y = -2; f.x = Math.random() * W; }
        if(f.x < -2) f.x = W + 2; if(f.x > W + 2) f.x = -2;
      }
      ctx.globalAlpha = 1;
    }
    function frame(){ paint(); raf = requestAnimationFrame(frame); }
```

The per-flake velocities are authored constants scaled by a per-field `speed` argument:

```js
/* surfaces/website/frontend/index.html:1518–1519 — current */
  particulate(document.getElementById('snow'), 9000,  .34, 1,   1.5);
  particulate(document.getElementById('deep'), 26000, .17, .55, 1);
```

So the authored speed only holds at 60Hz. On the machine this product is aimed at — a developer's
laptop — it is wrong most of the time:

| Display / condition | Actual speed |
| --- | --- |
| 60Hz | 1.0× (authored) |
| 120Hz ProMotion MacBook | **2.0×** |
| 144Hz monitor | **2.4×** |
| 60Hz under load, dropping to 30fps | **0.5×** |

The near/deep ratio (`1` vs `.55`) survives, so the two fields stay in proportion — but the whole
column drifts twice as fast as authored on the most likely hardware. `DESIGN.md` calls the water
column the page's ground, and its speed is the difference between *marine snow* and *static*.

This is the one defect in an otherwise carefully-built canvas layer. The same function already
clamps the backing store (line 1457), stops on `visibilitychange` (line 1496), stops off-screen
via `IntersectionObserver` (line 1498), watches the element rather than the window with a
`ResizeObserver` (line 1505), and honours a mid-session `prefers-reduced-motion` change through
`motionJobs` (line 1494). Only the clock is missing.

## Target

`paint` takes a frame-delta expressed in 60Hz units — `1` means "one 60Hz frame's worth" — and
scales displacement by it. `frame` computes that delta from the `requestAnimationFrame`
timestamp, clamped so a tab restore cannot teleport the field.

```js
/* target */
    function paint(dt){
      const d = dt === undefined ? 1 : dt;
      ...
        f.y += f.v * d; f.x += f.d * d;
      ...
    }
    let last = 0;
    function frame(now){
      /* Displacement is per 60Hz frame, so it is scaled by how many of those actually
         elapsed. Without this the column falls at 2x on a 120Hz display and half speed on a
         loaded one. The clamp is for a restored tab: rAF can hand back a gap of seconds, and
         a flake must not jump the whole column in one step. */
      const dt = last ? Math.min((now - last) / 16.667, 3) : 1;
      last = now;
      paint(dt);
      raf = requestAnimationFrame(frame);
    }
```

`3` is 50ms — three 60Hz frames. Past that the field simply loses time rather than lurching.

## Repo conventions to follow

- Everything in this function is commented with the failure it prevents, not with what the code
  does. The exemplar is the `size()` comment at lines 1451–1456, which explains the retina
  backing store decision by naming the cost it avoided. Match that register.
- `particulate` is entirely self-contained and closes over `raf`, `running`, `onScreen`, `W`,
  `H`, `flakes` (line 1448). Add `last` to that same closure, not to module scope — there are
  **two** instances of this function and each needs its own clock.

## Steps

1. Change `paint`'s signature and its two displacement lines. Replace lines 1473–1484:

   ```js
   /* current — surfaces/website/frontend/index.html:1473–1484 */
       function paint(){
         ctx.clearRect(0, 0, W, H);
         ctx.fillStyle = ink;
         for(const f of flakes){
           ctx.globalAlpha = f.a;
           ctx.beginPath(); ctx.arc(f.x, f.y, f.r, 0, 6.283); ctx.fill();
           f.y += f.v; f.x += f.d;
           if(f.y > H + 2){ f.y = -2; f.x = Math.random() * W; }
           if(f.x < -2) f.x = W + 2; if(f.x > W + 2) f.x = -2;
         }
         ctx.globalAlpha = 1;
       }
   ```

   with:

   ```js
   /* target */
       /* `dt` is in 60Hz frames: 1 means one frame's worth of drift. Called with no argument
          for a still repaint (a resize, or the first paint before the loop starts). */
       function paint(dt){
         const d = dt === undefined ? 1 : dt;
         ctx.clearRect(0, 0, W, H);
         ctx.fillStyle = ink;
         for(const f of flakes){
           ctx.globalAlpha = f.a;
           ctx.beginPath(); ctx.arc(f.x, f.y, f.r, 0, 6.283); ctx.fill();
           f.y += f.v * d; f.x += f.d * d;
           if(f.y > H + 2){ f.y = -2; f.x = Math.random() * W; }
           if(f.x < -2) f.x = W + 2; if(f.x > W + 2) f.x = -2;
         }
         ctx.globalAlpha = 1;
       }
   ```

   **The `dt === undefined` default is load-bearing.** `paint()` is called with no argument in
   three places — line 1491 (`size(); paint();`), line 1511 (inside the `ResizeObserver`) and
   line 1514 (the `onResize` fallback). Without the default, `f.v * undefined` is `NaN`, every
   flake's coordinates become `NaN`, and both canvases go permanently blank. Do not use
   `function paint(dt = 1)` if you would rather — that is equivalent and also correct — but do
   not remove the default, and do not "fix" the three bare call sites by passing `1`; a still
   repaint should not advance the field at all, and `1` would nudge it.

2. Replace `frame` and `start`. Replace lines 1485–1489:

   ```js
   /* current — surfaces/website/frontend/index.html:1485–1489 */
       function frame(){ paint(); raf = requestAnimationFrame(frame); }
       function start(){
         if(running || reduce || document.hidden || !onScreen) return;
         running = true; frame();
       }
   ```

   with:

   ```js
   /* target */
       let last = 0;
       /* Displacement is per 60Hz frame, so it is scaled by how many of those actually
          elapsed — otherwise the column falls at twice the authored speed on a 120Hz display
          and half of it on a loaded one. The clamp is for a restored tab: rAF can hand back a
          gap of seconds, and a flake must not cross the whole column in one step. */
       function frame(now){
         const dt = last ? Math.min((now - last) / 16.667, 3) : 1;
         last = now;
         paint(dt);
         raf = requestAnimationFrame(frame);
       }
       function start(){
         if(running || reduce || document.hidden || !onScreen) return;
         /* the clock restarts with the loop: the gap since it stopped is not drift owed */
         running = true; last = 0; raf = requestAnimationFrame(frame);
       }
   ```

   Note the two changes in `start()`: `last = 0` (so the first frame after any stop uses `dt = 1`
   rather than billing the field for however long it was paused), and going through
   `requestAnimationFrame(frame)` instead of calling `frame()` directly — `frame` now needs a
   timestamp, and only rAF supplies one.

3. Leave `stop()` (line 1490) alone. `cancelAnimationFrame(raf)` plus `running = false` is
   already correct, and `last` is reset on the way back in, not on the way out.

## Boundaries

- Do NOT change the authored velocities, the `speed` arguments at lines 1518–1519, the flake
  count formula (`Math.round(W * H / area)`), the radius floor, or the alpha ranges. The point of
  this plan is that the values already in the file finally mean what they say.
- Do NOT change the dpr clamp, the `IntersectionObserver`, the `visibilitychange` listener, the
  `ResizeObserver`, or the `motionJobs` registration. They are correct.
- Do NOT convert the loop to a fixed-timestep accumulator. A clamped delta is the fix; an
  accumulator is a rewrite and will fail review.
- Do NOT add new dependencies.
- If any "current" excerpt does not match the file, STOP and report.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all pass.
  - `grep -n 'f.y += f.v' surfaces/website/frontend/index.html` must show the `* d` form and
    nothing else.
- **Feel check**:
  - Open the page and confirm **both** fields are moving — the near field over the water column
    and the deep field below the fold. A blank canvas means the `undefined` default was dropped
    (see step 1); scroll to the lower band to check the deep one specifically.
  - Resize the window and confirm the field is still moving afterwards, and that it did not jump.
  - Switch to another tab for ten seconds and come back: the field must resume from where it was,
    **not** jump forward by ten seconds of drift. This is what the `last = 0` reset and the clamp
    are for, and it is the most likely thing to get wrong.
  - In DevTools → Rendering, enable **Emulate CSS `prefers-reduced-motion`** and confirm both
    fields stop within a frame (the live `matchMedia` listener at line 1420 handles this — it must
    keep working). Turn it off and confirm they restart without a jump.
  - **The measurement, if the hardware is available**: on a 120Hz display, open DevTools →
    Rendering → **Frame Rendering Stats** to confirm the page is actually running at 120fps, then
    watch a single flake cross the column and time it. Before this change it crosses in roughly
    half the time it takes on a 60Hz display; after, the two should match within eyeballing
    distance. If no 120Hz display is available, say so in the report rather than claiming the
    check passed — the code change is still correct, but the payoff is unverified.
- **Done when**: both fields animate, survive a resize and a tab switch without jumping, stop and
  restart cleanly under reduced motion, and the 46 website tests pass.
