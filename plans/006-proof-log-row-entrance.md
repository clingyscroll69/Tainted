# 006 — Give proof-log rows an entrance

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (not a git repository; verify with `shasum -a 256 surfaces/website/frontend/index.html`)
- **Severity**: MEDIUM (additive — a missed opportunity, not a defect)
- **Category**: 8 — Missed opportunities
- **Estimated scope**: 1 file, ~10 added CSS lines, 0 JavaScript changes
- **Depends on**: plan **001** for the `:root` motion block this adds a token to. If 001 has not
  run, add `--dur-enter:.26s` to `:root` on its own, just before the `--ff-*` tokens.

## Problem

During the descent — the product's one authored moment — three columns are on screen at once.
`.rig` is a three-column grid (line 203: `grid-template-columns:298px minmax(0,1fr) 336px`), and
all three tracks are in the first viewport: the descent rail, the water column carrying the lamp,
and the instrument rail carrying **Run**, **Registers** and **Proof log**.

Of everything visible while the lamp descends, the proof log is the only element with no motion at
all. The lamp travels (line 2942). The taint graph's ink crosses over 550ms (lines 449–454). The
proof-strength marks ease (lines 642, 647). The log teleports a row into place every 640ms:

```js
/* surfaces/website/frontend/index.html:2585–2590 — current */
    const [txt, cls] = LOGLINE[out];
    const li = document.createElement('li');
    li.innerHTML = '<span class="t">' + String(i + 1).padStart(2, '0') + '</span>' +
                   '<span class="e">' + ESC(el.querySelector('h3').textContent) + '</span>' +
                   '<span class="r ' + cls + '">' + txt + '</span>';
    if(logEl.dataset.clean !== '1'){ logEl.innerHTML = ''; logEl.dataset.clean = '1'; }
    logEl.appendChild(li);
```

```css
/* surfaces/website/frontend/index.html:600–603 — current */
.log{list-style:none;margin:0;padding:0}
.log li{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:baseline;
  padding:10px 18px;border-bottom:1px solid var(--rule-soft);font-size:0.8125rem}
.log li:last-child{border-bottom:0}
```

**Purpose:** preventing a jarring change, and spatial consistency. The log is the running record
of a descent, and its rows arrive on a paced clock — 640ms apart — which is unusually generous
room for an entrance. A row that appears from nothing reads as a rendering artefact; a row that
arrives from below reads as the record growing, in the direction the column is being read.

**Frequency:** occasional — once per run, N rows per run. Well inside the tier AUDIT.md allows a
standard animation.

## Target

Pure CSS, no JavaScript change, using `@starting-style` for entry:

```css
/* target — replaces surfaces/website/frontend/index.html:600–603 */
.log{list-style:none;margin:0;padding:0}
.log li{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:baseline;
  padding:10px 18px;border-bottom:1px solid var(--rule-soft);font-size:0.8125rem}
.log li:last-child{border-bottom:0}
/* A row arrives every 640ms while the lamp descends, and it used to arrive from nothing. It
   enters from below because that is the direction the record grows — and only once the log is
   live (`data-clean="1"`, set by ignite() before the first row), so the seed row the page ships
   with does not fade in on first paint. 260ms sits well inside the step, so a row never lands
   on top of one that has not finished arriving. */
.log[data-clean="1"] li{
  opacity:1;transform:none;
  transition:opacity var(--dur-enter) ease-out,transform var(--dur-enter) ease-out;
}
@starting-style{
  .log[data-clean="1"] li{opacity:0;transform:translateY(6px)}
}
```

And the token, added to the `:root` motion block plan 001 created:

```css
  --dur-enter:.26s;        /* a new row or block arriving */
```

### Why the `[data-clean="1"]` scope is load-bearing

`@starting-style` applies to an element the first time it is rendered — **including the initial
page render**. The stylesheet ships one seed row in the markup:

```html
<!-- surfaces/website/frontend/index.html:1274 -->
      <li><span class="t">—</span><span class="e">Waiting for the lamp.</span><span class="r">idle</span></li>
```

Unscoped, that row would fade in on page load. This page has no load entrance anywhere else, and
adding one is out of character for it. The attribute gate solves it exactly, for free:

- On first load `#prooflog` has **no** `data-clean` attribute at all — `clearResult()` (which sets
  it to `'0'` at line 2258) is not part of the init sequence at lines 2982–2988. The selector does
  not match, so the seed row does not animate.
- `ignite()` sets `logEl.dataset.clean = '1'` at line 2589 **before** `appendChild(li)` at line
  2590, so the parent already carries the attribute at the moment each real row is inserted, and
  the starting style applies.
- `prove()` (line 2900) and `clearResult()` (line 2258) both set it back to `'0'`, so the reset
  row that follows does not animate either.

Do not remove the attribute selector, and do not "simplify" it to `.log li`.

## Repo conventions to follow

- Comments name the decision and what goes wrong without it. Keep the one in the target — the
  `[data-clean="1"]` gate will otherwise be deleted as noise by the next reader.
- Motion tokens live in the single `:root` block (lines 34–114), added before the `--ff-*` type
  tokens. Exemplar: the block plan 001 adds.
- No JavaScript is needed and none should be added. Exemplar of this file preferring CSS for
  predetermined motion: the entire descent is a CSS transition driven by one inline
  `style.transition` assignment, not a JS tween.

## Steps

1. Add `--dur-enter:.26s;` to the `:root` motion token block, after `--dur-pulse`.
2. Append the two rules from **Target** (`.log[data-clean="1"] li` and the `@starting-style`
   block) immediately after line 603, comment included. Leave lines 600–603 exactly as they are.
3. Change no JavaScript.

## Boundaries

- Do NOT modify `ignite()` (lines 2574–2592), `logEl.dataset.clean` handling, or any other JS.
- Do NOT animate anything other than `opacity` and `transform`. In particular do not animate
  `height`, `padding` or `margin` to smooth the list's growth — that is layout on every frame,
  and the panels below the log (`#toolgraph-panel`, the Active plane panel) tolerate the push.
- Do NOT use `@keyframes`. Rows can arrive faster than 260ms if the engine's own timing shifts,
  and transitions retarget where keyframes restart. This is AUDIT.md §4.
- Do NOT increase the duration past 300ms or the offset past 8px. 640ms is the step; an entrance
  that eats half of it reads as lag.
- Do NOT add a stagger. The rows are already staggered by the engine's clock.
- Do NOT add new dependencies. `@starting-style` is native CSS.
- If lines 600–603 do not match the excerpt, STOP and report.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all pass.
  - `grep -c 'starting-style' surfaces/website/frontend/index.html` returns `1`.
  - `git diff` is not available (not a repo); confirm by inspection that no line between 2574 and
    2592 changed.
- **Feel check**:
  1. Load the page. The **"Waiting for the lamp."** row must be visible immediately with **no**
     fade. If it fades, the `[data-clean="1"]` gate is wrong — that is the single most likely
     mistake in this plan.
  2. Press **Try it with `demo/demo`** → **Analyze** → **Arm & prove**. Watch the Proof log panel
     in the right rail, not the water column.
  3. Each row must rise ~6px into place as it fades in, finishing well before the next row
     arrives. No row should still be moving when the next one lands.
  4. In DevTools → Animations panel, set playback speed to **10%** and re-run. Confirm the
     translate and the fade are the same length and end together, and that the row's final
     position is flush with the row above it — a leftover `transform` shows up here as a
     permanently offset row.
  5. Re-run a second time without reloading (press **Re-run**). The log resets to the seed row —
     confirm the reset row does **not** animate, and that the new run's rows do.
  6. Interrupt a run by pressing **Analyze** mid-descent. The log resets; confirm no orphan row
     fades in afterwards. (If plan 002 has run, no orphan rows arrive at all.)
  7. DevTools → Rendering → **Emulate CSS `prefers-reduced-motion: reduce`**, then re-run. Rows
     must appear with a short fade and **no** movement. If plan 004 has run this is automatic —
     `transform` is off its surviving property list. If 004 has not run, rows will appear
     instantly, which is also acceptable; note which you observed.
- **Done when**: the seed row never animates, real rows rise into place inside their step, the
  10% playback check is clean, and the 46 website tests pass.
