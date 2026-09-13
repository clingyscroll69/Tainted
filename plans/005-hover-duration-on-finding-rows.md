# 005 — Take the finding row's hover off the state-change duration

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (not a git repository; verify with `shasum -a 256 surfaces/website/frontend/index.html`)
- **Severity**: MEDIUM
- **Category**: 2 — Easing & duration
- **Estimated scope**: 1 file, 1 line
- **Depends on**: plan **001** (supplies `--dur-control`). If 001 has not run, substitute the
  literal `.18s` wherever this plan writes `var(--dur-control)` — and nothing else changes.

## Problem

```css
/* surfaces/website/frontend/index.html:626–631 — current */
.find{
  display:grid;grid-template-columns:96px minmax(0,1fr);
  border-bottom:1px solid var(--rule-soft);
  transition:background .5s ease-out;
}
.find:hover{background:rgb(var(--ch-wash) / .035)}
```

The only property `.find` transitions is `background`, and the only thing that changes its
background is `:hover`. So a 500ms `ease-out` is serving a hover state.

Reading a Tainted report means sweeping the cursor down the Observations list. At 500ms on the
way out, the rows behind the cursor are still fading while the ones ahead are fading in — on a
nine-candidate run, moving down the list at a normal speed leaves three or four rows lit at once.
The highlight stops meaning "this row" and starts meaning "roughly where the mouse has been".
AUDIT.md puts hover in the `ease` family and well inside the sub-300ms budget; 500ms is not close.

**This is not the documented decision.** `DESIGN.md:358` describes a band — *"state changes
carried by 0.45–0.6s ease-out colour transitions"* — and every other member of that band is a
genuine state change written by `ignite()`: the bulb (line 642), the strength word (647), the
readout numerals (433), the taint graph's ink (449–454). A hover is not a state change. This row
inherited the value from its neighbours rather than choosing it.

**Honest caveat, and the reason the feel check below is not optional:** the hover delta is
`rgb(var(--ch-wash) / .035)` — a 3.5% alpha wash. It is deliberately near the threshold of
visibility, and it is possible that at that contrast the trailing rows are not perceptible and
this change is a no-op to the eye. The code reasoning stands either way, but do not report this
as an improvement you observed unless you observed it.

## Target

```css
/* target — surfaces/website/frontend/index.html:626–631 */
.find{
  display:grid;grid-template-columns:96px minmax(0,1fr);
  border-bottom:1px solid var(--rule-soft);
  /* A hover, not a state change: the row's highlight has to keep up with the cursor sweeping
     a nine-candidate list, and the 0.45–0.6s band this used to sit in belongs to the proof
     marks `ignite()` writes, not to the pointer. */
  transition:background var(--dur-control) ease;
}
.find:hover{background:rgb(var(--ch-wash) / .035)}
```

`--dur-control` is `.18s` — the duration this file already uses for every other control hover
(`.btn` line 402, `.mini` line 736). Reusing it rather than inventing a third value is the point;
AUDIT.md's 100–160ms press-feedback band and 150–250ms dropdown band both bracket it comfortably.

`ease` rather than `ease-out`, per AUDIT.md's decision order: hover and colour changes take
`ease`. This also matches `.mini` and `.reveal`, which specify no easing and therefore already
get `ease`.

## Repo conventions to follow

- Exemplar for a control hover in this file, three declarations up the same stylesheet:
  ```css
  /* surfaces/website/frontend/index.html:736 */
    text-transform:uppercase;transition:border-color .18s,color .18s,background .18s;
  ```
  (after plan 001 this reads `var(--dur-control)`.)
- Comments name the decision and the failure avoided. Keep the one in the target.
- Dense declarations, no reformatting of the surrounding block.

## Steps

1. Replace line 629 of `surfaces/website/frontend/index.html`:

   ```css
   /* current */
     transition:background .5s ease-out;
   ```

   with the commented target above (four lines: three comment lines plus the declaration).

2. Nothing else. Do not touch line 631.

## Boundaries

- Do NOT change the hover colour, the alpha, or `.find:hover`'s selector. If plan 004 has already
  run, line 631 is wrapped in `@media (hover:hover) and (pointer:fine)` — leave that wrapper
  exactly as it is.
- Do NOT change any other member of the 0.45–0.6s band (lines 433, 449–454, 642, 647, 386). Those
  are the documented state-change durations and are correct.
- Do NOT add a `transform` or a border change to the hover. A finding row is a block of prose and
  a code sample the reader is reading; moving it under the cursor is a regression, not polish.
- Do NOT add new dependencies.
- If line 629 does not read exactly as quoted, STOP and report.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all pass.
  - `grep -n 'transition:background' surfaces/website/frontend/index.html` — the `.find` hit must
    show `var(--dur-control) ease` (or `.18s ease`).
- **Feel check** — this is the whole plan; do it before and after:
  1. Load the page, press **Try it with `demo/demo`**, then **Analyze**, so the Observations list
     has nine rows. Scroll to it.
  2. Sweep the cursor down the list at a normal reading speed, then back up.
  3. **Before**: rows behind the cursor stay faintly lit; at speed, several are lit at once.
     **After**: the highlight tracks the cursor and only one row is lit.
  4. Now the honest part: if you cannot see the difference at all — the wash is 3.5% alpha and
     that is a real possibility — **say so in the report** rather than asserting an improvement.
     To make the comparison legible, temporarily raise the alpha to `.14` in DevTools, repeat the
     sweep, and confirm the timing difference is what you expect; then revert the alpha. Do not
     commit an alpha change.
  5. In DevTools → Rendering, enable **Emulate CSS `prefers-reduced-motion: reduce`** and confirm
     the hover still fades (it should — `background-color` is on plan 004's surviving property
     list, and if 004 has not run yet it will snap, which is that plan's problem, not this one).
- **Done when**: the declaration reads as targeted, the sweep tracks the cursor, and the 23
  website tests pass.
