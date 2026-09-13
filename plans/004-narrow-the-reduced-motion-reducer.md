# 004 — Narrow the reduced-motion reducer to movement, and gate `:hover` for touch

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (not a git repository; verify with `shasum -a 256 surfaces/website/frontend/index.html`)
- **Severity**: MEDIUM (part A) / LOW (part B)
- **Category**: 6 — Accessibility
- **Estimated scope**: 1 file, one media block rewritten + 8 rules wrapped in place

## Problem — Part A: the reducer removes feedback, not just movement

```css
/* surfaces/website/frontend/index.html:989–1003 — current */
/* Reduced motion resolves to the final state instantly — it does not turn a slow pulse
   into a fast one. Capping the iteration count is the point: an infinite animation given a
   near-zero duration flickers, which is the opposite of what was asked for. State changes
   still land; only their travel is removed. */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{
    transition-duration:1ms!important;transition-delay:0ms!important;
    animation-duration:1ms!important;animation-delay:0ms!important;
    animation-iteration-count:1!important;
    scroll-behavior:auto!important;
  }
  .btn.running .icon{animation:none;opacity:.75}
  .lamp{transition:none}
}
```

The comment's last sentence — *"State changes still land; only their travel is removed"* — is the
intent, and the rule does not deliver it. `transition-duration:1ms` on `*` removes **every**
transition in the file, including the ones that carry no travel at all:

| Line | Rule | What is lost |
| --- | --- | --- |
| 517 | `.setup input{transition:border-color .15s ease}` | the field's border answering focus |
| 402 | `.btn{transition:background …,box-shadow …}` | the primary control's hover |
| 736 | `.mini{transition:border-color …,color …,background …}` | every secondary control's hover |
| 538 | `.reveal{transition:color .15s,background .15s}` | the password reveal's hover |
| 629 | `.find{transition:background .5s ease-out}` | the finding row's hover |
| 642 | `.beam .bulb{transition:background …,box-shadow …,border-color …}` | the proof-strength mark lighting |
| 647 | `.beam .st{transition:color .45s ease-out}` | the strength word's ink |
| 433 | `.rd .v{transition:color …,text-shadow …}` | the two big numerals lighting |
| 449–454 | `.taint .edge / .node / .sink / .cap` | the taint graph's proof ink |

None of those moves anything. A `prefers-reduced-motion` request is a request to stop things
travelling — colour, opacity and shadow feedback is what the setting is meant to preserve. Right
now a reduced-motion user gets a page where nothing acknowledges hover or focus at all.

**On not re-litigating the documented decision.** `DESIGN.md:356` and `:358` argue this block, and
the argument is correct as written: *"Under `prefers-reduced-motion` the sequence resolves to its
final state instantly; it does not become a fast animation"* — **the sequence**, meaning the
lamp's descent. That outcome does not depend on the blanket at all. It is already delivered twice
over, by JavaScript and by a specific rule:

```js
/* surfaces/website/frontend/index.html:2922–2926 — the descent is skipped entirely */
    if(reduce){
      [...finds].sort((a, b) => a.dataset.depth - b.dataset.depth).forEach(ignite);
      settle();
      return;
    }
```

```css
/* surfaces/website/frontend/index.html:1002 */
  .lamp{transition:none}
```

So this plan changes nothing the design document asked for. It removes collateral damage the
document does not claim.

## Problem — Part B: `:hover` is ungated

There is no `@media (hover: hover) and (pointer: fine)` anywhere in the file. On a touch device a
tap fires a hover, and the hovered state then sticks until something else is tapped. Eight rules
are affected; the most visible is the primary control, which keeps a cyan glow after being
pressed:

```css
/* surfaces/website/frontend/index.html:404 — current */
.btn:hover:not(:disabled){background:var(--thermo-lift);box-shadow:0 6px 22px -6px rgb(var(--ch-thermo) / .55)}
```

These are colour, background and box-shadow only — no transforms — which is why this is LOW and
not MEDIUM. The page is also responsive down to 375px (`DESIGN.md` documents a ≤860px breakpoint),
so touch is a real target, not a hypothetical.

## Target — Part A

```css
/* target — replaces surfaces/website/frontend/index.html:989–1003 */
/* Reduced motion removes travel, not feedback. A request to stop things moving is not a
   request to strip the colour that says a control heard you — so the property list is narrowed
   to the things that do not move, and they keep a short duration instead of being zeroed. The
   iteration cap is still the point for the pulse: an infinite animation given a near-zero
   duration flickers, which is the opposite of what was asked for. The lamp's descent does not
   depend on this block at all — `prove()` skips the sequence outright when the setting is on. */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{
    transition-property:opacity,color,background-color,border-color,fill,stroke,box-shadow,text-shadow!important;
    transition-duration:.2s!important;transition-delay:0ms!important;
    animation-duration:1ms!important;animation-delay:0ms!important;
    animation-iteration-count:1!important;
    scroll-behavior:auto!important;
  }
  .btn.running .icon{animation:none;opacity:.75}
  .lamp{transition:none}
}
```

Restricting `transition-property` is what removes the movement: `transform` is not on the list, so
no transform transition can run — it snaps to its end state instead. That is the correct outcome
for every transform in the file and for the entrances plans 006–008 add.

`.2s` matches the value AUDIT.md gives for a reduced-motion colour transition.

## Target — Part B

Each of the eight `:hover` rules wrapped **in place**, so cascade order is unchanged. Specificity
is unaffected — a media query adds none. Example:

```css
/* target — surfaces/website/frontend/index.html:404 */
@media (hover:hover) and (pointer:fine){
  .btn:hover:not(:disabled){background:var(--thermo-lift);box-shadow:0 6px 22px -6px rgb(var(--ch-thermo) / .55)}
}
```

## Repo conventions to follow

- This file's comments explain the decision and name the failure it prevents. The existing comment
  at lines 989–993 is itself the exemplar — the replacement must be just as specific about *why*,
  because the next reader will otherwise re-add the blanket.
- Media queries in this file are written without spaces inside the parentheses:
  `@media (prefers-reduced-motion:reduce)` (line 994), `@media (max-width:860px)`. Match that:
  `@media (hover:hover) and (pointer:fine)`.
- Declarations are dense and multi-per-line. Do not reformat to one-per-line.

## Steps

1. Replace lines 989–1003 wholesale with the **Target — Part A** block above, comment included.

2. Wrap each of these eight rules in `@media (hover:hover) and (pointer:fine){ … }` at its current
   position. Do not move any rule to a new location in the file — wrap where it sits, indenting the
   wrapped rule by two spaces:

   | Line | Rule to wrap |
   | --- | --- |
   | 404 | `.btn:hover:not(:disabled){…}` |
   | 419–420 | `.btn.ghost:hover:not(:disabled){…}` — a two-line rule; wrap both lines together |
   | 480 | `.taint a:hover .edge{stroke:var(--snow)}` |
   | 481 | `.taint a:hover .cap,.taint a:hover .src-cap{fill:var(--snow)}` |
   | 540 | `.reveal:hover{…}` |
   | 566 | `.linkbtn:hover{color:var(--snow)}` |
   | 631 | `.find:hover{background:rgb(var(--ch-wash) / .035)}` |
   | 738 | `.mini:hover{…}` |
   | 819 | `.runlog-list .e:hover{…}` |

   Lines 480 and 481 are adjacent and belong to the same interaction — wrap them in one media
   block rather than two.

3. Do **not** wrap line 138, `::-webkit-scrollbar-thumb:hover`. A scrollbar thumb is not a touch
   target and the pseudo-element does not fire a sticky hover.

## Boundaries

- Do NOT remove `.lamp{transition:none}` (line 1002) or `.btn.running .icon{animation:none;opacity:.75}`
  (line 1001). Both are still needed.
- Do NOT touch the JavaScript reduced-motion handling — `MOTION`/`reduce`/`motionJobs`
  (lines 1417–1423), the `if(reduce)` branch in `prove()` (2922), or the `scrollIntoView`
  branches at 2978 and 2999. They are correct and this plan depends on them.
- Do NOT add `transform` to the reduced-motion `transition-property` list. Its absence is the
  mechanism.
- Do NOT relocate any `:hover` rule to a new part of the stylesheet.
- Do NOT touch `DESIGN.md`.
- Do NOT add new dependencies.
- If any "current" excerpt does not match the file, STOP and report.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all pass.
  - `grep -c 'hover:hover' surfaces/website/frontend/index.html` must return `8`.
  - `grep -n 'transition-duration:1ms' surfaces/website/frontend/index.html` must return nothing.
- **Feel check, reduced motion** — DevTools → Rendering → **Emulate CSS `prefers-reduced-motion: reduce`**:
  - Hover the **Arm & prove** button: the background must still shift to `--thermo-lift` over a
    short fade. Before this change it snapped; if it still snaps, `transition-property` is wrong.
  - Focus a form field with Tab: the border must still ease to cyan, and the focus ring must
    appear immediately.
  - Run a demo analysis and press **Arm & prove**: every finding must light **at once**, with no
    lamp travel and no per-finding sequencing. The bulbs and strength words should ease into their
    colours over ~200ms rather than snapping — that is the intended new behaviour, and it is the
    part most likely to be mistaken for a regression, so check it deliberately against
    `DESIGN.md:356`, which asks only that *the sequence* resolve instantly.
  - Confirm the lamp cone never travels down the column, and that the running icon does not pulse.
  - Confirm both marine-snow canvases are frozen.
- **Feel check, touch** — DevTools → device toolbar, iPhone preset (or a real phone at ≤860px):
  - Tap **Arm & prove** and then tap elsewhere. The button must not keep its cyan glow.
  - Tap a finding row, then scroll. The row must not stay highlighted.
- **Feel check, desktop regression** — with both emulations off, confirm every hover in the table
  above still works: primary button, ghost button, taint lane, reveal, sign-out link, finding row,
  mini buttons, and a full-run-log entry. A wrapped rule that lost its closing brace shows up here
  as one dead hover.
- **Done when**: reduced motion keeps colour feedback and drops all travel, touch no longer sticks
  a hover, all nine desktop hovers still work, and the 46 website tests pass.
