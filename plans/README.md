# Animation plans — Tainted website surface

Eight plans from an `improve-animations` audit of `surfaces/website/frontend/index.html`
(2026-09-05). That one file is the entire web surface: vanilla HTML, an inline `<style>`, an
inline IIFE, no framework, and no motion library. Every plan is scoped to it.

**Stamp.** This project is **not** a git repository, so plans cite a file hash instead of a
commit: `surfaces/website/frontend/index.html` sha256 `1d67baaf858962…`. Before starting any
plan, run

```
shasum -a 256 surfaces/website/frontend/index.html
```

and confirm the prefix matches. If it does not, the line numbers in that plan have drifted — the
plan's Boundaries section tells you to stop and report rather than improvise, and that still
applies.

**The stamp no longer matches, and that is expected.** All eight plans are done, and the file has
since changed again: the flat taint graph in the water column was removed (2026-09-05) because the
sounding already tells that story, and the water column now holds a doorway back into it instead.
These plans are a record of work completed, not a queue — do not re-run them against the current
file.

## Plans

| # | Title | Severity | Category | Status |
| --- | --- | --- | --- | --- |
| [001](001-motion-tokens.md) | Lift the motion values into `:root` tokens | LOW | 7 Cohesion & tokens | **DONE** |
| [002](002-cancel-the-descent.md) | Give the descent a cancellation token | **HIGH** | 4 Interruptibility | **DONE** |
| [003](003-frame-rate-independent-snow.md) | Make the marine snow frame-rate independent | **HIGH** | 5 Performance | **DONE** |
| [004](004-narrow-the-reduced-motion-reducer.md) | Narrow the reduced-motion reducer; gate `:hover` for touch | MEDIUM / LOW | 6 Accessibility | **DONE** |
| [005](005-hover-duration-on-finding-rows.md) | Take the finding row's hover off the state-change duration | MEDIUM | 2 Easing & duration | **DONE** |
| [006](006-proof-log-row-entrance.md) | Give proof-log rows an entrance | MEDIUM | 8 Missed opportunities | **DONE** |
| [007](007-land-the-verdict.md) | Land the verdict instead of teleporting it | MEDIUM | 8 Missed opportunities | **DONE** |
| [008](008-write-the-fix-flow.md) | Busy state and patch entrance for "Write the fix" | MEDIUM / LOW | 8 Missed opportunities | **DONE** |

## Recommended execution order

Run them in numerical order. It is not arbitrary — 001 is first because it is the enabling change,
and the two HIGHs come before the additive work so a stranded-timer bug is not competing for
review attention with an entrance animation.

```
001  ──┬── 005   (needs --dur-control)
       ├── 006   (needs the :root motion block; adds --dur-enter)  ──┐
       └── 007   (needs --ease-lamp)                                 │
                                                          008 ───────┘  (needs --dur-enter)
002  (independent)
003  (independent)
004  (independent; changes what 006/007/008 do under reduced motion)
```

### Dependencies

| Plan | Depends on | Nature |
| --- | --- | --- |
| 005 | 001 | Uses `var(--dur-control)`. Each plan states its literal fallback, so it can run standalone. |
| 006 | 001 | Adds `--dur-enter` to the token block 001 creates. |
| 007 | 001 | Uses `var(--ease-lamp)` and adds `--dur-verdict-in`. |
| 008 | 006 | Uses `--dur-enter`. Also interacts with **004**: if 004 has run, `.mini:hover` is inside a `@media (hover:hover)` block and the new `.mini.running` rules go *after* it. |
| 002 | — | Independent. If 001 has run first, keep its `STEP_MS`/`tok()` forms and change only the guards. |
| 003 | — | Fully independent; touches one function nothing else in this directory goes near. |
| 004 | — | Independent, but it decides how 006, 007 and 008 behave under `prefers-reduced-motion` (their entrances keep the fade and drop the movement). Run it *before* them if you want that verified in one pass. |

Every plan names its own fallback for a token it does not own, so any single plan can be executed
in isolation. Running 001 first simply means none of the fallbacks are needed.

## What this audit did not report

Recorded so a later pass does not re-raise settled questions:

- **The 0.45–0.6s state-change band** and the lamp's 620ms descent are argued in `DESIGN.md:358`
  and were not re-litigated. Plan 001 names those values; it does not change them. Plan 005 moves
  *one* declaration out of the band on the grounds that a hover is not a state change — that is
  the only place this audit touched it.
- **The blanket reduced-motion reducer's stated purpose** is correct and plan 004 preserves it.
  004 removes collateral damage (colour-only feedback), not the documented behaviour.
- **Clean on inspection**: no `ease-in` anywhere, no `transition: all`, no `scale(0)`, no animated
  layout properties, no `transform-origin` errors — there is nothing trigger-anchored on this
  surface, no menus, popovers or tooltips.
- **The canvas layer** (lines 1443–1519) already clamps its backing store, gates on
  `visibilitychange` and `IntersectionObserver`, watches the element rather than the window, and
  honours a mid-session `prefers-reduced-motion` change. Plan 003 is the one thing wrong with it.
- **Entrance animations inside `#findings` at ignite time** were considered and rejected:
  `#findings` sits in `.below` while the Arm control and the lamp are in `.water`, so anything
  animating there during a descent happens off-screen. That is why 006 targets the proof log —
  the one animatable surface that is actually visible while the lamp descends.
- **A count-up on the two readout numerals** was rejected: they are the run's load-bearing
  numbers, and rolling 0→7 prints counts the engine never measured.
- **A draw-in on the coverage bars** was rejected on the design document's own argument — the
  mark differs in kind (solid cyan vs. broken amber), not in length, and animating length
  reintroduces the fraction reading `DESIGN.md` deliberately removed.

## Execution results (2026-09-05)

All eight applied to `surfaces/website/frontend/index.html`, in numerical order.
File hash moved `1d67baaf858962` -> `3fcfb990961440`. Original snapshot kept during the run so
the before/after below could be measured, then discarded.

No git worktree was used: this project is untracked, so the skill's `execute` isolation was not
available. Every edit was applied as an **asserted exact-string replacement** (a helper that
refuses to write unless the target text matches exactly once), never by line number, because
each plan's line numbers are relative to the original file and shift as earlier plans land.

### Gates, all passing

| Gate | Result |
| --- | --- |
| Website tests | 46 passed |
| CLI / CI / MCP tests | 12 / 11 / 11 passed |
| Core tests | 127 passed, **1 pre-existing failure** (`test_orchestrator_planes.py::test_every_candidate_produces_a_finding_none_are_silently_dropped`) — fails identically before any edit; in the engine, not this surface, and out of scope |
| JS syntax | `node --check` on the extracted script: clean after every plan |
| CSS braces | balanced after every plan (440 pairs) |
| Stray duration literals | 0 outside the token block |
| Lamp-curve literals | 2 (token definition + JS fallback) |
| `runSeq` occurrences | 7 |
| `hover:hover` gates | 8 |
| Old blanket reducer | 0 occurrences |
| `@starting-style` blocks | 3 (log rows, verdict, patch) |
| `verdict lands` sites | 2 (settle + announceCandidates; **not** clearResult) |
| Patch button disabled *after* `box.focus()` | confirmed by source order |

### Verified in a running browser

Served on `127.0.0.1:8931` and driven through the demo flow.

- **Tokens resolve**: `--ease-lamp: cubic-bezier(.22,.61,.36,1)`, `--dur-descent: .62s`, `--dur-enter: .26s`, `--dur-verdict-in: .34s`.
- **006's main hazard is clear**: on load `#prooflog` carries no `data-clean` attribute, so the shipped "Waiting for the lamp." row computes `opacity:1; transform:none` and does not fade in. After a run it is `data-clean="1"` and rows bind `opacity, transform` at `0.26s`.
- **007's main hazard is clear**: on load the headline is `class="verdict unproven"` with no `lands`, so it does not animate on first paint. `announceCandidates` and `settle` both add `lands`; `clearResult` does not. The second line resolves `transition-delay: 0.07s` and `cubic-bezier(0.22, 0.61, 0.36, 1)` — the lamp's curve, from the token.
- **003's trap is clear**: both canvases paint non-zero pixels, so the `dt === undefined` default is intact and no coordinate went `NaN`.
- **008 end to end**: two rapid clicks on "Write the fix" produced **exactly one** patch block (the `dataset.busy` re-entry guard), focus landed on the patch (`document.activeElement === .patch`), and only then was the button disabled.
- **No residual offset**: forcing every entrance transition to `finish()` leaves the patch, all nine log rows and both verdict spans at `opacity:1; transform:none` with zero live animations — the check the plans specified via the Animations panel.

### 002: the finding was real, and worse than the plan said

Reproduced on the original build, then confirmed fixed, with the same script both times:

| | original | fixed |
| --- | --- | --- |
| `#scan` during descent | **live** | disabled |
| submit mid-descent | tears down the surface | refused |
| stranded log rows appended | **8** | 0 |
| final verdict | **"Nothing reached", `data-lit=1`, 0 proven** | "Do not ship", 5 proven |

The plan predicted "a verdict about a repository the page is no longer showing". What actually
happens is a **false negative**: the stranded `settle()` counts the *new* analysis's nine
candidates, all still unlit, and stamps "Nothing reached" as a settled result. A security
scanner claiming a clean run it never performed is the worst direction this could break in.

### Deviations from the plans as written

1. **002** placed `let runSeq = 0;` beside `let armed = false;` — which sits ~350 lines *below*
   `clearResult()`, its first reader. It works (the TDZ resolves before any call) but is fragile,
   so it was moved up to the run-lifecycle cluster next to `finds` / `lastReport`. The plan's own
   stated convention ("declared next to the thing they guard") is better served there.
2. **008** step 8 anticipated that `.mini.running .icon` would keep pulsing under reduced motion
   because line 1001 only covers `.btn.running .icon`. It would have, so
   `.mini.running .icon{animation:none;opacity:.75}` was added alongside it. Hence three
   `mini.running` matches rather than the two the plan predicted.
3. Test counts in every plan said 23 website tests; the suite actually has **46**. Corrected
   throughout.

### Not verified — stated plainly

- **The snow's actual motion, and 003's payoff.** The automation tab reports
  `document.hidden === true` and `requestAnimationFrame` never fires in it, so the particulate
  loop is correctly stopped by the existing visibility gating and could not be watched. The
  arithmetic was instead unit-tested in isolation against the exact expressions now in the file:
  drift over 2s spans **4.80x** across 30–144Hz before the fix and **1.013x** after (the 1.3%
  residual is `16.667` vs the true frame time), and a 10s tab-restore gap clamps to 3 frames
  instead of 600. The fix is correct; nobody has yet *seen* it, and no 120Hz comparison was run.
- **Every animation's felt quality.** Transitions do not advance on a hidden tab — all three
  entrances were confirmed present as live `CSSTransition` objects in state `running` at
  `currentTime: 0`, and confirmed to end correctly when forced, but none was observed playing.
  Whether 260ms reads as "arriving" or "lagging", and whether 005's 3.5%-alpha hover change is
  perceptible at all, still needs a human watching a real run.
- **Reduced motion and touch (004).** `prefers-reduced-motion` cannot be toggled from page
  JavaScript, so the narrowed reducer and the eight `hover:hover` gates were verified by
  structure and cascade position only, not by emulation.
- **Screen-reader behaviour** (007 step 8, 008 step 5).

## Executing

These plans do not modify code by themselves. Either hand one to any agent, or run:

```
improve-animations execute plans/002-cancel-the-descent.md
```

which dispatches an executor in an isolated worktree and reviews the resulting diff. Note that a
worktree needs a git repository; if this project is still untracked, run the plan directly and
review the diff by hand instead.

Every plan carries a **Feel check** section. It is not optional — 002's whole verification is a
manual interruption reproduction, and 005 explicitly asks the executor to report honestly if the
improvement is not visible.

## Review pass (2026-09-05, after the eight plans)

A `review-animations` pass over the applied file found three things the audit had not, and
they were fixed in the same session. File hash moved `3fcfb990961440` -> `0a8f0d5b4e38f0`.

| # | What | Where |
| --- | --- | --- |
| R1 | **The taint graph's focus indicator animated.** `:521` removes the default outline, so the stroke and fill changes at `:522-524` *are* the lanes' only focus indicator — and they inherited the 0.55s proof band. A keyboard-reached indicator that takes half a second to appear. Fixed with `transition:none`. | `index.html` taint block |
| R2 | **Plan 005 fixed one of two hover surfaces.** `.taint a:hover` rode the same 0.55s band, and `.taint .src-cap` carried no transition at all — so one caption snapped while its sibling in the same rule took 550ms. | same |
| R3 | **`.lamp{transition:none}` in the reducer was dead.** The `*` rule two lines above declares `transition-property/duration/delay` with `!important`, which outranks a normal shorthand at any specificity. Removed, and the reason written into the block's comment. | reduced-motion block |

**R1 and R2 could not be fixed by duration alone.** A transition is resolved from the
*after-change* style, and "lit, not hovered" is the same computed style whether the lane just
lit up or the cursor just left it — so overriding the duration inside `:hover` buys a fast
hover-in and a 550ms hover-out. The band is therefore now **worn, not declared**: `syncTaint()`
puts `.landing` on a lane whose class actually changed and takes it off after
`--dur-state-slow`; the base rules carry the pointer's own `--dur-control`. Verified in a
browser: exactly one lane wears `.landing` at a time during a descent, zero after settle, and a
settled lit lane reads `stroke 0.18s` again.

Also changed in the same pass:

- **`#proved` deep links land settled.** `prove({instant:true})` skips the descent and the lamp.
  The comment at the address block always said the hash "carries straight through to the settled
  state"; the code played the full ~6s descent on every open of a shared link. `prove` now takes
  an options object, so the Arm listener calls `prove()` rather than *being* `prove` — an event
  object as the first argument would have read as `{instant: …}`.
- **`settle()` clears `armed`.** Pre-existing, and it made "Re-run" a live button that did
  nothing: `prove()` returned on its own first line. Predates plan 002, which quotes the three
  existing `armed = false` sites.
- **A press is not a hover.** New `--dur-press:.14s` for `.btn:active`; 180ms is right for the
  hover `--dur-control` also served, and outside the 100–160ms press band.
- **The fix button keeps its icon.** `btn.textContent` took the `<svg class="icon">` with it, so
  the acts row relaid out in the same instant the patch above it faded up. Only the label node is
  rewritten now, and the wrench becomes `#i-proof`.
- **`setLampPct` re-resolves on resize.** A percentage against a stale height put the lamp off
  its own depth scale. Deliberately not a snap — mid-descent the transform in flight retargets.
- **`will-change:transform` on `.water.running .lamp`**, scoped so an idle page holds no layer.

### Not changed, and why

- **`--dur-verdict:.6s`** still crossfades the headline's colour for 260ms after
  `--dur-verdict-in:.34s` has finished landing it. Bringing it to ~.4s would make the headline one
  gesture, but .4s is below the 0.45–0.6s band `DESIGN.md:358` argues, and that is a design
  decision, not a review's to make.
- **The `box-shadow` transitions** on `.beam .bulb` and `.btn:hover`. The blanket rule says animate
  only `transform`/`opacity`, but both elements transition `background` and `border-color` in the
  same breath, so they repaint either way — hoisting only the shadow onto an opacity layer removes
  no repaint and splits a designed mark into two.

### Not verified

- **The resize retarget.** `onResize` batches through `requestAnimationFrame`, which never fires
  in the automation tab (`document.hidden === true`) — the same wall plan 003 hit.
- **Reduced motion.** `prefers-reduced-motion` cannot be toggled from page JavaScript. The
  `.landing` guard is `!reduce`, so under the setting the graph keeps the reducer's own 200ms
  colour change; that is structure, not observation.
- **Felt quality**, as before. Transitions do not advance on a hidden tab.
