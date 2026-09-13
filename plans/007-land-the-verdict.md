# 007 — Land the verdict instead of teleporting it

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (not a git repository; verify with `shasum -a 256 surfaces/website/frontend/index.html`)
- **Severity**: MEDIUM (additive — a missed opportunity, not a defect)
- **Category**: 8 — Missed opportunities
- **Estimated scope**: 1 file, ~10 added CSS lines, 2 changed JS lines
- **Depends on**: plan **001** for `--ease-lamp` and the `:root` motion block. If 001 has not
  run, substitute the literal `cubic-bezier(.22,.61,.36,1)` and add `--dur-verdict-in:.34s` to
  `:root` on its own.

## Problem

`settle()` rewrites the page's headline in a single frame at the end of a multi-second descent:

```js
/* surfaces/website/frontend/index.html:2642–2645 — current */
    verdict.className = 'verdict ' + (n.proven ? 'open' : 'unproven');
    verdict.innerHTML = n.proven ? '<span>Do not</span> <span>ship</span>'
      : reported ? '<span>Reported,</span> <span>unproven</span>'
                 : '<span>Nothing</span> <span>reached</span>';
```

The element already transitions its ink:

```css
/* surfaces/website/frontend/index.html:382–391 — current */
.verdict{
  font-family:var(--ff-display);font-weight:700;
  font-size:clamp(2.5rem,5.1vw,4.375rem);line-height:.94;letter-spacing:-.022em;
  text-transform:uppercase;margin-bottom:15px;max-width:13ch;
  transition:color .6s ease-out;
}
/* Two lines, not a <br>: the accessible name needs the word break the eye already gets. */
.verdict span{display:block}
.verdict.open{color:var(--lamp)}
.verdict.unproven{color:var(--wash)}
```


So at the payoff moment the colour crosses over for 600ms **while the words underneath it swap
instantly**. Whatever the headline said before is replaced mid-fade, which reads as a rendering
glitch rather than a result arriving. This is a 70px display line — the largest type on the page,
and the sentence the whole product exists to produce.

**Purpose:** state indication. **Frequency:** rare — once per run, and a run is a deliberate
multi-second act. AUDIT.md puts this in the tier where the delight budget is allowed to be spent.

The markup is already built for it. `verdict.innerHTML` writes **two block-level `<span>`s** —
"Do not" / "ship" — deliberately, so the accessible name gets the word break (see the comment at
line 388 and at 2085–2086). That is a ready-made two-step stagger with no markup change needed.

## Target

```css
/* target — appended after surfaces/website/frontend/index.html:391 */
/* The verdict is the one sentence this product exists to produce, and it used to be swapped in
   underneath its own 600ms colour crossfade — which reads as a glitch, not a result. It lands
   on the lamp's own curve, because it is the last beat of the same moment. `.lands` is set only
   where JavaScript writes the headline, so the line the page ships with does not fade in on
   first paint. The first line carries no delay: motion here must never read as withholding the
   verdict. */
.verdict.lands span{
  opacity:1;transform:none;
  transition:opacity var(--dur-verdict-in) ease-out,
             transform var(--dur-verdict-in) var(--ease-lamp);
}
.verdict.lands span:nth-child(2){transition-delay:70ms}
@starting-style{
  .verdict.lands span{opacity:0;transform:translateY(10px)}
}
```

Token, added to the `:root` motion block:

```css
  --dur-verdict-in:.34s;   /* the headline landing */
```

Total 410ms including the stagger — inside AUDIT.md's 200–500ms modal/drawer budget, which is the
right band for a rare, deliberate moment.

### Why `--ease-lamp` for the transform

`cubic-bezier(.22,.61,.36,1)` is the descent's curve (`DESIGN.md:358`). Reusing it means the
verdict settles with the same physics as the lamp that produced it, and adds no new curve to a
file that has exactly one. The opacity stays on plain `ease-out`.

### Why `.lands` is load-bearing

`@starting-style` applies the first time an element is rendered, **including on initial page
load** — and the served markup already contains two spans:

```html
<!-- surfaces/website/frontend/index.html:1066 -->
      <h1 class="verdict unproven" id="verdict"><span>Nothing</span> <span>analysed yet</span></h1>
```

Without a gate, the headline would fade up on every page load. `verdict.className` is *replaced*
(not appended to) at three sites, which makes the gate easy to place precisely:

| Line | Site | Should it land? |
| --- | --- | --- |
| 2642 | `settle()` — the run's verdict | **yes** |
| 2092 | `announceCandidates()` — "Nine candidates / unproven" after Analyze | **yes** |
| 2263 | `clearResult()` — reset to "Nothing analysed yet" | **no** — a teardown, not a result |

## Repo conventions to follow

- Comments name the decision and the failure avoided. Keep the ones in the target; the `.lands`
  gate will otherwise be simplified away.
- The stylesheet's own precedent for a class that exists purely to carry state into CSS:
  `.water.running` (line 378) and `.btn.running` (line 411). `.lands` follows that shape.
- Motion tokens go in the single `:root` block before the `--ff-*` tokens.
- `verdict` is declared at line 1627 and is in scope at all three call sites.

## Steps

1. Add `--dur-verdict-in:.34s;` to the `:root` motion token block, after `--dur-enter` (or after
   `--dur-pulse` if plan 006 has not run).

2. Append the **Target** CSS immediately after line 391 (`.verdict.unproven{color:var(--wash)}`),
   comment included.

3. In `settle()`, replace line 2642:

   ```js
   /* current */
       verdict.className = 'verdict ' + (n.proven ? 'open' : 'unproven');
   ```

   with:

   ```js
   /* target */
       verdict.className = 'verdict lands ' + (n.proven ? 'open' : 'unproven');
   ```

4. In `announceCandidates()`, replace line 2092:

   ```js
   /* current */
       verdict.className = 'verdict unproven';
   ```

   with:

   ```js
   /* target */
       verdict.className = 'verdict lands unproven';
   ```

5. Leave line 2263 (inside `clearResult()`) as `verdict.className = 'verdict unproven';` — no
   `lands`. Clearing the surface is not a result arriving, and dropping the class here is also
   what re-arms the entrance for the next real write.

## Deliberately out of scope

`settle()` also rewrites `#deckline` (line 2658) and `#rest` (line 2635) in the same frame, and
the sweep that produced this plan considered staggering all three. Two reasons not to:

1. **It would not work as written.** `@starting-style` applies to newly-rendered *elements*.
   `#deckline` and `#rest` are persistent `<p>` elements whose `innerHTML` changes — the elements
   themselves are never re-rendered, so no starting style fires. Animating them would require
   wrapping their written content in a `<span>` inside the JS string, i.e. a markup change.
2. **Three staggered elements is too much.** The verdict at 410ms is already the outer edge of
   what a security result can afford before motion starts reading as withholding it.

Do not add them. If a future plan does, it is a separate decision with a separate argument.

## Boundaries

- Do NOT remove or change `transition:color .6s ease-out` on `.verdict` (line 386). The ink
  crossfade is documented (`DESIGN.md:358`) and correct; this plan adds the words landing *with*
  it, it does not replace it.
- Do NOT add `lands` at line 2263.
- Do NOT give `span:nth-child(1)` a delay. The first line must be readable immediately.
- Do NOT animate `#deckline`, `#rest`, `#obscount`, or the readout numerals. See above.
- Do NOT change the `<span>` structure or add a `<br>` — the comment at line 388 explains why
  the spans exist, and the accessible name depends on them.
- Do NOT use `@keyframes`, and do NOT exceed 500ms total including the stagger.
- Do NOT add new dependencies.
- If any "current" excerpt does not match the file, STOP and report.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all pass. `tests/test_sandbox_and_frontend.py` and `tests/test_demo.py` both assert on rendered output; if either fails, report rather than adjusting the test.
  - `grep -c "verdict lands" surfaces/website/frontend/index.html` returns `2`.
  - `grep -n "verdict.className = 'verdict unproven'" surfaces/website/frontend/index.html`
    returns exactly one line: 2263.
- **Feel check**:
  1. Load the page. The headline **"Nothing analysed yet"** must be visible immediately with no
     fade or movement. If it rises into place, the `.lands` gate is wrong — the single most
     likely mistake in this plan.
  2. Press **Try it with `demo/demo`** → **Analyze**. The headline changes to "Nine candidates /
     unproven" and **should** land: first line, then second 70ms behind it.
  3. Press **Arm & prove** and watch the headline at the end of the descent. "Do not ship" must
     rise into place on the second line 70ms behind the first, while the ink warms to
     `--lamp` over the existing 600ms.
  4. In DevTools → Animations panel at **10% playback**, confirm: the two lines are offset by a
     visible beat, both end flush (no residual `transform`), and the colour transition is
     *longer* than the movement — the words should finish arriving while the ink is still warming.
     If the words finish after the colour, `--dur-verdict-in` is too large.
  5. Press **Re-run** and confirm it lands again — the class is already present, and
     `@starting-style` must still fire because the spans are new elements each time. If the second
     run teleports, the spans are being reused somewhere and this plan needs rethinking; report it.
  6. Press **Analyze** again from a settled state: `clearResult()` runs, the headline resets to
     "Nothing analysed yet" — confirm that reset **teleports** (no landing), then the new
     candidate count lands.
  7. DevTools → Rendering → **Emulate CSS `prefers-reduced-motion: reduce`** and re-run: the
     words must appear with a short fade and **no** movement, and the stagger delay must be gone
     (plan 004 zeroes `transition-delay`). Confirm the verdict is still fully legible the instant
     it appears.
  8. Screen-reader sanity check, because `#verdictlive` is `aria-live="polite"` (line 1065): with
     VoiceOver on (Cmd+F5 on macOS), run a demo and confirm the verdict is announced once and
     reads as "Do not ship" — not "Do notship" and not twice. Animation should not affect this;
     confirm it did not.
- **Done when**: the shipped headline never animates, both JS-written headlines land, the reset
  teleports, the 10% playback check is clean, and the 46 website tests pass.
