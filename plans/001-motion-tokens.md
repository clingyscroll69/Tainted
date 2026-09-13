# 001 — Lift the motion values into `:root` tokens

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (this project is **not** a git repository, so there is no commit to cite; verify the hash
  with `shasum -a 256 surfaces/website/frontend/index.html` before starting)
- **Severity**: LOW
- **Category**: 7 — Cohesion & tokens
- **Estimated scope**: 1 file, ~12 added lines + ~14 in-place substitutions

## Problem

`surfaces/website/frontend/index.html` defines roughly sixty colour, shadow and font tokens in
`:root` (lines 34–114) and **zero motion tokens**. Nine distinct durations are hand-typed across
the stylesheet, and the product's one signature curve exists only as a string literal inside
JavaScript:

```js
/* surfaces/website/frontend/index.html:2942 — current */
      lamp.style.transition = 'transform .62s cubic-bezier(.22,.61,.36,1), opacity .5s ease-out';
```

`DESIGN.md:358` documents the motion system in prose — "the lamp's descent
(`transform .62s cubic-bezier(.22,.61,.36,1)`), with state changes carried by 0.45–0.6s ease-out
colour transitions". Because none of those values is named in the code, that paragraph cannot be
checked against the stylesheet; it can only be trusted. Every later plan in this directory also
needs to reference these values, and inlining them nine more times is how the drift the colour
tokens exist to prevent arrives in the motion layer.

There is a second, hidden coupling. The descent's step interval is a magic number that must stay
just above the transition it waits for:

```js
/* surfaces/website/frontend/index.html:2939–2945 — current */
    (function next(){
      if(step >= order.length){ setTimeout(settle, 480); return; }
      const el = order[step];
      lamp.style.transition = 'transform .62s cubic-bezier(.22,.61,.36,1), opacity .5s ease-out';
      setLampPct(depthToPct(+el.dataset.depth) - 14);
      setTimeout(() => { ignite(el, step); step++; next(); }, 640);
    })();
```

`640` is `620 + 20`. Nothing says so, and nothing breaks loudly if someone changes `.62s`.

## Target

Tokens added to the end of the `:root` block, **immediately before the `--ff-*` font tokens**, so
the block reads colour → shadow → motion → type:

```css
/* target — surfaces/website/frontend/index.html, inside :root, before line 111 */

  /* Motion. DESIGN.md's "Motion" section is the spec for these values; naming them here is
     what lets the document be checked against the stylesheet instead of trusted. The spread
     of state durations is deliberate and documented as a band (0.45–0.6s) — it is named, not
     collapsed. Collapsing it is a design decision, not a refactor. */
  --ease-lamp:cubic-bezier(.22,.61,.36,1); /* the descent — the one authored moment */
  --dur-field:.15s;        /* a field's border answering focus */
  --dur-control:.18s;      /* a control's hover and press */
  --dur-state:.45s;        /* a state change lands */
  --dur-state-mid:.5s;     /* the same change, one step slower */
  --dur-state-slow:.55s;   /* carried across the taint graph */
  --dur-verdict:.6s;       /* the headline's ink */
  --dur-descent:.62s;      /* one step of the lamp's descent — keep in SECONDS, see step 4 */
  --dur-pulse:1.15s;       /* the running icon */
```

**No value changes.** This plan renames; it does not retune. Every duration in the file must be
byte-for-byte the same number after this change as before it.

## Repo conventions to follow

- All tokens live in the single `:root` block at `surfaces/website/frontend/index.html:34–114`.
  Nothing else in the file declares custom properties. Add to that block; do not create a second one.
- Tokens carry a comment explaining the *decision*, not the value. Imitate the exemplar at
  lines 100–102: `/* The last literals. A control's ink, its hover, a field's sunk ground and the
  browser surfaces belong to the world too; retyping them per rule is the drift every other token
  here exists to prevent. */`
- JavaScript reads tokens through the helper that already exists for this purpose — do not call
  `getComputedStyle` again:
  ```js
  /* surfaces/website/frontend/index.html:1426–1427 — the exemplar */
    const CSS = getComputedStyle(document.documentElement);
    const tok = (name, fallback) => (CSS.getPropertyValue(name) || '').trim() || fallback;
  ```
  `tok` is in scope at line 2942 — both are inside the same top-level IIFE, and `particulate`
  already uses it at line 1449 (`const ink = tok('--snow', '#F4F6FA');`). Always pass the literal
  fallback, exactly as that exemplar does.

## Steps

1. In `surfaces/website/frontend/index.html`, insert the motion token block from **Target** into
   `:root` between line 109 (`--panel-shadow:...;`) and the blank line before line 111
   (`--ff-display:...`).

2. Replace each duration literal with its token. These are the only sites; every one is a
   1:1 substitution of an identical value:

   | Line | Current fragment | Becomes |
   | --- | --- | --- |
   | 355 | `transition:opacity .45s ease-out;` | `transition:opacity var(--dur-state) ease-out;` |
   | 386 | `transition:color .6s ease-out;` | `transition:color var(--dur-verdict) ease-out;` |
   | 402 | `transition:background .18s ease-out,box-shadow .18s ease-out,transform .18s ease-out;` | `transition:background var(--dur-control) ease-out,box-shadow var(--dur-control) ease-out,transform var(--dur-control) ease-out;` |
   | 415 | `animation:pulse 1.15s ease-in-out infinite` | `animation:pulse var(--dur-pulse) ease-in-out infinite` |
   | 433 | `transition:color .5s ease-out,text-shadow .5s ease-out;` | `transition:color var(--dur-state-mid) ease-out,text-shadow var(--dur-state-mid) ease-out;` |
   | 449 | `transition:stroke .55s ease-out,stroke-width .55s ease-out}` | `transition:stroke var(--dur-state-slow) ease-out,stroke-width var(--dur-state-slow) ease-out}` |
   | 451 | `transition:fill .55s ease-out,stroke .55s ease-out}` | `transition:fill var(--dur-state-slow) ease-out,stroke var(--dur-state-slow) ease-out}` |
   | 452 | `.taint .sink{transition:fill .55s ease-out,stroke .55s ease-out}` | `.taint .sink{transition:fill var(--dur-state-slow) ease-out,stroke var(--dur-state-slow) ease-out}` |
   | 454 | `transition:fill .55s ease-out}` | `transition:fill var(--dur-state-slow) ease-out}` |
   | 517 | `transition:border-color .15s ease}` | `transition:border-color var(--dur-field) ease}` |
   | 538 | `transition:color .15s,background .15s;` | `transition:color var(--dur-field),background var(--dur-field);` |
   | 629 | `transition:background .5s ease-out;` | `transition:background var(--dur-state-mid) ease-out;` |
   | 642 | `transition:background .45s ease-out,box-shadow .45s ease-out,border-color .45s ease-out;` | `transition:background var(--dur-state) ease-out,box-shadow var(--dur-state) ease-out,border-color var(--dur-state) ease-out;` |
   | 647 | `transition:color .45s ease-out;` | `transition:color var(--dur-state) ease-out;` |
   | 736 | `transition:border-color .18s,color .18s,background .18s;` | `transition:border-color var(--dur-control),color var(--dur-control),background var(--dur-control);` |

   Line 629 is retuned by plan **005** afterwards. Leave it as the token substitution here.

3. Replace the JS transition string at line 2942 so the descent reads its curve from the token:

   ```js
   /* target — surfaces/website/frontend/index.html:2942 */
         lamp.style.transition =
           'transform ' + DESCENT + ' ' + tok('--ease-lamp', 'cubic-bezier(.22,.61,.36,1)') +
           ', opacity ' + tok('--dur-state-mid', '.5s') + ' ease-out';
   ```

4. Derive the step interval from the same token instead of the magic `640`. Add these two lines
   immediately after `let step = 0;` (line 2938), and use `STEP_MS` in the `setTimeout` on line 2944:

   ```js
   /* target — surfaces/website/frontend/index.html, after line 2938 */
       const DESCENT = tok('--dur-descent', '.62s');
       /* the step waits out the descent it started, plus a frame — so the token is the only
          number, and changing it cannot leave the two out of step */
       const STEP_MS = Math.round(parseFloat(DESCENT) * 1000) + 20;
   ```

   Then line 2944 becomes:

   ```js
         setTimeout(() => { ignite(el, step); step++; next(); }, STEP_MS);
   ```

   `parseFloat` reads seconds. **`--dur-descent` must stay in seconds** (`.62s`, not `620ms`) or
   `STEP_MS` becomes 620020. The comment in the token block says so; keep it.

5. Leave the `1ms` values inside the `prefers-reduced-motion` block (lines 996–997) as literals.
   They are not part of the motion scale — they are its removal, and plan 004 rewrites that block.

## Boundaries

- Do NOT change a single duration or curve **value**. This plan is a rename. If a substitution
  would alter a number, stop and report it.
- Do NOT touch `DESIGN.md`.
- Do NOT collapse `--dur-state` / `--dur-state-mid` / `--dur-state-slow` / `--dur-verdict` into
  one token. The 0.45–0.6s spread is a documented design decision (`DESIGN.md:358`); changing it
  is not this plan's call.
- Do NOT add new dependencies, a build step, or a separate stylesheet. This project ships one
  HTML file with an inline `<style>`.
- Do NOT reformat surrounding CSS. The file's house style is dense multi-declaration lines; match it.
- If a line's current content does not match the "Current fragment" column (drift since the hash
  above), STOP and report rather than guessing which line was meant.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all must still pass. `tests/test_sandbox_and_frontend.py` asserts against the frontend.
  - `grep -nE '(transition|animation):[^;]*[0-9]+(\.[0-9]+)?m?s' surfaces/website/frontend/index.html`
    must return **only** the two lines inside the `prefers-reduced-motion` block (996–997) and the
    `@keyframes pulse` definition if it carries no duration. Any other hit is a missed substitution.
  - `grep -c 'cubic-bezier(.22,.61,.36,1)' surfaces/website/frontend/index.html` must return `2`:
    the token definition and the JS fallback argument.
- **Feel check**: open the page, fill the repository field with the demo (`Try it with demo/demo`
  button), press **Analyze**, then **Arm & prove**, and confirm:
  - the lamp still descends one stop per finding, and each finding's bulb lights **after** the lamp
    arrives rather than while it is still moving — if `STEP_MS` were computed wrong the two would
    desynchronise visibly on the first step;
  - the descent takes the same wall-clock time as before the change (time it with a stopwatch on a
    9-candidate demo run before and after — the difference should be under half a second total).
- **Done when**: the `grep` sweeps above are clean, the 46 website tests pass, and a demo run is
  indistinguishable from one recorded before the change.
