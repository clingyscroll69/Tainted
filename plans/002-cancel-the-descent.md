# 002 — Give the descent a cancellation token

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (not a git repository; verify with `shasum -a 256 surfaces/website/frontend/index.html`)
- **Severity**: HIGH
- **Category**: 4 — Interruptibility
- **Estimated scope**: 1 file, ~5 sites, ~14 added lines

## Problem

The lamp's descent is a recursive `setTimeout` chain with **no way to stop it**:

```js
/* surfaces/website/frontend/index.html:2937–2945 — current */
    const order = [...finds].sort((a, b) => a.dataset.depth - b.dataset.depth);
    let step = 0;
    (function next(){
      if(step >= order.length){ setTimeout(settle, 480); return; }
      const el = order[step];
      lamp.style.transition = 'transform .62s cubic-bezier(.22,.61,.36,1), opacity .5s ease-out';
      setLampPct(depthToPct(+el.dataset.depth) - 14);
      setTimeout(() => { ignite(el, step); step++; next(); }, 640);
    })();
```

A second run can be started while that chain is in flight. The form's submit handler has no
guard, and `#scan` is disabled only *inside* `analyze()` — so it is live for the whole descent:

```js
/* surfaces/website/frontend/index.html:2887 — current */
  document.getElementById('setup').addEventListener('submit', ev => { ev.preventDefault(); analyze(); });
```

```js
/* surfaces/website/frontend/index.html:2855–2857 — current */
  async function analyze(){
    const scan = document.getElementById('scan');
    scan.disabled = true;
```

Pressing **Analyze** — or just hitting Enter in any field of `#setup` — mid-descent calls
`clearResult()`, which tears the result surface down but cannot reach the chain:

```js
/* surfaces/website/frontend/index.html:2228–2234 — current */
  function clearResult(){
    lastReport = null;
    analysedKey = null;
    finds = [];
    findingsEl.innerHTML = '';
    emptyEl.hidden = false;
    armed = false;
```

What happens next, on a 9-candidate run interrupted at step 3:

1. `order` still holds the six remaining `.find` elements, now **detached** from the document.
   `ignite()` (line 2574) keeps running against them — adding classes nobody can see, and
   appending a proof-log row for each via `logEl.appendChild(li)` (line 2590) into a log the new
   analysis has just reset.
2. `syncTaint()` (line 1914) walks `laneFinds()` — rebuilt from the *new* `finds` — and maps
   `tg-<i>` lanes by index, so the water column lights lanes belonging to a different repository.
3. `settle()` fires 480ms after the last orphan and writes a verdict (`verdict.innerHTML`, line
   2643), the two big readout numerals, the strength counts, and `document.body.dataset.lit = '1'`
   (line 2683) **over the new, unproven surface**.
4. `clearResult()` never removes `running` from `#water`, so `.water.running .lamp{opacity:1}`
   (line 378) keeps the cone lit over a cleared page until that orphaned `settle()` gets to
   line 2682 and turns it off.

For this product that is the worst available failure. `DESIGN.md` states the rule the page is
built to keep — *"Don't print a strength word before the evidence exists… a claim of proof with
the evidence withheld is the one unforgivable move"* — and step 3 prints a verdict about a
repository the page is no longer showing.

## Target

A monotonic generation counter. Every descent captures the generation it belongs to and returns
the moment that generation is no longer current. `clearResult()` bumps it, so tearing down the
surface is by itself enough to strand every timer the old run owns.

```js
/* target */
    const seq = ++runSeq;
    ...
    (function next(){
      if(seq !== runSeq) return;               /* this descent's run no longer exists */
      if(step >= order.length){ setTimeout(() => { if(seq === runSeq) settle(); }, 480); return; }
      ...
      setTimeout(() => {
        if(seq !== runSeq) return;
        ignite(el, step); step++; next();
      }, STEP_MS);
    })();
```

Plus: `#scan` disabled for the duration of a run, and `clearResult()` putting the lamp back where
it found it.

## Repo conventions to follow

- Run-lifecycle flags are module-scoped `let`s declared next to the thing they guard. The
  exemplar is one line above where you will add the counter:
  ```js
  /* surfaces/website/frontend/index.html:2572 — the exemplar */
    let armed = false;
  ```
- Every guard in this file carries a comment saying *why*, in the words of the thing that goes
  wrong without it. Imitate lines 2891–2892: `/* aria-busy rather than disabled: taking the
  focused control out of the tree mid-run drops a keyboard user back to the top of the document. */`
- `water`, `lamp`, `armBtn` and `setLampPct` are all declared at lines 1610–1635, above both
  `clearResult()` (2228) and `prove()` (2889), inside the same IIFE. They are in scope in both.
- Enabling and disabling `#scan` already has a pattern — set it in the function that owns the
  work, clear it in that function's `finally` (lines 2857 and 2884). Follow it.

## Steps

1. Declare the counter beside `armed`. Replace line 2572:

   ```js
   /* current — surfaces/website/frontend/index.html:2572 */
     let armed = false;
   ```

   with:

   ```js
   /* target */
     let armed = false;
     /* A descent is a chain of timers, and the surface underneath it can be torn down by
        Analyze at any point. The generation is what lets a stranded timer notice that the run
        it belongs to no longer exists — without it, `settle()` writes a verdict over whatever
        repository happens to be on screen when the chain runs out. */
     let runSeq = 0;
   ```

2. In `clearResult()`, bump the generation and put the lamp back. Replace line 2234
   (`    armed = false;`) with:

   ```js
   /* target — surfaces/website/frontend/index.html:2234 */
       armed = false;
       /* Any descent still in flight belongs to a run this call has just erased. */
       runSeq++;
       water.classList.remove('running');
       lamp.style.transition = 'none';
       setLampPct(6);
   ```

3. In `prove()`, capture the generation and take `#scan` out of reach. Replace lines 2889–2890:

   ```js
   /* current — surfaces/website/frontend/index.html:2889–2890 */
     async function prove(){
       if(armed) return; armed = true;
   ```

   with:

   ```js
   /* target */
     async function prove(){
       if(armed) return; armed = true;
       const seq = ++runSeq;
       /* Analyzing mid-descent strands this run's timers over a surface built from a different
          repository, so the control that would do it is closed for the length of the run. */
       document.getElementById('scan').disabled = true;
   ```

4. Guard the chain. Replace lines 2939–2945:

   ```js
   /* current — surfaces/website/frontend/index.html:2939–2945 */
       (function next(){
         if(step >= order.length){ setTimeout(settle, 480); return; }
         const el = order[step];
         lamp.style.transition = 'transform .62s cubic-bezier(.22,.61,.36,1), opacity .5s ease-out';
         setLampPct(depthToPct(+el.dataset.depth) - 14);
         setTimeout(() => { ignite(el, step); step++; next(); }, 640);
       })();
   ```

   with:

   ```js
   /* target */
       (function next(){
         if(seq !== runSeq) return;
         if(step >= order.length){ setTimeout(() => { if(seq === runSeq) settle(); }, 480); return; }
         const el = order[step];
         lamp.style.transition = 'transform .62s cubic-bezier(.22,.61,.36,1), opacity .5s ease-out';
         setLampPct(depthToPct(+el.dataset.depth) - 14);
         setTimeout(() => {
           if(seq !== runSeq) return;
           ignite(el, step); step++; next();
         }, 640);
       })();
   ```

   **If plan 001 has already run**, the `lamp.style.transition` line and the `640` will already
   read `DESCENT`/`tok(...)` and `STEP_MS`. Keep whatever is there; change only the guards.

5. Guard the reduced-motion branch the same way. Replace lines 2922–2926:

   ```js
   /* current — surfaces/website/frontend/index.html:2922–2926 */
       if(reduce){
         [...finds].sort((a, b) => a.dataset.depth - b.dataset.depth).forEach(ignite);
         settle();
         return;
       }
   ```

   with:

   ```js
   /* target */
       if(reduce){
         if(seq !== runSeq) return;
         [...finds].sort((a, b) => a.dataset.depth - b.dataset.depth).forEach(ignite);
         settle();
         return;
       }
   ```

6. Re-open `#scan` when the run ends, on both exits.

   In `settle()`, immediately after line 2683 (`    document.body.dataset.lit = '1';`) add:

   ```js
       document.getElementById('scan').disabled = false;
   ```

   In `fail()`, immediately after line 2846 (`    armed = false;`) add:

   ```js
       document.getElementById('scan').disabled = false;
   ```

7. Add the belt to the submit handler as well, so an Enter keypress cannot start an analysis
   while a run is live even if a future edit forgets the disabled attribute. Replace line 2887:

   ```js
   /* current */
     document.getElementById('setup').addEventListener('submit', ev => { ev.preventDefault(); analyze(); });
   ```

   with:

   ```js
   /* target */
     document.getElementById('setup').addEventListener('submit', ev => {
       ev.preventDefault();
       /* Enter in any field submits this form, and `#scan` being disabled does not stop that. */
       if(armed) return;
       analyze();
     });
   ```

## Boundaries

- Do NOT change the descent's timing, curve, order, or the 480ms settle delay. This plan adds
  guards only.
- Do NOT change `ignite()`, `settle()`, `syncTaint()` or `renderReport()` beyond the two
  single-line additions named in step 6.
- Do NOT use `AbortController`, a promise-based rewrite, or `async`/`await` in the chain. A
  counter is the whole fix; a rewrite is out of scope and will fail review.
- Do NOT make `armBtn` `disabled` during a run. That is deliberately avoided — see the comment
  at lines 2891–2892 and `DESIGN.md:330`. `aria-busy` and `.running` stay as they are.
- Do NOT add new dependencies.
- If any "current" excerpt above does not match the file, STOP and report.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all pass.
  - `grep -c 'runSeq' surfaces/website/frontend/index.html` must return `7` (declaration, bump in
    `clearResult`, capture in `prove`, and four comparisons).
- **Feel check** — this is the one that matters, and it is a two-minute manual reproduction.
  Serve the site (`PYTHONPATH=.:surfaces/website python -m surfaces.website.backend.run`, or
  however the repo's README starts it), then:
  1. Press **Try it with `demo/demo`**, then **Analyze**, then **Arm & prove**.
  2. While the lamp is still descending — around the third or fourth finding — click into the
     repository field and press **Enter**.
  3. **Before the fix**: the proof log keeps filling with rows, the water column lights lanes,
     and a few seconds later a verdict ("Do not ship" or "Reported, unproven") appears over a
     page whose Observations list is empty or freshly re-analysed. That is the bug.
  4. **After the fix**: the descent stops dead at the moment of the interruption, the cone goes
     out, the lamp returns to the surface, no further log rows arrive, and no verdict is ever
     written. The new analysis renders normally.
  5. Repeat once more, interrupting on the *very first* step, and once interrupting during the
     480ms gap after the last finding — the verdict must not appear in either case.
  6. Confirm the normal path is untouched: a full uninterrupted demo run still lights every
     finding in depth order and settles with a verdict.
  7. Confirm `#scan` is visibly disabled for the length of a run and live again the moment it
     settles or fails.
- **Done when**: step 4 holds for all three interruption points, step 6 is unchanged from before
  the edit, and the 46 website tests pass.
