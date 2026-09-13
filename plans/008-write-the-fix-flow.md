# 008 — Give the "Write the fix" flow a busy state and the patch an entrance

- **Status**: DONE (applied and verified 2026-09-05)
- **Stamp**: 2026-09-05 · `surfaces/website/frontend/index.html` sha256 `1d67baaf858962`
  (not a git repository; verify with `shasum -a 256 surfaces/website/frontend/index.html`)
- **Severity**: MEDIUM (part A) / LOW (part B)
- **Category**: 8 — Missed opportunities
- **Estimated scope**: 1 file, one event handler + ~8 CSS lines
- **Depends on**: plan **006** for `--dur-enter`. If 006 has not run, add `--dur-enter:.26s` to
  the `:root` motion block yourself.
- **Merged from two findings** because both live in the same event handler (lines 3004–3035) and
  are the same interaction: asking the engine for a patch, and getting one.

## Problem — Part A: a focused control is disabled for the length of a network round-trip

```js
/* surfaces/website/frontend/index.html:3004–3011 — current */
  findingsEl.addEventListener('click', async ev => {
    const btn = ev.target.closest('[data-fix]');
    if(!btn) return;
    const article = btn.closest('.find');
    const index = finds.indexOf(article);
    btn.disabled = true;
    try {
      const fix = await call('/api/fix', Object.assign(repoSelection(), {index}));
```

Two problems in one line.

**No feedback.** `/api/fix` asks the engine to write a patch. That is real work — static analysis
plus, for the ranked candidates, a model call. The button greys out and nothing else happens for
however long that takes. Nothing on the page says the request is in flight.

**It does exactly what this codebase forbids.** The rule is stated in the file, about the primary
control, two hundred lines earlier:

```js
/* surfaces/website/frontend/index.html:2891–2893 — the rule */
    /* aria-busy rather than disabled: taking the focused control out of the tree mid-run
       drops a keyboard user back to the top of the document. */
    armBtn.setAttribute('aria-busy', 'true');
    armBtn.classList.add('running');
```

And again in the design document, `DESIGN.md:330`: *"**Running:** Not disabled. Transparent with
a cyan border, `cursor: progress`, a pulsing icon, and `aria-busy="true"` — never `disabled`,
because taking the focused control out of the tree mid-run drops a keyboard user to the top of
the document."*

A keyboard user who tabs to **Write the fix** and presses Enter is dropped to the top of the
document, and the page never told them anything was happening. The vocabulary to fix it already
exists — `.btn.running` (lines 411–415) and `@keyframes pulse` (line 416) — and the button
already carries an icon to pulse (`#i-wrench`, line 2080).

## Problem — Part B: the patch appears with no bridge

```js
/* surfaces/website/frontend/index.html:3031–3035 — current */
      const acts = article.querySelector('.acts');
      acts.parentNode.insertBefore(box, acts);
      btn.textContent = hasEdits ? 'Patch written below' : 'Needs your answer';
      box.setAttribute('tabindex', '-1');
      box.focus({preventScroll: true});
```

A dashed frame containing a multi-line coloured diff is inserted into the finding, pushing the
action row down, with nothing bridging the change. Unlike everything else in `#findings`, this one
**is** on screen when it happens: the reader has scrolled to this finding and pressed its button,
so they are looking directly at the place the block appears.

**Purpose:** preventing a jarring change. **Frequency:** rare — once per finding, per fix asked
for. Comfortably inside the tier AUDIT.md allows animation.

## Target — Part A

```css
/* target — appended after surfaces/website/frontend/index.html:738 */
/* A mini control that is working says so the same way the primary one does — and for the same
   reason it is not `disabled` while it works: taking the focused control out of the tree drops
   a keyboard user to the top of the document. See DESIGN.md, "Buttons / Running". */
.mini.running{border-color:var(--thermo);color:var(--thermo);cursor:progress}
.mini.running .icon{animation:pulse var(--dur-pulse) ease-in-out infinite}
```

```js
/* target — surfaces/website/frontend/index.html:3004–3011 */
  findingsEl.addEventListener('click', async ev => {
    const btn = ev.target.closest('[data-fix]');
    if(!btn) return;
    /* Re-entry is guarded on the button, not by disabling it: this control must stay in the
       focus order while the engine writes the patch (DESIGN.md, "Buttons / Running"). */
    if(btn.dataset.busy === '1') return;
    const article = btn.closest('.find');
    const index = finds.indexOf(article);
    btn.dataset.busy = '1';
    btn.classList.add('running');
    btn.setAttribute('aria-busy', 'true');
    try {
      const fix = await call('/api/fix', Object.assign(repoSelection(), {index}));
```

On success, the button is retired **after** focus has moved to the patch, so nothing is taken out
from under the keyboard:

```js
/* target — surfaces/website/frontend/index.html:3031–3035 */
      const acts = article.querySelector('.acts');
      acts.parentNode.insertBefore(box, acts);
      btn.classList.remove('running');
      btn.removeAttribute('aria-busy');
      btn.textContent = hasEdits ? 'Patch written below' : 'Needs your answer';
      box.setAttribute('tabindex', '-1');
      box.focus({preventScroll: true});
      /* Focus has already moved to the patch, so retiring the button now takes nothing out
         from under the keyboard — and one finding cannot collect two patch blocks. */
      btn.disabled = true;
```

On failure, the button goes back to being pressable:

```js
/* target — surfaces/website/frontend/index.html:3036–3039 (the catch block) */
    } catch(e){
      btn.dataset.busy = '';
      btn.classList.remove('running');
      btn.removeAttribute('aria-busy');
      btn.disabled = false;
      showError('Could not write that fix.', ' ' + e.message);
    }
```

## Target — Part B

```css
/* target — appended after surfaces/website/frontend/index.html:881 */
/* The patch is inserted into a finding the reader is looking at, so it arrives rather than
   appearing. 6px only: it is a diff about to be read, so it settles, it does not travel. */
.patch{
  opacity:1;transform:none;
  transition:opacity var(--dur-enter) ease-out,transform var(--dur-enter) ease-out;
}
@starting-style{
  .patch{opacity:0;transform:translateY(6px)}
}
```

No first-paint hazard here: `.patch` elements are created only by this handler (line 3016,
`box.className = 'proof patch'`), never served in the markup. No gate class is needed.

## Repo conventions to follow

- The running-control exemplar, which Part A copies deliberately rather than inventing:
  ```css
  /* surfaces/website/frontend/index.html:411–415 */
  .btn.running,.btn.running:disabled{
    background:transparent;color:var(--thermo);border-color:var(--thermo);
    cursor:progress;
  }
  .btn.running .icon{animation:pulse 1.15s ease-in-out infinite}
  ```
  `.mini` is transparent at rest, so it needs only the border, ink and cursor — not the
  `background:transparent` reset.
- `aria-busy` is set and removed with `setAttribute`/`removeAttribute`, never with a property.
  Exemplar: lines 2893 and 2670.
- Comments name the decision and cite the rule. Both targets do; keep them.

## Steps

1. Add the `.mini.running` rules from **Target — Part A** immediately after line 738
   (`.mini:hover{…}`). If plan 004 has run, line 738 is inside an
   `@media (hover:hover) and (pointer:fine)` block — add the new rules **after** that block's
   closing brace, not inside it. A running state is not a hover state.

2. Add the `.patch` rules from **Target — Part B** immediately after line 881
   (`.patch pre .file{color:var(--wash-dim)}`).

3. Replace the handler's opening (lines 3004–3011) with **Target — Part A**'s JS block. The
   single line being removed is `btn.disabled = true;` at line 3009.

4. Replace lines 3031–3035 with **Target — Part A**'s success block. Note the order carefully:
   insert → clear running → set label → set tabindex → **focus** → **then** disable. Reversing
   the last two reintroduces exactly the bug this plan fixes.

5. Add the three cleanup lines to the `catch` block, keeping the existing `btn.disabled = false;`
   and `showError(...)` calls.

6. If `--dur-enter` is not in `:root`, add `--dur-enter:.26s;` to the motion token block.

## Boundaries

- Do NOT change what `/api/fix` is called with, how the diff is built, how `ESC` is applied, or
  the `.add`/`.del`/`.file` colouring (lines 3016–3029). The escaping there is security-relevant
  — a patch is derived from a scanned repository, which this product treats as definitionally
  untrusted. Leave it exactly as it is.
- Do NOT remove `box.focus({preventScroll: true})` or change `preventScroll`.
- Do NOT make the button re-pressable after a successful patch. One finding, one patch block.
- Do NOT animate `height` or `max-height` on `.patch` to smooth the layout push. `opacity` and
  `transform` only.
- Do NOT add a spinner element, a skeleton, or a progress bar. The pulse is this file's answer to
  "working", and a second answer is a cohesion regression.
- Do NOT touch `.btn.running` or `@keyframes pulse`.
- Do NOT add new dependencies.
- If any "current" excerpt does not match the file, STOP and report.

## Verification

- **Mechanical**:
  - `cd /Users/sapnagoel/Documents/coding/Tainted && PYTHONPATH=.:surfaces/website pytest surfaces/website/tests` — 46 tests, all pass.
  - `grep -n 'btn.disabled = true' surfaces/website/frontend/index.html` must show exactly one
    hit, and it must be **after** the `box.focus` line.
  - `grep -c 'mini.running' surfaces/website/frontend/index.html` returns `2`.
- **Feel check**:
  1. Run a demo analysis, press **Arm & prove**, scroll to a proven finding and press
     **Write the fix**.
  2. The button must go transparent-with-cyan-border and its wrench must pulse for the length of
     the request — the same treatment **Arm & prove** wears while descending. Compare the two
     side by side; they should look like one idea.
  3. The patch block must rise ~6px into place as it fades in, not appear.
  4. **The keyboard check, which is the point of Part A**: reload, run a demo, then use **Tab
     only** to reach a finding's **Write the fix** button and press Enter. While the request is
     in flight, press Tab once. Focus must move to the *next control on the page* — not to the
     top of the document. Before this change it jumps to the top. When the patch arrives, focus
     must land on the patch block itself.
  5. With a screen reader on (VoiceOver: Cmd+F5), repeat step 4 and confirm the button is
     announced as busy while the request is in flight.
  6. Force the failure path: in DevTools → Network, set throttling to **Offline**, then press
     **Write the fix** on another finding. The pulse must stop, the button must return to its
     resting appearance and stay pressable, and the error must appear in the form's error slot.
     Then press it again and confirm it retries (this is what `btn.dataset.busy = ''` is for —
     if it does nothing on the second press, that line was missed).
  7. In DevTools → Animations at **10% playback**, confirm the patch's fade and translate end
     together with no residual offset.
  8. DevTools → Rendering → **Emulate CSS `prefers-reduced-motion: reduce`**: the patch must fade
     without moving, and the wrench must not pulse — line 1001 already handles `.btn.running .icon`
     but **not** `.mini.running .icon`. Check this specifically; if the wrench still pulses under
     reduced motion, add `.mini.running .icon{animation:none;opacity:.75}` alongside the existing
     `.btn.running .icon` rule inside the reduced-motion block, matching it exactly.
- **Done when**: the busy state matches the primary control, Tab does not jump to the top of the
  document mid-request, the failure path retries, reduced motion stops the pulse, and the 23
  website tests pass.
