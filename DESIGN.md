---
name: Tainted
description: A security scanner that proves holes by running the real exploit, and says plainly when it did not.
colors:
  abyss: "#02060D"
  ink: "#050A14"
  thermocline-cyan: "#23D6E6"
  lamp-red: "#FF5A46"
  lamp-tint: "#FFB3A6"
  half-light-amber: "#E8A33D"
  half-light-tint: "#F0C381"
  patch-add: "#7BE0A8"
  patch-del: "#FF9182"
  snow: "#F4F6FA"
  wash: "#A8BACB"
  wash-dim: "#8496AC"
  wash-faint: "#43576E"
  water-0: "#123C57"
  water-1: "#0C2C45"
  water-2: "#0B2036"
  water-3: "#071A2E"
  water-4: "#05101F"
  water-5: "#030A14"
  water-6: "#02060D"
  lift: "#081322"
  lift-deck: "#071120"
  scrim: "#02080F"
  brief-ground: "#040A13"
  rule-control: "#72849B"
  btn-ink: "#02141A"
  thermo-lift: "#4EE6F4"
  scroll-thumb: "#1D4054"
  scroll-thumb-hi: "#255273"
  rule: "rgb(120 160 195 / .16)"
  rule-soft: "rgb(120 160 195 / .09)"
  panel: "rgb(11 26 44 / .62)"
  field: "rgba(0,0,0,.24)"
  field-off: "rgba(0,0,0,.10)"
typography:
  verdict:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "clamp(2.5rem, 5.1vw, 4.375rem)"
    fontWeight: 700
    lineHeight: 0.94
    letterSpacing: "-0.022em"
  readout:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "clamp(2.375rem, 4.6vw, 3.75rem)"
    fontWeight: 700
    lineHeight: 0.9
    letterSpacing: "-0.05em"
  finding-proven:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "1.875rem"
    fontWeight: 600
    lineHeight: 1.08
    letterSpacing: "-0.018em"
  finding:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "1.3125rem"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "-0.008em"
  lead:
    fontFamily: "Saira, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 400
    lineHeight: 1.6
  body:
    fontFamily: "Saira, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.55
  verdict-compact:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "clamp(2.125rem, 3.4vw, 3rem)"
    fontWeight: 700
    lineHeight: 0.94
    letterSpacing: "-0.022em"
  verdict-tight:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "clamp(1.75rem, 2.7vw, 2.375rem)"
    fontWeight: 700
    lineHeight: 0.94
    letterSpacing: "-0.022em"
  readout-compact:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "clamp(1.875rem, 3.1vw, 2.625rem)"
    fontWeight: 700
    lineHeight: 0.9
    letterSpacing: "-0.05em"
  readout-tight:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "clamp(1.625rem, 2.5vw, 2.125rem)"
    fontWeight: 700
    lineHeight: 0.9
    letterSpacing: "-0.05em"
  verdict-phone:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "clamp(2.125rem, 11.5vw, 2.875rem)"
    fontWeight: 700
    lineHeight: 0.94
    letterSpacing: "-0.022em"
  wordmark:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "0.13em"
  finding-demonstrated:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "-0.012em"
  finding-compact:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    lineHeight: 1.15
  lead-compact:
    fontFamily: "Saira, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
  data:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "0.8125rem"
    fontWeight: 400
    letterSpacing: "-0.02em"
  label:
    fontFamily: "Saira Condensed, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    letterSpacing: "0.19em"
rounded:
  none: "0"
  focus: "2px"
  field: "3px"
  scrollbar: "7px"
spacing:
  hairline: "1px"
  xs: "4px"
  sm: "9px"
  md: "16px"
  lg: "26px"
  xl: "40px"
components:
  button-primary:
    backgroundColor: "{colors.thermocline-cyan}"
    textColor: "{colors.btn-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "13px 22px"
    height: "46px"
  button-primary-hover:
    backgroundColor: "{colors.thermo-lift}"
    textColor: "{colors.btn-ink}"
  button-primary-disabled:
    backgroundColor: "transparent"
    textColor: "{colors.wash-dim}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.wash}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "8px 16px"
    height: "44px"
  input:
    backgroundColor: "rgba(0,0,0,.24)"
    textColor: "{colors.snow}"
    typography: "{typography.data}"
    rounded: "{rounded.field}"
    padding: "9px 10px"
    height: "44px"
  panel:
    backgroundColor: "rgb(11 26 44 / .62)"
    textColor: "{colors.wash}"
    rounded: "{rounded.none}"
    padding: "15px 18px"
  proof-block:
    backgroundColor: "{colors.scrim}"
    textColor: "{colors.wash}"
    typography: "{typography.data}"
    rounded: "{rounded.none}"
    padding: "13px 15px"
---

# Design System: Tainted

## Overview

**Creative North Star: "The Mesophotic Dive"**

Tainted's run view is a logged dive. It has a descent, a thermocline you are not supposed to cross, a turnaround at the deepest point the run actually reached, and ascent stops on the way back up. The three engine operations map onto that journey without being renamed for it: `analyze` is the descent, `prove` is the turnaround, `fix` is the ascent. The reader is not looking at a dashboard of findings; they are reading a dive log, and the question it answers is how far a stranger's data got before it reached something dangerous.

The density is instrument density. Panels are hairline-ruled, lifted a single value off the ground, and packed with real readouts — this is an Operate surface for a developer who wants a verdict in seconds and evidence immediately after. Nothing is decorative. The one thing the page is allowed to spend space on is deep water: the column continues below the doorway back into the descent, and empty abyss is a legitimate state.

The system's whole credibility rests on one rule, and the palette exists to enforce it: **warm light is physically impossible at this depth without your own lamp**, so warm ink appears only where Tainted executed an exploit and watched it succeed. Everything the run did not touch stays cold. This is not a severity scale and must never be used as one — colour reports how far something was proven, and scale reports how much it matters.

The visual anti-reference is confirmed and specific: the oscilloscope "signal bench" world this replaced, whose instrument metaphor carried no true fact. A drawn sine wave is not proof. Any mark on this surface must correspond to something the engine actually measured or executed.

**Key Characteristics:**
- One continuous water column, read top to bottom; depth is position, not decoration
- **Each check axis is a stratum of that column**, with a ceiling of its own, and a run can
  only be in one of them at a time
- Cold by default; warm only where an exploit ran
- Hairline rules and lifted panels, never cards, never nested containers
- Condensed display, mono for every number, humanist sans for prose
- Dark-only by commitment, not by omission
- Every number counted from the engine's report, never authored

## Colors

A single deep-water ground darkening with depth, one instrument accent, and a two-step warm scale that the run has to earn.

### Primary
- **Thermocline Cyan** (`#23D6E6`): The instrument. The ownership boundary, the primary button, focus rings, the verified state, the caret, text selection, and a fix that was re-proved closed. It is the only colour the interface may use about itself; everything else reports a result.

### Secondary
- **Lamp Red** (`#FF5A46`): **PROVEN, and nothing else.** An exploit was executed and observed to succeed. Also the mark's core and the verdict when a run is open.
- **Lamp Tint** (`#FFB3A6`): Lamp-lit text on the near-black proof ground, where full Lamp Red would vibrate.
- **Half-Light Amber** (`#E8A33D`): **DEMONSTRATED** — an exploit built and deliberately not fired — and, separately, any run that contacts nothing (demonstration mode). Half light, never full.
- **Half-Light Tint** (`#F0C381`): Amber text on the ink ground.

### Tertiary
- **Patch Add** (`#7BE0A8`) / **Patch Del** (`#FF9182`): Added and removed lines inside a suggested patch. Confined to the patch block; a diff read as flat text is a diff you have to re-derive by eye.

### Neutral
- **The Depth Ramp** (`#123C57` → `#0C2C45` → `#0B2036` → `#071A2E` → `#05101F` → `#030A14` → `#02060D`): One ordered scale, named once. The water column is drawn from it and so is every ground that has to sit level with a given depth. Restating these as literals is how a ground and the water it is supposed to match drift apart.
- **Ink** (`#050A14`): The page ground behind everything that is not water.
- **Abyss** (`#02060D`): The footer and the scrollbar track; identical to the ramp's last stop, so the column ends without a seam.
- **Lift** (`#081322`) / **Lift Deck** (`#071120`): The rails and the header, each lifted one value off the ink.
- **Scrim** (`#02080F`): The ground a proof block is printed on — below the ink, so evidence reads as recessed into the page.
- **Snow** (`#F4F6FA`): Primary text and the marine-snow particulate.
- **Wash** (`#A8BACB`) / **Wash Dim** (`#8496AC`): Secondary and tertiary text. Both tinted from the water's own hue; neither is grey.
- **Wash Faint** (`#43576E`): Inactive fills only. At 2.67:1 it is never text and never a lone state mark.
- **Rule Control** (`#72849B`): The border of anything interactive. It exists because the decorative `--rule` measures under the 3:1 WCAG 1.4.11 asks of a control boundary.

### Named Rules

**The Lamp Rule.** Warm ink — Lamp Red or Half-Light Amber — may appear **only** where the engine did the corresponding thing. Red means an exploit executed and succeeded. Amber means built-but-not-fired, or a run that contacted nothing. A candidate nobody attempted is cold, whatever its severity. Colour is proof strength; it is never severity, and it is never emphasis.

**The One Instrument Rule.** Cyan is the only colour the interface is permitted to use about itself. If a mark is cyan, it is the product speaking; if it is warm, it is the run reporting. Never mix the registers on one element.

**The Stated-State Rule.** No state is carried by colour or shape alone. Every dashed node, dimmed dot and coloured bulb has the word beside it or a visually-hidden equivalent, because a shape difference is not available to a screen reader and a hue difference is not available under forced colours.

## Typography

**Display Font:** Saira Condensed (with `system-ui`, sans-serif) — weights 500/600/700, self-hosted as three static instances
**Body Font:** Saira (with `system-ui`, sans-serif) — variable, 100–900
**Data Font:** Martian Mono (with `ui-monospace`, monospace) — variable, 100–800

**Character:** Condensed grotesque for anything that ranks, a humanist sans for anything that explains, and a mono for every value the engine measured. The pairing is a dive slate: compressed capitals for the reading you take, a legible sans for the note you write beside it. All three are self-hosted so the voice survives an offline or network-restricted run, and the three faces the first viewport needs are preloaded.

### Hierarchy
- **Verdict** (Saira Condensed 700, `clamp(2.5rem, 5.1vw, 4.375rem)`, 0.94, `-0.022em`, uppercase): The `<h1>`. Two lines, always, set as separate spans so the accessible name keeps the break the eye gets.
- **Readout** (Martian Mono 700, `clamp(2.375rem, 4.6vw, 3.75rem)`, 0.9, `-0.05em`): The two dive-computer numbers, PROVEN and REPORTED. The denominator is 0.36em beside them.
- **Finding — proven** (Saira Condensed 600, 30px / 1.08): A finding the lamp lit.
- **Finding — demonstrated** (Saira Condensed 600, 24px): Half-lit.
- **Finding — cold** (Saira Condensed 600, 21px / 1.15): Everything else. **Scale is the ranking; no badge or chip does it.**
- **Lead** (Saira 400, 17px / 1.6, max 52ch): The sentence under the verdict.
- **Body** (Saira 400, 15px / 1.55, max 65–75ch): Descriptions and prose. `.desc` caps at 70ch.
- **Data** (Martian Mono 400, 13px, `-0.02em`): Proof blocks, field values, key–value readouts, the engine's coverage sentences.
- **Label** (Saira Condensed 600, 12px, `0.19em`, uppercase): Panel headings and micro-labels.

### Named Rules

**The Twelve-Pixel Floor.** No text below 12px anywhere. The ramp is 12 / 13 / 15 / 17 / 21 / 24 / 30 plus the two clamped display sizes; it deliberately has no steps between, because eight sizes inside 4.5px is a cloud, not a hierarchy.

**The Tabular Rule.** `font-variant-numeric: tabular-nums` is on `body`. Every number on this page sits in a column that has to line up, and a proportional numeral in a dive log is a misread value.

**The Counted-Words Rule.** Every quantity in prose is counted from the findings at render time and spelled out from a word table, never authored. A stale number in a sentence about proof undercuts the only thing the product sells.

## Layout

A three-column mission panel at ≥1181px: the descent rail (298px), the water column (fluid), and the instrument rail (336px). The water column is **first in the document** so the verdict is the first thing a screen reader reaches; CSS `order` puts the descent back on the left for the eye.

The descent rail is sticky (`top: 62px`) and travels with the reader, because the column is taller than the content it sits beside. Below the three-column rig sit the briefing band, the observations list, the optional full run log, and the four-up instrument band.

**Breakpoints.** 1240px (findings split into claim | evidence), 1180px (rail drops below and becomes a 2-up; descent narrows to 250px), 860px (single column, water first, header unpins, form fields go to 16px), 460px (tighter gutters, the flow chips rotate to vertical).

**Height breakpoints are first-class here and unusual enough to state:** at `max-height: 940px` and again at `max-height: 720px` the water body compresses rather than what follows it being pushed off the screen. The first viewport must hold the verdict, the two readouts and the way back into the descent together; that promise outranks filling the column.

**Density.** Panel padding is 15–18px; the findings list uses a 96px beam rail against fluid content. Spacing steps in use: 1px (rules), 4px, 9px, 16px, 26px, 40px. Grid gaps of exactly 1px against a `--rule-soft` background are how the band and the register 3-up draw their dividers — the gap *is* the rule.

**Every grid track carries `min-width: 0`.** A canvas holds an intrinsic pixel width, and without this the width Cytoscape measured at 336px becomes the track's automatic minimum the moment the window narrows.

## Elevation & Depth

This system is tonally layered, not shadowed. Depth comes from the seven-step water ramp and from surfaces lifted a single value off their ground — `--lift` for rails, `--panel` at 62% over it, `--scrim` *below* the ink for proof blocks. There is exactly one conventional shadow in the system, and it is ambient rather than structural.

The rest of the depth cue is **light**, which is the point of the world.

### Shadow Vocabulary
- **Panel ambient** (`box-shadow: 0 10px 26px -14px rgba(0,0,0,.85)`): The only neutral elevation shadow. Offset, soft, achromatic. Panels and only panels.
- **Active stage halo** (`0 0 0 4px rgb(35 214 230 / .18), 0 0 12px 2px rgb(35 214 230 / .5)`): The stage the run is currently at.
- **Thermocline bloom** (`0 0 22px 3px rgb(35 214 230 / .42)`): The ownership boundary, the one rule that crosses the whole column.
- **Proven bulb** (`0 0 0 4px rgb(255 90 70 / .14), 0 0 16px 3px rgb(255 90 70 / .38)`): A finding whose exploit executed.

### Named Rules

**The Lit-Object Rule.** Depth is carried by light, not by drop shadows. A zero-offset coloured halo is permitted **only** on an element that is emitting — the active stage node, the thermocline, a proven bulb, the lamp cone. Everything else takes the neutral panel ambient or nothing. This is a deliberate departure from the general "no coloured glows" guidance and it is the system's elevation model: a lit object in dark water throws a halo, and on this surface a halo therefore means something is lit. Audits will flag these; they are correct that the pattern exists and wrong that it is decoration.

## Shapes

Square by default. The primary button, ghost buttons, panels, proof blocks and the instrument band all have **zero radius** — an instrument reads a value, it does not round its corners. The only radius in the system is 3px, on form fields and the demonstration banner, where a sunk input needs to read as a well rather than a panel.

Borders are 1px hairlines throughout, at two weights: `--rule` (16% wash) for decorative separation and `--rule-control` (a solid `#72849B`) for anything interactive, which exists solely to clear the 3:1 that a control boundary requires.

Recurring silhouettes carry meaning and are not interchangeable:
- **Circle** — an untrusted entry point. A stranger can send this.
- **Diamond** — a sink. The dangerous place.
- **Dashed stroke** — attempted and refused, or not reached this run. Used identically in the sounding, the coverage bars, the proof-strength list and the taint profile.
- **Hairline horizontal rule in cyan** — the thermocline, and nothing else.
- **Hairline horizontal rule in wash** — a layer's ceiling. Deliberately neither cyan nor dashed, because both of those marks are already spoken for; a breached ceiling brightens rather than changing kind.

## Components

**Character: "Cold, exact, and lit only when earned."** Every control rests in instrument cyan or in nothing at all. Warm ink is never a style choice on a control — it is a result the run produced.

### Buttons
- **Shape:** Square (`0` radius), uppercase, Saira Condensed 700, `0.15em` tracking.
- **Primary:** Solid Thermocline Cyan on Button Ink (`#02141A`), 13px 22px, min-height 46px.
- **Hover:** Lifts to `#4EE6F4` with a cyan ambient shadow. **Active:** `translateY(1px)`.
- **Disabled:** Transparent with a `--rule` border and Wash Dim text — and every disabled state is paired with a sentence saying why, in the words of the thing the reader has to do next.
- **Running:** Not disabled. Transparent with a cyan border, `cursor: progress`, a pulsing icon, and `aria-busy="true"` — never `disabled`, because taking the focused control out of the tree mid-run drops a keyboard user to the top of the document.
- **Ghost / mini:** Transparent, `--rule-control` border, Wash text, min-height 44px, Saira Condensed 600 at 12px.

### Inputs / Fields
- **Style:** 3px radius, `rgba(0,0,0,.24)` sunk ground, `--rule-control` border, Martian Mono at 13px, min-height 44px, caret in Thermocline Cyan.
- **Focus:** The `:focus-visible` ring does the work (2px cyan, 3px offset). The border shift to cyan is reinforcement and never the indicator — on its own it is a 1px edge at 2.16:1, well under what WCAG 2.4.11 requires.
- **Disabled:** `--field-off` ground, Wash Faint text — genuinely `disabled`, never merely dimmed. The *label* stays readable, or the form cannot explain what it has stopped asking for.
- **Mobile:** 16px at ≤860px, exactly. Below 16px iOS Safari zooms the viewport on focus and does not come back.

### Panels / Containers
- **Corner style:** None. **Border:** 1px `--rule`. **Background:** `--panel` (62% panel ink) over the rail's lift gradient.
- **Shadow:** Panel ambient only (see Elevation).
- **Padding:** 15–18px. **Never a card, and never a nested container.**

### Navigation
There is none. This is a single surface with a sticky deck carrying the mark, the run label, the ownership chip and the share control. At ≤860px the deck unpins and the strap's second line is dropped — the verdict says it better two lines later.

### The Ownership Chip (signature)
The header chip answers exactly one question: *what happens if you press Arm right now.* It is derived from the form on every keystroke, never from the last report, and it carries its state in ink as well as in words:
- **Verified** — Thermocline Cyan, closed shield. Localhost, or a target the engine verified.
- **Demonstration** — Half-Light Amber, closed shield. A run that contacts nothing.
- **Open** — Wash Dim, open shield. Not established, required, or a token supplied but not yet checked.

A supplied token is *not* a verified one; it stays cold until the engine says otherwise.

### The Lamp (signature)
The lamp ignites each finding from cold to lamp-red as the real run's results are read out in depth order. It lives in the sounding, which is the one place on this surface where depth is drawn — and it is now **mounted on something**, which is the subject of the next section. The ink is unchanged and the law is unchanged: warm light exists only where the lamp was switched on.

### The Submersible (signature)
For a long time the lamp was a 14px dot and a cone, translated down a gradient with nothing holding either. A light with no body cannot **be** somewhere, and being somewhere is the entire claim this scene makes — so the light is carried by a crewed submersible: hull, acrylic dome, ducted thruster, a floodlight rig under the nose and a lamp-red strobe on the sail.

It is a submersible rather than a diver because of what the scene actually does. The dive is graded to sixty units and holds station for minutes at a time; nobody hovers at a trench mouth on a lungful of air, and the readouts down the left edge were always a submersible's console. It is a vehicle for the same reason the engine has a voice: this is an instrument that goes and looks.

- **It answers its own velocity.** One number, `--sub-run` (0 hovering, 1 at cruise), is written once per frame and drives everything: the hull pitches nose-down as it gathers way (to `--sub-pitch-max`) and levels into a hover, the thruster turns only while making way, the ballast bubbles quicken, and the two floodlights **splay when hovering and pull in straight when running**. A propeller spinning at a dead stop is the same lie as a bar filling against nothing.
- **Two cones, not one.** A vehicle has a light on each side of its nose, and the overlap between them is what makes a beam read as volume rather than as a wedge of paint. Each is 84° against the single cone's 120°, thrown from the rig and converging. The old sweep waved about because a diver holding a torch would; nothing was holding it, so it read as aimless.
- **It rides above the plane it lights.** A lamp is over the thing it illuminates. That is the truthful arrangement and it is also what keeps an opaque hull off the one line of text the reader is waiting for at the moment it lights.
- **The sea rocks nothing; the vehicle rocks.** The swell used to be applied to the whole water column, which was the right workaround when there was no body to move. A boat moves and a sea does not.

### The Sounding (signature)
**Arm & Prove hands the screen over.** For the length of the run the page is not scrollable and not reachable by keyboard (`inert`); the reader is in the water, and the descent *is* the progress indicator.

- **The strata.** One layer per check axis, ordered by depth, each with a ceiling of its own. Zone names are deliberately none of the five the descent rail uses for the engine's pipeline stages — a layer and a stage are different things and may not trade names.
- **A layer is taller than the screen it is drawn on, and that is the whole scene.** `--world-screens` (1.5) sets how much frame a world gets, and `ppm` — pixels per depth unit — is read off it. This is the number the first build of the sounding was wrong about and everything else was downstream of: twelve units of depth were worth about 205px, so three worlds were on screen at every moment, no world was ever the frame, and the only thing left that could say *you are somewhere else now* was a hairline and a caption pinned beside it. That is not a place with a boundary; it is a list with rules between the rows and a submarine drawn on top of it. How far apart two candidates can sit, how long the vehicle travels between crossings, and how much open water there is at a boundary all now fall out of that one token.
- **What it may claim: the frontier.** `/api/prove` now reports each candidate as the engine finishes attacking it, and the scene holds one number derived from that — the deepest point the run has **earned**. A layer with anything outstanding stops the vehicle at the deepest mark it has already read out; a layer with none blocks nothing. The submersible flies toward the frontier and never past it, and every honest property of the scene falls out of that one rule. **No percentage is printed anywhere.**
- **Out-of-order arrival is the normal case, and it is not hidden.** `orchestrator.prove` iterates `analysis.ranked()` — structural holes first, then model rank, then severity — and the check axis is **not in that sort key at all**. Results genuinely arrive out of depth order. So the vehicle hovers at a blocked ceiling while deeper results bank up silently behind it, and when the blocker lands the frontier jumps and it makes one long unbroken run. The status line says which layer and how many of its candidates are in. Hovering is not a stall: it is the instrument refusing to claim depth the run has not paid for. The engine is **not** reordered to suit the picture.
- **A deployment that cannot watch its own run says so.** The sandboxed executor runs the whole engine behind one request and hands back a finished report, so there is nothing honest to emit before it lands. The stream's first event carries `streams: false` and the scene says in words that this run reports only when it ends. Silence from a slow run and silence from an unobservable one look identical, and a progress indicator that cannot tell them apart will invent motion to cover the difference. This case needs no special handling — the frontier returns the first ceiling on its own.
- **Breaching is earned.** A layer opens only once every candidate inside it has been attempted. A layer with no candidates is crossed without a stop and says so.
- **One world on the screen, and no other.** A world's water panel, its three planes' worth of sea and its contacts are one object, moved together by `veil()`: full strength through the whole of the world, dissolved over `--world-fade` at each boundary, and `visibility: hidden` outside that — not dimmed, not behind something, not a hairline away at the top of the frame. There is no value of `depth` at which two worlds are both legible. The dissolve lands in open water because each world holds its own content clear of its ends by `--world-lead`, so nothing recognisable is ever half-transparent: by the time the reef is fading, the reef is a screen above. The water panels are stacked deepest-first and only the world being *left* fades, over one that is already there at full strength — which is what keeps the middle of a crossing from going grey.
- **A boundary is a thing that happens, not a line that is drawn.** There is no ceiling rule and no permanent zone caption anywhere in the water. Crossing into a world plays one wipe, once, argued from the two places it is between — the surface breaking, silt off a floor that has just arrived, a roof closing over, a floor falling away, a bioluminescent bloom answering something arriving in the dark — and the world's name arrives on a title card with it and then leaves. The written account nothing may lose (which layer, its check, its count, how many are in) is in the status line and the ladder, both live text.
- **A candidate is a contact, met in the water.** It used to be a full-width row — a dot at the left margin, a title, the strength word flushed right, four of them stacked. That is a table with a submarine over it, and it was the loudest reason the scene read as a document. A contact is now a mark out in the water at its own depth with its caption hung off it on a leader: faint until the vehicle is near, lit when the lamp reaches it, gone once it has risen past the console. Its caption's width is a length and never a percentage — the mark is a zero-width anchor, so a percentage resolves against nothing and an `auto` width shrink-to-fits to zero.
- **It writes nothing.** `ignite()` still puts every strength word on the page and `settle()` still writes the verdict; the turnaround reads those back out of the DOM they were written into, so the two accounts cannot disagree.
- **Leaving.** One control and one key (<kbd>Esc</kbd>), and their meaning depends on where the run has got to: **before** the report there is a live request to cancel (the fetch is aborted and the page returns to its pre-run state, with no error banner — a cancellation is not a failure); **after** it there is only an animation to skip. At the turnaround the reader surfaces themselves; nothing moves under them unasked.
- **The descent is continuous, and that is structural.** There is no timeline and no queue of steps: the vehicle has a position and a velocity, the run has a frontier, and **one** `requestAnimationFrame` loop reconciles them. It accelerates toward cruise under its own inertia (`--sub-tau`) and brakes into the frontier on an exponential approach (`--sub-brake`), so it never overshoots and never snaps — it arrives by running out of gap. Marks light **positionally**, when the vehicle draws level with them, not because a queue reached them.

  This replaced an `await` chain — travel, stop, flash, hold, travel, stop, hold — and every one of those holds was a join the eye read as a slideshow. `--vel-descent` survives as the **cruise ceiling** in px/s, so a dive to 60 still takes longer than a dive to 12; what is gone is any per-step duration. **Nothing inside the scene may await anything.**
- **The water is not equally thick everywhere.** The cruise ceiling is a *field over depth*, not a constant: each world carries a `pace` array in the `LAYERS` table — its ceiling as a fraction of `--vel-descent`, sampled across its own band and interpolated — and `cruiseAt(depth)` reads it. This is the fix for the complaint that only the opening layers felt like places. At one flat 340px/s, a twelve-unit band was **3.9s** on a laptop while the crossing wipe ran for 1.5s and the title card for 2.6s: for four worlds out of five *the arrival animation was longer than the world*, so everything under the shelf read as a wipe rather than as somewhere you had been. The field gives the dive a shape instead — roughly 13.4s / 6.2s / 10.4s / 4.9s / 4.6s, about forty seconds of travel — and each number is an argument about its own place: you slip under the surface, you cruise the reef and slow at the failed coupling, you **duck** under the overhang and stay slowed, the floor leaves and you **fall** (the one world that goes above 1.0, arrested before the boundary), and then everything thickens into the trench.

  The field is authored in seconds and it has to mean them, so `--vel-descent` is referred to a 900px viewport before it is divided by `ppm`. `ppm` is proportional to the viewport, so a raw `V / ppm` made the whole dive longer on a bigger window — the same five worlds and the same five encounters taking 39s on a laptop and 53s on a tall monitor. Referring V cancels `ppm` exactly: the dive is the same length of **time** everywhere and the same number of **screens** everywhere, and what changes with the window is only how much of a world is visible at once, which is what a window is.

  It is emphatically **not** a hold. A hold is a duration, and every duration this scene ever had was a join the eye read as a slideshow; this is a rate, the vehicle still accelerates toward it under `--sub-tau`, and it still brakes into the frontier on the same exponential approach, taking whichever of the two is asking it to go slower. Two corollaries fell out of building it and are load-bearing: `cruiseAt`'s anti-stall floor must be an epsilon (0.05) and **not** the 2 that `cruise()` carries — two depth units per second is 226px/s, which silently overrode every slow world in the dive and left the field correct in the table and doing nothing — and `--sub-run` must still be normalised against the **base** ceiling, or the hull draws itself at full cruise while creeping through the trench at a tenth.
- **A run does not pause because nobody is watching it.** A backgrounded tab gets no frame callbacks, and the descent *is* the loop — so while the tab is hidden the vehicle is placed at the frontier directly, on a timer, and the marks it passed are lit. Travel is what is skipped; the result never is. Reduced motion takes the same path for the same reason, including when it is switched on **mid-descent**.

### The Five Worlds (signature)
Each check axis has a sea of its own — a sunlit shelf, a fore-reef, a coral overhang, the drop-off, a trench mouth. Five bands of the same empty water do not become five places because they are captioned differently, and "one layer per check axis" is the claim the whole scene rests on: the layers have to be distinguishable by looking, not only by reading. Everything is flat SVG and CSS gradients — no raster asset and no library, because this surface is one self-contained file that has to survive an offline run.

A world is three things and not one. It has its **own water** — a gradient panel in its own colours, keyed off the check in a `[data-world]` block, not one step of a shared ramp, because five brightnesses of the same blue is a picture of one place at five depths and the claim is five places. It has its **own light**: `--w-beam` says how much of the vehicle's own lamp survives in it, and a torch that is nearly invisible on the shelf and the only light there is at the trench does more to say *you have gone somewhere* than any amount of scenery. And it has **something in it to meet**, argued from the check the world stands for rather than chosen for looking good in water:

- **Sunlit shelf** (`test_integrity`) — a survey transect strung with station markers, and one station with its tether and nothing on the end of it. That is what "watched" looks like on a seabed, and the gap is what this check is about. The only place on this surface where an absence is drawn as the subject rather than as a state.
- **Fore-reef** (`classic_injection`) — an intake run along the reef with a coupling that has failed. Something built to carry one thing, carrying whatever is put into it, with the break at the joint.
- **Coral overhang** (`agent_injection`) — the world the vehicle passes *under*, and filter feeders hanging off it: an inlet and an outlet in one body, which is the shape of the hole. Whatever arrives is taken in and whatever is taken in is passed on, by the same animal, through the same opening.
- **The drop-off** (`bola`) — another submersible's lights, a long way off across the void, working. The only object in five worlds doing what the vehicle is doing: you are not the only one down here with a light, and nothing about the water is checking whose it is. The near plane is deliberately bare; the emptiness is the design.
- **Trench mouth** (`rls`) — tube worms standing where the ground lets them and nowhere else, in a band you can see the edge of. A policy, drawn. The mat is an ellipse and never a strip: a 400px band 13px tall is a hairline ruled across the frame, which is the one thing this scene exists to stop drawing.

And it has **something in it that is alive**, which is the fourth thing and was the one missing. Sway and drift between them say *anchored* and *adrift*; nothing said *alive*, so three worlds out of five had nothing in them doing anything but rocking, and the deeper the dive went the more static it got. Five verbs now — **swim** (a crossing, with a line that rises or falls), **beat** (the body flexing about its own caudal peduncle, on the `<use>` inside the wrapper because the crossing owns the wrapper's transform), **hover**, **rise** and **crawl** — and one signature animal per world, argued the same way its encounter is:

- The shelf's **turtle** is the calibration for the whole dive: the last animal the reader meets that is doing something ordinary, at a size they can judge, in light they can see it by. Everything after it is doing something the dark requires.
- The fore-reef's **shark** crosses the far plane once and never approaches — a shark that swims up to the reader is a theme park — and a **moray** sits in the break in the pipe, because what lives in a hole in something built is the entire point of the hole.
- The overhang's **siphonophore** is the argument rather than an inhabitant: not one animal but a colony that has stopped being able to tell where one body ends and the next begins — a swimming half that cannot feed, a feeding half that cannot swim, one shared gut, no boundary anywhere on it. That *is* `agent_injection`. Its **moon jellies** are on the near plane going **up**, the one thing in five worlds that passes the vehicle the other way.
- The drop-off's other submersible now resolves, for about one second of its forty-six, into a **hull** — the same class of vehicle the reader is in. Before that second it is two lights that could be anything; after it, it is somebody with the same equipment and the same authority.
- The trench's **anglerfish** is the last thing in the dive and the only animal the lamp does not find: it arrives carrying its own light. It is also the single exception to *nearness is silhouette* — at #000406 water a #000305 silhouette is a shape nobody can see, and this one is not backlit, it is lit by the only lamp there is and by the thing over its own head. Its lure is a DOM element, not a fill, because it has to glow.

**A silhouette is identified by its profile, so profile is the whole budget.** A lozenge with a triangle on the back is not a fish; nine of them on a fixed grid inside one sprite is a dingbat repeated, and it could not vary size, phase or heading because it was one element. Every animal is now drawn from the two or three features its outline is actually known by — a forked caudal and an eye that is a *hole* (`fill-rule:evenodd`, because at these tones an eye drawn in ink is invisible and an eye drawn as an absence is what makes a shape read as an animal), a heterocercal tail and a swept first dorsal, cephalic lobes and a concave trailing edge, a gape that cannot close. A branching coral is **stroked** at three widths, not outlined, because a branch that tapers over three orders is three stroke widths and not forty path nodes — and it is a *clump* of stout stems, not one trunk thinning to a twig, which is a drawing of a winter tree. A sea fan gets a faint membrane behind its mesh because a gorgonian is a **plane** held against a current, and the anastomoses — branches fusing back into each other — are the structural difference between a fan and a shrub. How much detail a shape gets is decided by how long the vehicle is beside it: a shoal crossing the far plane needs a profile; the thing that comes into the lamp at the bottom needs teeth.

**A world holds more than one animal, and no two share a body plan.** One signature encounter per layer told five worlds apart and did not make any of them feel inhabited: a place with exactly one creature in it is a diorama. Each layer now carries two or three, and the rule for picking them is that a silhouette earns its place by being unmistakable for something — a shelf with a turtle, a spotted eagle ray and a cuttlefish on it is three different answers to the same water, where a shelf with three fish on it is one answer printed three times. The shelf gets the ray (a duck-bill rostrum and swept wings, deliberately *not* the manta) and cuttlefish; the fore-reef a lionfish and parrotfish beside its shark and moray; the overhang a nautilus and a squid under its siphonophore; the drop-off an oarfish and two hammerheads (a cephalofoil is a shape nothing else in the sea has, so the reader reads a different animal rather than the reef's shark moved); the trench a gulper eel and a vampire squid beside its angler.

**Movement has to leave the horizontal, and it has to leave the plane.** Every crossing was one straight line across the frame at constant speed, and after the first pass that is the whole problem — five worlds of animals all making the same journey on the same axis. Four more paths now: **dive** (steeply diagonal, growing the whole way — a ray comes off the top of a shelf, it does not cross it), **sound** (purely vertical), **helix** (a crossing that will not hold its depth), and **jet** (the same line, but the speed along it is not constant — a cephalopod fires and coasts, and per-keyframe `animation-timing-function` is what says so). Plus **graze**, **undulate** and **flutter** for animals whose verb is not travel at all.

The larger half of the fix is a scale change on the crossing itself: `--sw-s0`/`--sw-s1` grow an animal toward the middle of its pass and shrink it again at both ends. In a scene with no perspective projection that is the *only* way to say something came nearer, and without it every crossing is a decal on a rail however interesting its line is. They default to 1, so a shoal is unchanged by their existence.

Two mechanical traps, both load-bearing: a travelling verb writes the element's **whole transform**, so anything with one on it must be placed by geometry and never seated with an inline `translateY(-100%)` — the transform is discarded the instant the animation starts. And `Object.assign(el.style, {'--x': …})` **silently does nothing**: a CSSStyleDeclaration has no such property, custom properties are reachable only through `setProperty`, and the assignment fails without throwing, so every per-instance distance in the sea goes through one `style()` helper instead.

**A shoal is N elements, not one sprite.** Same heading, same speed, individual phase: one crossing animation played by every member with staggered negative delays, its own body size, its own beat. That is also what a shoal *is*. The count is a **budget** and not a composition — every member is separately composited, and a world that is `content-visibility:hidden` for four fifths of the dive still has to composite all of it during the fifth — so no world exceeds ~95 animated elements.

- **Three planes, three transform writes.** Far (`--par-far`), mid (`--par-mid`) and near (`--par-near`, deliberately **greater than 1** — it is in front of the vehicle) move at fractions of the world's travel. Parallax is the difference between travelling through a place and scrolling a gradient past a window; the near plane overtaking the sub is the depth cue. Every object on a plane moves with it, so a frame writes three transforms and never one per object.
- **A band is anchored at its middle.** A plane travelling at `k` times the world's rate *cannot* stay aligned with the world — that inequality is what parallax is — so the only question is where the one moment of agreement is placed. At the middle, the sea sits exactly on its stratum while the vehicle is passing through it and drifts only on the way in and out, which is when drifting is the effect rather than the error.
- **Distance is haze; nearness is silhouette.** Underwater a far object tends *toward* the colour of the water between you and it, so the far plane is painted in wash and barely there. Anything close is between you and what light there is, so it is darker than the water. Getting this backwards makes a coral head look like a cloud.
- **Ink reaches a sea object by inheritance, never by a class.** A `<use>` instances its symbol into a shadow tree that document selectors cannot reach into, so `.sea .ink{fill:…}` matches nothing and every shape falls back to the SVG default — solid black. `color` and `fill` are inherited, so they cross that boundary; shapes take `currentColor` and vary their own `fill-opacity`.
- **The instrument paints above the sea.** A silhouette may sweep over the submarine — that overtaking is what the near plane is for. It may never sweep over a contact's title; that reads as a rendering fault. Back to front: water, far sea, mid sea, marine snow, the lamp's plane, the vehicle, near sea, the closing vignette, the strata and their contacts, the crossing, the depth scale, the readouts. The water ground therefore cannot share an element with the strata, even though both travel at the world's rate.
- **No edge in the water is an accident of a box.** A landscape mass is a stretched path, so its fill stops dead at the bottom of its own box, and a canopy is solid along the top of its box — invisible when a band was 200px tall, a hairline ruled across the whole frame once one is 1500px. Both are feathered (`.ground`, `.canopy`), and so are the water panels, whose joins would otherwise be one colour's rectangle over another's. The lamp's own plane is no longer painted either: it was the last horizontal rule left in the water after the ceilings went, which made it the most conspicuous one.
- **Colour dies with depth.** `filter: saturate(calc(1 - var(--dsat)))` on the planes, driven from depth to `--dsat-max`. The floodlights are *outside* that filter, so by the trench the only warm thing left in frame is the light the vehicle is carrying. The page already stated "warm light does not survive at depth" as a law; this renders it as physics. The value is quantised to forty steps across the dive, because `saturate()` re-rasterises the plane it is on and nobody can see a thousandth.

### Motion
Two authored moments: the lamp's descent (`transform .62s cubic-bezier(.22,.61,.36,1)`) and the sounding's travel — which is no longer an eased transition at all but a velocity integrated per frame, so what is named is a rate (`--vel-descent`), an inertia (`--sub-tau`) and a braking constant (`--sub-brake`), never a duration. State changes are carried by 0.45–0.6s ease-out colour transitions. Reduced motion is read **live** through a `matchMedia` change listener so a mid-session change stops the ambient canvases immediately, and it caps `animation-iteration-count` at 1 rather than giving an infinite animation a near-zero duration, which would flicker. The sea's animations are **enumerated** in that block rather than swept with a universal selector — the list is the contract, so adding a sea object cannot quietly add a loop the block does not know about — and it covers `.sea use`, because a beat or a bell lives on the `<use>` inside a wrapper and would otherwise survive its own animal being stopped. Stopping a crossing is not enough on its own either: eleven objects sharing one keyframe all rest at its first frame, which is eleven animals in a heap against the left edge, so each crossing verb is given a **resting position** instead. A reader who asked for less movement is owed the same place held still, not the place with its animals deleted.

**Two rules the sounding adds.** The descent loop **writes and never reads** — no `getComputedStyle`, no `getBoundingClientRect`, nothing that forces a style or layout flush over a document ten thousand pixels tall, because that read wedged the renderer outright. And no state the scene's visibility depends on may be deferred to `requestAnimationFrame`: frame callbacks do not arrive in a backgrounded tab, so the hand-over uses one forced reflow instead — and the descent itself has a timer-driven fallback for exactly the same reason.

**Reduced motion and the sounding.** The crossing wipes, the title card's travel and a contact's ping are one-shots rather than loops, and under this setting they do not play at all: the vehicle is *placed* at the frontier rather than flown to it, so a 1.5s wipe would be answering a moment that has already passed. The card holds its text without travelling. A layer lands by colour, by water and by the words in the status line, which is what the rest of the page does.

The scene still takes the screen — a modal account of a wait is not motion, and the reader is owed one either way — but nothing travels: the vehicle is placed at the frontier rather than flown to it, and the layers land by colour and text. The sea itself **stays**: it is picture, not motion, and a reader who asked for less movement did not ask to be shown an empty rectangle instead of a place. What stops is everything that loops — swaying, drifting, spinning, pulsing — enumerated rather than swept with a universal selector, so that adding a sea object cannot quietly add an animation the reducer has never heard of. This is a deliberate departure from "the sequence resolves instantly, it does not become a fast animation", and it follows the same principle: reduced motion removes travel, not feedback.

## Do's and Don'ts

### Do:
- **Do** place a mark by what the engine measured. Depth is a scale position (0–70) derived from the check's distance past the ownership boundary, and it is labelled as a scale, not a measurement. The stops are evenly spaced (12/24/36/48/60) so every stratum can hold its own candidates without them printing into the layer below — the **order** is the meaning, and re-spacing the scale costs nothing.
- **Do** group a picture's marks by the layer they belong to. Spread evenly across a frame, nine taint lanes are a picket fence whose ends happen to differ by a few pixels.
- **Do** let scale do the ranking. A proven finding is 30px, demonstrated 24px, cold 21px — all at full ink, because an unproven finding still has to be readable to be acted on.
- **Do** state a remainder. If two numbers do not partition a run, write the rest down rather than leaving the reader to subtract.
- **Do** give every state a word as well as a mark, and keep `forced-color-adjust: none` on the proof-strength marks so the law survives forced colours.
- **Do** keep `--wash-dim` as the floor for real text, and treat anything dimmer as a stroke.
- **Do** self-host every face and preload the three the first viewport sets.
- **Do** theme the browser surfaces — selection, caret, scrollbar, focus ring, underline offset. They belong to the design too.
- **Do** let the water take colour with depth, and keep the lamp outside that filter. Red is the first wavelength the sea absorbs, so the surface's own law — warm light only where the lamp was switched on — is also what actually happens to a light going down. When a rule can be rendered as physics rather than asserted as a convention, render it.
- **Do** move the light's body and leave the light's ink alone. Giving the lamp a vehicle changed nothing about `--lamp`, which is proof strength in forty-odd rules; a submersible's lamp is still a lamp.

### Don't:
- **Don't** print a percentage, a fraction or a filling bar for the progress of a run. The engine sends one report at the end; a bar filled against a total nobody measured is the same overclaim as a proof without evidence. Segment by real layers and fill by real attempts, or say plainly that nothing is known yet.
- **Don't** use warm ink for anything but proof strength. Not for severity, not for emphasis, not for a destructive action.
- **Don't** print a strength word before the evidence exists. `ignite()` is the only thing permitted to write one; a claim of proof with the evidence withheld is the one unforgivable move.
- **Don't** express two different outcomes as two lengths of one gauge. Proved and reported differ in kind, so their marks differ in kind — a solid cyan rule against a broken amber one. Drawing 100% against 40% states a fraction the engine never measured.
- **Don't** put text on `--w0`, the lit water in the top tenth, unless it is display type. `--wash-dim` measures 3.83:1 there.
- **Don't** add a radius to a control, a card to a panel, or a badge to a finding.
- **Don't** let `--wash-faint` carry text or be the only mark for a state.
- **Don't** drop below 12px anywhere.
- **Don't** introduce a light theme. `color-scheme: dark` is a commitment to the use scene — a developer reading a security result — not an omission.
- **Don't** build travel out of per-step durations. A descent assembled from "go here, hold, go there, hold" is a slideshow with the joins showing, however well each step is eased. Give the thing a velocity and a destination it has earned, and let it fly.
- **Don't** let decoration cross a result. A foreground silhouette passing in front of the vehicle is depth; the same silhouette passing in front of a candidate's title is a rendering fault. The instrument paints above the sea, always.
- **Don't** reorder the engine to make a picture easier to draw. `prove` attacks structural holes first and interleaves the check axes; the scene absorbs that with a frontier rather than asking the engine to run in the order the water is drawn in.
