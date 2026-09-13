"""The sounding: a submersible on a continuous descent through five distinct seas.

These guard the three things the rewrite was for, and each of them is a rule that a later change
could quietly undo:

  * the descent is continuous — one frame loop, no awaited hold per candidate;
  * it is never deeper than the run has earned — `frontier()` is the only authority;
  * the instrument is legible over the sea, and the sea is drawn per check axis.

They read the source rather than a rendered page, which is the same bargain the rest of
`test_sandbox_and_frontend.py` makes: this surface is one file with no build step, so its source
IS its behaviour.
"""

from __future__ import annotations

import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "index.html"
HTML = FRONTEND.read_text(encoding="utf-8")

CHECKS = ["test_integrity", "classic_injection", "agent_injection", "bola", "rls"]


# --------------------------------------------------------------------------- #
# The vehicle
# --------------------------------------------------------------------------- #
def test_the_light_is_carried_by_something():
    """A light with no body cannot be somewhere, and being somewhere is this scene's whole
    claim. The lamp used to be a 14px dot and a cone with nothing holding either."""
    assert 'class="snd-sub"' in HTML
    assert "snd-hull" in HTML
    assert 'class="snd-lamp"' not in HTML and 'id="snd-lamp"' not in HTML
    # two floodlights thrown from the rig, not one cone hung in the water
    assert HTML.count('class="snd-cone l"') == 1
    assert HTML.count('class="snd-cone r"') == 1


def test_the_proof_strength_ink_is_untouched():
    """`--lamp` is the page's proof-strength red in forty-odd rules and three DESIGN.md laws.
    Giving the light a body was never a reason to rename the ink."""
    assert "--lamp:#FF5A46;" in HTML
    assert "--lamp-glow:" in HTML and "--lamp-tint:" in HTML
    assert "--ch-lamp-warm:" in HTML


def test_the_vehicle_answers_its_own_velocity():
    """Pitch, thruster, bubbles and the splay of the lights are all driven from one number, so
    a hovering submarine cannot be drawn under power."""
    assert "--sub-run" in HTML
    # the pitch is negated where it is USED and not where it is written, because
    # `--sub-pitch-max` is a magnitude and nose-down is the negative direction
    assert "-1 * var(--sub-pitch)" in HTML
    assert "calc(.9s / max(.06, var(--sub-run)))" in HTML


def test_the_vehicle_keeps_station_on_four_axes():
    """This test used to be half of the one above, which asserted the hull transform was exactly
    `rotate(calc(-1 * var(--sub-pitch)))` — one axis, driven by one number. The vehicle has since
    been given four more: a lateral drift, a yaw that lags the drift, a roll that lags the yaw,
    and a distance. The assertion broke because it was written to a shape rather than to a rule,
    and for a while the only thing it was guarding was its own spelling.

    So it guards the rule instead. The point of the extra axes is that they are LAGS — the hull
    is still turning after the drift has stopped, and banks after the turn — and a lag only
    exists if the axes stay separate properties written from separate numbers. Collapse any two
    of them onto one input and the whole assembly peaks on the same frame again, which is the
    rigid decal this was all built to stop being.
    """
    # pitch and roll compose on one rotation, and they are not the same number
    assert "rotate(calc(-1 * var(--sub-pitch) + var(--sub-roll)))" in HTML
    # yaw is a foreshortening on a side-profile sprite, never a second rotation
    assert "scaleX(var(--sub-fore))" in HTML
    assert "rotate(var(--sub-yaw))" not in HTML
    assert "scale(var(--sub-z))" in HTML
    # every axis is written from the frame loop, so none of them is a constant in disguise
    for axis in ("--sub-yaw", "--sub-roll", "--sub-fore", "--sub-z"):
        assert "setProperty('%s'" % axis in HTML
    # and all four are pinned under reduced motion, where the loop that writes them never runs
    assert "--snd-subx:50%;--sub-yaw:0deg;--sub-roll:0deg;--sub-fore:1;--sub-z:1" in HTML


# --------------------------------------------------------------------------- #
# The descent is continuous
# --------------------------------------------------------------------------- #
def _scene_source() -> str:
    start = HTML.index("const scene = (function(){")
    return HTML[start:HTML.index("/* ================= talking to the engine", start)]


def test_the_descent_is_one_loop_and_not_a_queue_of_steps():
    """The stutter this replaced was an `await` chain: travel, stop, hold, travel, stop, hold.
    Every one of those holds was a join the eye read as a slideshow. There is now a single frame
    driver, and nothing inside the scene may await anything."""
    scene = _scene_source()
    assert "function drive(now)" in scene
    assert "requestAnimationFrame(drive)" in scene
    assert "await " not in scene, "the descent awaits something again"
    for gone in ("function travel(", "async function breach(", "--dur-step", "--dur-travel-min"):
        assert gone not in HTML, f"{gone} came back"


def test_a_mark_lights_because_the_vehicle_reached_it():
    """Positional, not sequential. That is what removes the last per-candidate stop, and it is
    also what keeps the picture and the position the same statement."""
    scene = _scene_source()
    assert "depth >= p.litAt" in scene
    assert "p.litAt = Math.max(c.layer.depth" in scene


def test_the_frontier_is_the_only_thing_that_says_how_deep():
    scene = _scene_source()
    assert "function frontier()" in scene
    # a layer with anything outstanding stops the vehicle at that layer's own ceiling
    assert "if(done.length < c.pips.length)" in scene
    # and the deepest it may ever go is the deepest thing there is to reach, never the scale end
    assert "function reach()" in scene
    assert "return Math.min(d, DEPTH_MAX)" in scene


def test_the_run_finishes_even_when_nobody_is_watching():
    """A backgrounded tab gets no frame callbacks, and the descent IS the loop — so without
    this the whole run hangs on a promise that can never resolve."""
    scene = _scene_source()
    assert "function catchUp()" in scene
    assert "document.hidden || reduce" in scene
    assert "visibilitychange" in scene
    # and a reader who turns reduced motion on mid-descent is answered now, not on reload
    assert "motionJobs.add({start: pace, stop: pace})" in scene


# --------------------------------------------------------------------------- #
# Five worlds
# --------------------------------------------------------------------------- #
def test_every_check_axis_has_a_sea_of_its_own():
    """Five bands of the same empty water do not become five places because they are captioned
    differently, and "one layer per check axis" is the claim the scene rests on."""
    for check in CHECKS:
        assert f"SEA.{check} = function" in HTML, f"{check} has no sea"


def test_a_sea_is_keyed_off_the_same_table_as_its_stratum():
    """A check cannot have one name in the layer table and another in the sea table, or a run
    grows a sixth axis and loses its world without anything failing."""
    layers = set(re.findall(r"check:'(\w+)'", HTML))
    seas = set(re.findall(r"SEA\.(\w+) = function", HTML))
    assert seas <= layers, f"a sea for a check no stratum knows: {seas - layers}"
    # a check with no sea is open water, and that has to be a deliberate branch
    assert "// open water: a layer this view has no sea for" in HTML


def test_sea_ink_is_inherited_and_never_classed():
    """A <use> instances its symbol into a shadow tree that document selectors cannot reach, so
    `.sea .ink{fill:...}` matches nothing and every shape falls back to the SVG default — solid
    black. `fill` and `color` are inherited, so they cross that boundary. This cost an afternoon
    and looked like a colour choice rather than a bug, which is exactly why it is pinned."""
    sprite = HTML[HTML.index('<svg class="sea-sprite"'):HTML.index("</defs></svg>")]
    assert 'fill="currentColor"' in sprite
    assert 'class="ink' not in sprite and 'class="mass"' not in sprite
    assert ".sea svg{color:" in HTML or ".sea svg{color" in HTML


def test_distance_is_haze_and_nearness_is_silhouette():
    """Underwater a far object tends toward the colour of the water between you and it, and a
    near one is between you and the light. Getting this backwards made a coral head a cloud."""
    assert ".snd-planes.far .sea svg{color:var(--wash)}" in HTML
    assert ".snd-planes.near .sea svg{color:var(--abyss)}" in HTML


def test_the_parallax_rates_are_read_from_the_stylesheet():
    """A factor named in the stylesheet and retyped in the script is the drift every token on
    this page exists to prevent."""
    for token in ("--par-far", "--par-mid", "--par-near"):
        assert f"{token}:" in HTML, f"{token} is not defined"
        assert f"rate('{token}'" in HTML, f"{token} is not read back"


def test_the_near_plane_is_in_front_of_the_vehicle():
    """Foreground objects overtaking the sub is the depth cue the whole three-plane rig is for;
    a near plane behind the vehicle is just a third background."""
    assert "--par-near:1." in HTML, "the near plane no longer outruns the world"
    assert ".snd-planes.near{z-index:7}" in HTML


def test_the_instrument_paints_above_the_sea():
    """A silhouette may sweep over the submarine. It may never sweep over a layer's name or a
    candidate's title — that reads as a rendering fault, and it hid the word CORAL OVERHANG
    behind a coral overhang."""
    assert ".snd-world{z-index:9}" in HTML
    assert ".snd-planes.near{z-index:7}" in HTML
    assert ".snd-sub{" in HTML and "z-index:6" in HTML
    # the ground travels with the world but paints under the sea, so it cannot share its element
    assert 'class="snd-waterbox"' in HTML
    assert ".snd-waterbox{" in HTML and "z-index:0" in HTML


def test_colour_dies_with_depth():
    """The page already states 'warm light does not survive at depth' as a law. This renders it:
    by the trench the only warm thing in frame is the light the vehicle is carrying, because the
    floodlights are outside the filter the sea is inside."""
    assert "filter:saturate(calc(1 - var(--dsat)))" in HTML
    assert "--dsat-max:" in HTML
    # written per frame but quantised, because saturate() re-rasterises the plane it is on
    assert "Math.round(q * num('--dsat-max'" in HTML


# --------------------------------------------------------------------------- #
# What the scene is allowed to say
# --------------------------------------------------------------------------- #
def test_no_percentage_and_no_bar_against_an_unmeasured_total():
    """DESIGN.md's hardest rule about this scene, and a streaming run is exactly when it would
    be most tempting to break it."""
    scene = _scene_source()
    # Scoped to the lines that actually SAY something to the reader. A percent sign in a CSS
    # position is a coordinate; a percent sign in the status line or the roster is a claim about
    # a total the engine never sent, and those are the only two places this rule is about.
    said = [ln for ln in scene.splitlines()
            if "status(" in ln or ".textContent =" in ln or "tail = " in ln]
    assert said, "the status writers moved and this test no longer reads them"
    for line in said:
        assert "%" not in line, f"a percentage is being printed: {line.strip()}"
    for gone in ("percent", "Math.round(done /", "/ total", "toFixed(0) + '%"):
        assert gone not in scene


def test_an_unwatchable_run_says_so_rather_than_being_read_as_a_slow_one():
    scene = _scene_source()
    assert "function streaming(on)" in scene
    assert "streams = !!on" in scene
    assert "reports only when it" in scene


def test_the_scene_still_writes_no_results_of_its_own():
    """`ignite()` is the only thing permitted to write a strength word, and the turnaround reads
    the verdict back out of the page rather than deciding it."""
    scene = _scene_source()
    assert scene.count("ignite(") == 1
    assert "vEl.textContent = (v.textContent" in scene
