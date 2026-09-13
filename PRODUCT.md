# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary user: a developer who built an app with AI (an LLM coding assistant, a
code-gen tool, a "vibe-coded" prototype) and needs to know if it is safe to
ship. They ship fast, often solo or on a small team, and usually are not security
experts — they can read a finding and apply a fix, but they do not think in
threat models. They want a straight yes or no, and when it's no, they want proof
and a fix.

## Product Purpose

Tainted is a security scanner for AI-written apps. It finds the places where a
stranger's data can reach something dangerous, **proves** each one by actually
carrying out the attack against the running app, and — where the fix is safe to
make — writes the fix and proves the hole closed. The developer should trust the
result because Tainted showed it, not because Tainted claimed it: no unproven scare, no
silent hole.

## Positioning

Proof, not suspicion. Other scanners emit a ranked list of warnings. Tainted confirms a
finding only by running the real exploit against the live app; a suspicion is never a
finding. It works across three registers no single-technique tool combines:
**Structure** (deterministic static analysis), **Meaning** (an LLM supplying the
judgment static analysis can't — for example, is this `id` someone's
property, and did anyone check ownership?), and **Proof** (live execution). How they
combine: the LLM *ranks* request-plane possible holes, and every one gets tried
anyway; on the tool plane's dynamic half the LLM *filters* instead, because that
half is expensive to try.

## Operating Context

The product is an engine (a Python library) with four thin front-end surfaces, each
deployable on its own: `cli/` (the developer's terminal, plus a pre-commit gate),
`ci/` (a CI/CD pipeline gate with ownership checks), `mcp/` (an MCP server for an
AI agent to call), and `website/` (a hosted app: a FastAPI backend and a browser
frontend that today draws findings as a graph). Core operations: `analyze(repo)`
— static, read-only, returns ranked possible holes; `prove(target, setup)`
— drives the running app and fires real exploits, gated by ownership checks once
the target isn't localhost; `fix(finding)` — writes the fix and re-checks
it. The website surface is the immediate focus for design work.

## Capabilities and Constraints

- Proven end to end: the request plane (BOLA/RLS, for example Supabase/PostgREST), the
  tool plane (MCP/n8n/LangChain tool graphs), classic injection (SQL injection is
  provable live), and test-integrity checking (a mutation-testing wrapper).
- Being honest about how far something was proven is a hard product rule: every
  finding is labeled by how far Tainted got. Some are **proven** (Tainted ran the
  exploit and it worked). Some are **reported** or **demonstrated but not run**
  (for example a coded agent's tool plane, or command/template injection). The
  product must never show a reported or demonstrated finding as a proven one.
- `prove` and `fix` act against a live app and can run real attacks. Once the target
  isn't localhost, Tainted gates that action behind an ownership check. This is a
  safety boundary; the product must show it plainly, never hide it.
- Consent is a settled constraint: a corpus-scan feature that attacked public agent
  configurations without their owners' consent was deliberately removed. Do not
  bring back any capability that acts against a system whose owner has not consented.
- Terms to keep exactly as they are: the three registers (**Structure / Meaning /
  Proof**), the three operations (**analyze / prove / fix**), request plane vs. tool
  plane, and the proof-strength labels above.

## Brand Commitments

The name is **Tainted**. Nothing else is fixed yet: no logo, no set voice or visual
identity, no defined personality. Future work chooses these. It must not treat any
invented mark, tagline, or tone as if it already existed.

## Evidence on Hand

Real, in the repo: the working engine (its hermetic test suite passes), live-tested
Gemini calls, and the four built surfaces, including the website's graph
frontend. There are **no** customers, testimonials, case studies, benchmark numbers,
press, or usage numbers. Future work must not invent any of these. If social proof or
numbers are needed, get them from the user; do not make them up.

## Product Principles

1. **Proof over suspicion.** A finding earns its place by being shown to work, not
   claimed. The product's credibility is the proof; never water it down with
   unproven noise.
2. **Honest about certainty.** Always show how far something was proven. Claiming too
   much is worse than claiming too little.
3. **For the non-expert who ships.** Speak to a developer, not a security analyst.
   Make the verdict and the next step obvious without a threat-modeling background.
4. **Consent is a boundary, not a setting.** The product only acts against systems
   whose owner has authorized it. This limits what features can do, not just what the
   copy says.
5. **The engine is the truth; surfaces are thin.** Every surface must show the same
   core result faithfully. A surface must never imply the engine can do something it
   can't.
