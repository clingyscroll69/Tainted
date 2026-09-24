"""Tutorial content for the CI surface. Text only; `entrypoint.py` renders it."""

from __future__ import annotations

LESSONS: list[dict] = [
    {
        "topic": "analyze-only",
        "title": "Gate every pull request",
        "summary": "Run tainted-ci on every pull request and report ranked possible holes in a job summary.",
        "steps": [
            {
                "heading": "Check out the repo",
                "body": "Create a GitHub Actions workflow in .github/workflows/tainted.yml. The entrypoint expects a checkout, so your preview deploy step (whatever builds and runs your app) should come before you call tainted-ci.",
            },
            {
                "heading": "Add the tainted-ci step",
                "body": "Call the tainted-ci container as a step in your job. Set TAINTED_REPO to point to your checkout (default: current directory). Pass GEMINI_API_KEY if you have one; without it, only static analysis runs.",
                "command": """name: Tainted
on: pull_request
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build and deploy preview
        # Your existing deploy step here
        run: npm install && npm run build
      - name: Scan for proven holes
        uses: docker://ghcr.io/...tainted-ci:latest
        with:
          env:
            TAINTED_REPO: .
            GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}""",
            },
            {
                "heading": "Understand what you see",
                "body": "The job writes a markdown summary to the GitHub PR. It lists candidates — possible holes found in your code by static analysis. No prove step runs yet, so nothing is proven. High-severity candidates still fail the job to surface them early.",
                "expect": "A job summary with 'Candidates' table showing severity, check type, title, and code location.",
            },
            {
                "heading": "Know the limits",
                "body": "This is analyze only. You are seeing ranked guesses, not proofs. Tainted argues from the code that a hole might exist, but did not fire an exploit. To see what is really vulnerable, add a preview deploy URL and proof will run.",
            },
        ],
        "next": "Move to prove-the-preview to actually confirm the holes.",
    },
    {
        "topic": "prove-the-preview",
        "title": "Prove holes against the preview",
        "summary": "Add your preview URL and Tainted fires real exploits to confirm which candidates are real vulnerabilities.",
        "steps": [
            {
                "heading": "Set the target URL",
                "body": "Your deploy step already builds a preview. After it starts, export the running URL as TAINTED_TARGET_URL. If the preview is at http://preview.example.com, Tainted will send requests to it.",
                "command": "TAINTED_TARGET_URL: http://preview.example.com",
            },
            {
                "heading": "Add test accounts",
                "body": "Proof requires two accounts to test ownership boundaries (BOLA: does account B see account A's records?). Set TAINTED_LOGIN_A and TAINTED_LOGIN_B as email:password pairs. The accounts must exist and have different records in your app.",
                "command": """TAINTED_LOGIN_A: user1@example.com:password123
TAINTED_LOGIN_B: user2@example.com:password456""",
            },
            {
                "heading": "Add a seed record",
                "body": "For BOLA proof, Tainted reads a specific record. Set TAINTED_SEED as table:id to seed the test. For example, items:42 tells Tainted to target the item with id 42 in the items table.",
                "command": "TAINTED_SEED: items:42",
            },
            {
                "heading": "Run the workflow",
                "body": "Push to a new branch. The job analyzes, then proves by sending HTTP requests against your preview. Each proven finding shows the request that broke in.",
                "expect": "Job summary now includes 'Proven' section with actual HTTP requests that succeeded. Candidates still appear; unproven ones are in a separate table.",
            },
            {
                "heading": "See the proof",
                "body": "Each proven finding shows the request method, URL, and what the response proved. For example, GET /api/users/123 when you were logged as a different user, and it returned that user's email.",
            },
        ],
        "next": "Move to ownership to verify who Tainted is claiming to be when it runs the proof.",
    },
    {
        "topic": "ownership",
        "title": "Prove the run is your repository's",
        "summary": "Understand why DNS records cannot guard preview deploys, and how OIDC repo-claims work.",
        "steps": [
            {
                "heading": "Why not DNS",
                "body": "A preview deploy lives for one job run, then vanishes. You cannot put a DNS TXT record at a domain that disappears after 10 minutes. So Tainted checks ownership a different way: a signed token proves the run belongs to your repository.",
            },
            {
                "heading": "The OIDC token",
                "body": "GitHub Actions can mint a short-lived signed identity token whose claims say which repository the run belongs to. Tainted accepts it only from GitHub's or gitlab.com's issuer, checks the signature against that issuer's keys, and requires audience tainted. Mint it in a step and pass it in. secrets.GITHUB_TOKEN is an API token, not this one.",
                "command": """- id: oidc
  run: |
    TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=tainted" | python -c 'import sys,json;print(json.load(sys.stdin)["value"])')
    echo "::add-mask::$TOKEN"
    echo "token=$TOKEN" >> "$GITHUB_OUTPUT"
# then, on the Tainted step:
env:
  TAINTED_OIDC_TOKEN: ${{ steps.oidc.outputs.token }}""",
            },
            {
                "heading": "Add the permission block",
                "body": "GitHub Actions requires you to opt into id-token minting. Add 'permissions: id-token: write' to your job. Without it, there is no token and Tainted refuses to prove against the URL.",
                "command": """permissions:
  id-token: write
  contents: read""",
            },
            {
                "heading": "What Tainted checks",
                "body": "The issuer is GitHub or gitlab.com, the signature is that issuer's, the audience is tainted, the token has not expired, and its repository claim matches GITHUB_REPOSITORY (or CI_PROJECT_PATH on GitLab). Any failure refuses the proof, and the report names which check failed.",
                "expect": "Job summary says the repository was verified, signed by GitHub Actions, audience tainted.",
            },
            {
                "heading": "The gap",
                "body": "The token proves the run belongs to your repository. It does not name the preview URL, because neither GitHub nor GitLab lets a workflow add a claim of its own. So which host the preview runs on is your workflow's word, and the report says so every time.",
            },
        ],
        "next": "Move to the-gate to set what severity of proven hole fails the job.",
    },
    {
        "topic": "the-gate",
        "title": "Fail the job when findings are proven",
        "summary": "Set TAINTED_FAIL_ON to choose the severity threshold that fails your build.",
        "steps": [
            {
                "heading": "Set the gate threshold",
                "body": "By default, TAINTED_FAIL_ON is high. A proven hole at high or critical severity fails the job. Proven medium and low findings pass, but appear in the summary. Change it to critical (only critical fails), medium (medium and up fail), or low (any finding fails).",
                "command": "TAINTED_FAIL_ON: high",
            },
            {
                "heading": "Proven vs reported",
                "body": "Only proven findings are compared against TAINTED_FAIL_ON. A proven finding is one where Tainted ran the attack and it worked. Reported findings are argued from the code but not run. High-severity reported findings show as a warning but do not fail the job.",
            },
            {
                "heading": "Analyze-only jobs",
                "body": "If you run analyze but no prove (no TAINTED_TARGET_URL set), severe static candidates are treated as warnings. They do not fail the job because they are not proven, but they do appear in orange in the summary.",
            },
            {
                "heading": "Run the test",
                "body": "Set TAINTED_FAIL_ON to low or medium and push. A proven finding at that severity will fail the job. The job summary shows which findings caused the failure.",
                "expect": "Job marked as failed with ::error:: showing the count and severity of blocking findings.",
            },
        ],
        "next": "Move to auto-fix-pr to have Tainted propose fixes for proven holes.",
    },
    {
        "topic": "auto-fix-pr",
        "title": "Auto-propose fixes as a PR",
        "summary": "Set TAINTED_FIX to open a pull request with fixes for proven holes; its own preview deploy proves them.",
        "steps": [
            {
                "heading": "Enable auto-fix",
                "body": "Set TAINTED_FIX to 1 (or true, or yes). After prove runs and finds eligible findings, Tainted generates fixes, writes them to a new branch, and opens a PR. The PR body shows the request that proved each hole.",
            },
            {
                "heading": "Understand eligible fixes",
                "body": "Only proven findings with deterministic fixes are opened as PRs: BOLA (missing ownership check), RLS (row-level security policies), and classic injection (SQL injection). Tool-plane findings (MCP tool graphs, LangChain agents) have no deterministic fix; those need you to decide something first. The PR note explains why.",
                "command": "TAINTED_FIX: 1",
            },
            {
                "heading": "What a fix PR contains",
                "body": "The branch name is tainted/fix-CHECKS-RUNID (for example tainted/fix-bola-12345). Tainted creates the branch, commits the fixes, pushes, and opens a PR. The body shows the request that proved the hole and explains how the fix will be proved.",
            },
            {
                "heading": "The loop",
                "body": "The run that opens the PR does not re-prove the fix: its preview is the unfixed app, so the attack would only succeed again. The PR's own CI run deploys the patched app, and Tainted sends the same attacks there. The fix holds when each is refused and each owner still reads their own record; a fix that refuses the owner too reads as unproven, not fixed.",
            },
            {
                "heading": "Let the PR start its own run",
                "body": "A pull request opened with the default GITHUB_TOKEN does not trigger workflows, so its proof never runs. Pass a personal access token or a GitHub App token as github-token, or push a commit to the branch yourself.",
                "command": "github-token: ${{ secrets.TAINTED_PR_TOKEN }}",
            },
            {
                "heading": "Review and merge",
                "body": "You still review the fix before merging. Tainted proposed it, but you approve it. This is not a set-and-forget tool; the fix needs your eyes.",
            },
        ],
        "next": "Move to choose-checks to see what each check needs before CI can prove it.",
    },
    {
        "topic": "choose-checks",
        "title": "Choose which checks run",
        "summary": "Learn what each of the five checks needs to be proved in CI, and narrow the run with only and skip.",
        "steps": [
            {
                "heading": "What each check needs",
                "body": "bola (one account reading another's record) and rls (a row policy that lets the read through) need the target URL and both logins; a seed record sharpens the probe. classic_injection (a SQL query, shell command or template built from input) needs the target URL, and login B if the route needs a sign-in; only SQL injection is fired, command and template injection are built and deliberately held. agent_injection (one agent holding a tool that reads untrusted content and a tool that acts) needs GEMINI_API_KEY, because a model has to drive the agent in the sandbox; without it the finding is reported, not proved. test_integrity runs only when you name it.",
            },
            {
                "heading": "Narrow the run",
                "body": "Set only to a comma-separated list to run those checks and nothing else, or skip to leave some out. A misspelt check name fails the job rather than quietly scanning something other than what you asked for.",
                "command": """with:
  only: bola,rls
  skip: agent_injection""",
            },
            {
                "heading": "Measure test integrity where your tests can run",
                "body": "test_integrity mutates your code and re-runs your own suite, so it needs your test dependencies and mutmut (Python) or Stryker (JS/TS). The action's container has none of them, so naming it there reports Not measured. Run it as an ordinary step after your install step instead, using the CLI.",
                "command": """- run: pip install -r requirements.txt tainted-cli mutmut
- run: tainted analyze . --only test_integrity""",
                "expect": "A Test integrity line with the share of mutants killed, and one low-severity row per line no test caught. None of them fail the job.",
            },
        ],
    },
]

# Shown in the job summary when the pipeline is only half-configured, to say what the run
# could not reach and what to set to reach it. Keyed by the gap that was detected.
NEXT_STEPS: dict[str, str] = {
    "no_target": "Set `TAINTED_TARGET_URL` to your running preview to prove holes by running real exploits. Until then, only static analysis runs — no attacks are fired.",
    "no_accounts": "Set `TAINTED_LOGIN_A` and `TAINTED_LOGIN_B` as `email:password` pairs so Tainted can test ownership boundaries (BOLA: can one account see another's records?).",
    "ownership_refused": "Ownership was refused; the line above says which check failed. On GitHub, add `permissions: {id-token: write}`, mint a token for audience `tainted` in a step, and pass it as `TAINTED_OIDC_TOKEN` (see `examples/github-workflow.yml`). `secrets.GITHUB_TOKEN` is not an OIDC token.",
    "all_configured": "All environment variables are set. Proof will run on the next push. Check the job summary for proven findings and re-verification of any fixes.",
}
