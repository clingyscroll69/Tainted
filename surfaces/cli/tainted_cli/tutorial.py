"""Tutorial content for the CLI surface. Text only; `main.py` renders it."""

from __future__ import annotations

LESSONS: list[dict] = [
    {
        "topic": "first-scan",
        "title": "Your first scan",
        "summary": "Install Tainted and run your first analyze scan to see possible holes in your code.",
        "steps": [
            {
                "heading": "Install Tainted",
                "body": "From the repo root where you have the core engine and surfaces/cli, run pip install -e . from the root, then pip install -e surfaces/cli. This installs the analyze command and the tainted-gate hook.",
            },
            {
                "heading": "Point analyze at your repo",
                "body": "From any directory, run tainted analyze with the path to your app. Tainted scans the code without running your app and without needing any credentials.",
                "command": "tainted analyze ./my-app",
                "expect": "A panel showing the repo path and counts. Below that, notes on which planes Tainted ran and which it skipped. Then a table of possible holes, ranked by severity.",
            },
            {
                "heading": "Understand what you see",
                "body": "Each row is a possible hole Tainted found by reading the code. The Severity column shows how bad each one is if it were real. Tainted has not proven any of these yet. Without GEMINI_API_KEY set, you are seeing only the Structure register, which finds routes, queries, and taint paths but cannot tell what they mean.",
            },
            {
                "heading": "Turn on the Meaning register",
                "body": "Set your GEMINI_API_KEY environment variable. Run analyze again. Tainted will rank the same holes differently because it now asks the model questions the code alone cannot answer, like whether an id belongs to someone and if anyone checked ownership.",
                "command": "export GEMINI_API_KEY=your-key && tainted analyze ./my-app",
            },
            {
                "heading": "Measure the tests that should catch it",
                "body": "test_integrity is the one check analyze leaves out unless you name it. It mutates your code and re-runs your own suite (mutmut for Python, Stryker for JS/TS), which takes minutes and needs that tool and your test dependencies installed. Every change no test catches is listed as a low-severity line to look at, never a vulnerability.",
                "command": "tainted analyze ./my-app --only test_integrity",
                "expect": "A Test integrity line with the share of mutants killed, and one row per surviving mutant. If the tool is missing, the line says it was not measured and why.",
            },
        ],
        "next": "Next, read the proof-strength labels in a report to understand which holes are proven and which are still hunches.",
    },
    {
        "topic": "reading-a-report",
        "title": "Reading a report",
        "summary": "Learn what each column in the report means, especially the proof-strength labels that tell you how confident Tainted is.",
        "steps": [
            {
                "heading": "Severity is the risk level if the hole is real",
                "body": "Each row shows Critical, High, Medium, Low, or Info. This is what Tainted thinks would happen if someone actually exploited it. A low-severity hole is still wrong and should be fixed, but it is less urgent.",
            },
            {
                "heading": "Check names the rule that found it",
                "body": "bola is Broken Object Level Authorization: one user reaches another user's record with their own token. rls is Row Level Security: the database's own row policy is missing or lets the read through. classic_injection is a SQL query, shell command or template built from input. agent_injection is one agent holding both a tool that reads untrusted content and a tool that acts, so the content can steer the action. test_integrity is a line your tests would not notice changing. Each one has its own proof strategy.",
            },
            {
                "heading": "Title and Location pinpoint the hole",
                "body": "The Title column describes what the hole is. The Location column gives the file and line number. Together they tell you exactly which part of your code needs to move. Navigate to that file and read the code to understand the finding.",
            },
            {
                "heading": "Proof strength shows how far Tainted got",
                "body": "Below the table, Tainted shows a Coverage section if proofs were attempted. It lists each check and marks it proven, reported, or demonstrated-but-not-run. Proven means Tainted actually ran the attack and it worked. Reported means Tainted found evidence in the code but did not run it. Demonstrated-but-not-run means Tainted built the payload but deliberately did not fire it.",
            },
            {
                "heading": "No LLM means incomplete ranking",
                "body": "Without GEMINI_API_KEY, all holes the Structure register finds are ranked by the Severity field, but they are all in the same proof category. The plane notes at the top say which registers ran. If Meaning is missing, you are not seeing the model's judgment about which holes are most likely real.",
            },
            {
                "heading": "A hole at severity does not mean it works",
                "body": "The Severity column shows the impact if the hole were real. A high-severity finding that is only reported, not proven, is a candidate worth investigating, not a confirmed vulnerability. Only proven findings have actually been attacked and found to work.",
            },
        ],
        "next": "Next, use tainted watch to re-run analyze on every save while you write and test code.",
    },
    {
        "topic": "on-save",
        "title": "Watching for changes",
        "summary": "Run tainted watch to re-scan your code every time you save a file, giving you fast feedback while you code.",
        "steps": [
            {
                "heading": "Start the watch loop",
                "body": "Run tainted watch with the path to your app. Tainted scans the repo once, prints the report, and then watches for file changes. Every time you save a file in your code editor, it re-runs analyze and clears the screen to show the new report.",
                "command": "tainted watch ./my-app",
                "expect": "The initial report, then a message at the bottom saying Watching for changes. Press Ctrl-C to stop.",
            },
            {
                "heading": "Edit your code and save",
                "body": "Open your app in your editor and make a change. When you save the file, watch detects it within a half-second and re-scans. The screen clears and a new report appears. If your change fixed a hole, it drops from the report. If it introduced one, it appears.",
            },
            {
                "heading": "Narrow the scans with --only",
                "body": "If your app is large, scanning all checks every time is slow. Use --only with a comma-separated list of checks to run fewer checks. For example, --only bola,rls scans only for broken API access and database policies, skipping injection and other checks.",
                "command": "tainted watch ./my-app --only bola,rls",
            },
            {
                "heading": "Skip specific checks with --skip",
                "body": "Alternatively, if one check is known to be noisy or not relevant to your app, use --skip to omit it. For example, --skip agent_injection will watch everything except the tool plane.",
                "command": "tainted watch ./my-app --skip agent_injection",
            },
            {
                "heading": "Stop the loop anytime",
                "body": "Press Ctrl-C to stop watching. The loop exits cleanly. You can restart watch again anytime.",
            },
            {
                "heading": "Watch does not need credentials or a running app",
                "body": "Unlike prove or fix, watch runs only the Structure register and optionally the Meaning register if GEMINI_API_KEY is set. It does not fire any attacks. Your app does not need to be running.",
            },
        ],
        "next": "Next, set up tainted-gate as a pre-commit hook to catch holes before you push.",
    },
    {
        "topic": "on-commit",
        "title": "Blocking commits with the gate",
        "summary": "Wire tainted-gate into your git pre-commit hook to block commits that introduce high-severity possible holes.",
        "steps": [
            {
                "heading": "Add the pre-commit hook to your config",
                "body": "Add this to your project's .pre-commit-config.yaml file: a repo pointing to the Tainted repo, a rev pointing to the version you want, and a hook with id tainted. See the main README for the exact YAML. Then run pre-commit install.",
            },
            {
                "heading": "Understand how the gate works",
                "body": "When you commit, the pre-commit hook runs tainted analyze on your repo. It scans the code without running your app. If any possible hole is at or above the fail-on threshold (default high), the commit is blocked and exits with code 1. Exit 0 means you can commit.",
            },
            {
                "heading": "Change the severity threshold",
                "body": "By default, tainted-gate blocks commits for High and Critical severity. You can lower or raise the threshold with the --fail-on flag. For example, --fail-on medium will block on Medium, High, and Critical. The allowed values are critical, high, medium, low, and info.",
            },
            {
                "heading": "Override the gate",
                "body": "The gate blocks because Tainted found something that needs attention. If you have reviewed the candidate and decided it is acceptable, you can override the gate with git commit --no-verify, but then you are responsible for the risk.",
            },
            {
                "heading": "The gate does not prove anything",
                "body": "The gate runs only analyze, which is static and read-only. It does not fire any attacks. A high-severity possible hole that blocks the commit is a candidate, not a confirmed vulnerability. After your code ships, you should prove these findings with tainted prove to know they are real.",
            },
            {
                "heading": "Set GEMINI_API_KEY for better blocking",
                "body": "Without the Meaning register, the gate blocks based on Severity alone. With GEMINI_API_KEY set, the model ranks which holes are most likely real. The gate will block more intelligently.",
            },
        ],
        "next": "Next, use tainted prove to run real attacks against your app and confirm a hole is real.",
    },
    {
        "topic": "proving-it",
        "title": "Proving with real attacks",
        "summary": "Run tainted prove against a running app to fire real exploits and confirm a possible hole is actually exploitable.",
        "steps": [
            {
                "heading": "Set up your target and accounts",
                "body": "You need: the base URL of your running app, two test accounts with login credentials, and at least one seed record owned by account A. For example, if your app is a notes app and account A owns a note with id 5, the seed record is notes:5. Tainted will use this to test whether account B can steal that note.",
                "command": "tainted prove ./my-app --url http://localhost:3000 --login-a a@test.com:password --login-b b@test.com:password --seed notes:5",
            },
            {
                "heading": "Watch the exploit run",
                "body": "Tainted logs in as both accounts, finds the seed record, and fires each possible hole at the running app. For bola, it asks if account B can read account A's data through the same route. For rls, it checks if PostgREST reads return rows that are not the caller's. For each one, the report shows whether the attack succeeded.",
            },
            {
                "heading": "Read the proof output",
                "body": "After the attack runs, the report shows proven findings in red boxes. Each box shows the HTTP request Tainted sent, the response it got, and why that response proves the hole. If no findings are proven, you see the list of candidates with their proof status as reported or not-reproduced.",
            },
            {
                "heading": "Localhost needs no ownership check",
                "body": "If your target is localhost or 127.0.0.1, Tainted trusts you own it and fires attacks immediately. No additional permission is needed.",
            },
            {
                "heading": "Remote targets are refused outright",
                "body": "The CLI proves against an app running on your own machine, so if the target is not localhost or 127.0.0.1, it refuses to run at all -- there is no flag or token that unlocks a remote target. Point it at an app running locally, or use the website surface, which has its own ownership check for a repository you picked from GitHub.",
            },
            {
                "heading": "Interpret the exit code",
                "body": "If prove finds any high-severity proven findings, it exits with code 1. Exit code 0 means no proven findings at that level or higher. Exit code 2 means the target was not localhost and prove was refused. Use these exit codes in scripts to decide what to do next.",
            },
        ],
        "next": "Next, use tainted fix to write a fix, then prove it again to see the hole close.",
    },
    {
        "topic": "fixing-it",
        "title": "Writing and proving a fix",
        "summary": "Run tainted fix to interview you about the fix and write the code, then prove it again to see the hole closed.",
        "steps": [
            {
                "heading": "Name the hole you want fixed",
                "body": "Every row analyze prints carries two handles: a # on the left and an ID next to it. Pass the ID with --finding-id and you have named the hole itself, so the same command still means the same hole after you edit the code. Pass the number with --index and you have named a position in that one report, which moves the moment anything else does. Prefer the ID; the number is there because a numbered table invites you to type the number.",
                "command": "tainted fix ./my-app --finding-id 1db5cbc5350811b5",
                "expect": "Tainted prints the title of the candidate and its ID. For some checks like agent_injection, it asks questions. For others like bola, it writes the fix immediately and shows the diff.",
            },
            {
                "heading": "Answer the interview questions",
                "body": "For some checks, the code alone cannot decide what the fix should be. Tainted asks: Should we add ownership checks? Should we reject the request? Should we change the data model? Each option is spelled out. Type your choice and press Enter. Use --yes to skip questions and accept the defaults.",
            },
            {
                "heading": "Review the diff before applying",
                "body": "Tainted prints the proposed fix as a diff. Read it carefully. The diff shows the file, the old code, and the new code. If the fix looks wrong or incomplete, do not apply it. You can run fix again and answer the questions differently.",
            },
            {
                "heading": "Apply the fix with --apply",
                "body": "By default, fix only shows the diff. Add --apply to write the fix to disk. Tainted writes the file and prints the path. The file is now changed in your working tree. Do not run fix again with --apply unless you want to overwrite it.",
                "command": "tainted fix ./my-app --finding-id 1db5cbc5350811b5 --apply",
            },
            {
                "heading": "Verify it with prove",
                "body": "fix does not re-run the attack: beside a patch nobody has applied yet, the attack would only find the hole again. Apply the fix, restart your app, and run the same prove as before. The fix holds when the finding comes back as not reproduced. prove also asks for the same record as account A, so a fix that locks the owner out too is reported as unproven, not as held.",
                "command": "tainted prove ./my-app --url http://localhost:3000 --login-a a@test.com:password --login-b b@test.com:password --seed notes:5",
                "expect": "The finding no longer appears among the proven. If it reads unproven because account A was refused as well, the fix went too far.",
            },
            {
                "heading": "An agent fix is checked on the spot",
                "body": "agent_injection is the exception. Its fix reshapes the agent graph, so Tainted rebuilds the graph the fix leaves and checks it right away: no agent may still hold both tools, and the pairing must not have moved to another agent. A fix that keeps both tools behind a gate is reported, not fixed, because the gate runs in your runtime. If a check fails, the exit code is 1.",
            },
        ],
    },
]
