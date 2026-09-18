/* Guided-tour content for the Tainted website. Text only; index.html renders it. */
window.TAINTED_TOUR = {
  label: 'Take the tour',
  intro: {
    title: 'Read a descent',
    body: 'This page logs a dive through your app. You send Tainted your code, it finds where a stranger\'s data reaches something dangerous, then fires the real attack to prove the hole works. The depth marks show how far the data got past the ownership boundary.'
  },
  steps: [
    {
      anchor: 'loaddemo',
      title: 'Start with the demonstration',
      body: 'The demo loads a made-up run from a fictional app. Its findings are invented, its proof is not attempted. But the layout, the color scheme, and the proof-strength marks are from real runs. Use it to learn the page without needing your own app running.',
      note: 'No code is scanned. No exploit fires. The workflow is live.'
    },
    {
      anchor: 'setup',
      title: 'Give Tainted your code',
      body: 'There is nowhere to type a repository name, on purpose. Sign in with GitHub and Tainted lists the repos your own token can reach, then fetches the one you pick for the length of a single request. Choose before you sign in whether that list covers your public repos only, or your private ones too — public only is the default, and it is the narrower thing to hand a scanner.',
      note: 'Analyze is static and read-only. Tainted never writes to your repo; the fix comes back as a patch.'
    },
    {
      anchor: 'scan',
      title: 'Analyze finds possible holes',
      body: 'Hit Analyze. Structure reads the code itself — routes, parameters, queries, policies, agent tools — exhaustive but cannot tell what any of it means. Meaning is the model answering what Structure can\'t: is this id someone\'s property, did anyone check ownership? Meaning only runs if you configure the Gemini key. Proof, the third register, runs later when you Arm. What comes back is ranked possible holes, nothing proven yet.'
    },
    {
      anchor: 'verdict',
      title: 'The verdict stays cold until proof lands',
      body: 'The verdict line shows how many holes have been proven and how many are only reported. Before you run an exploit, it says nothing is proven yet. That is correct. A hole is not real until Tainted breaks in through it.'
    },
    {
      anchor: 'findings',
      title: 'Each observation shows a path',
      body: 'One finding lists where a stranger\'s request entered, which check found it, and the depth: how far past the ownership boundary it reached. The depth is a ranking, not a distance. The deeper the mark, the more it had to get through.'
    },
    {
      anchor: 'hd-str',
      title: 'Three proof strengths, not one',
      body: 'Proven means Tainted ran the real attack and it worked. That mark is warm red. Demonstrated means a real payload was built but deliberately not fired, for command injection and coded agents. Cold marks were never tried. Every finding shows which it is. One word and one color does the job.'
    },
    {
      anchor: 'gate',
      title: 'The thermocline holds off strangers',
      body: 'The ownership check is a cyan line on the left rail. On localhost, Tainted runs any exploit you ask. Off localhost, Tainted refuses until you prove you own the target. Publish the verification token as a DNS record or at /.well-known/tainted. That boundary is correct and it cannot be switched off.'
    },
    {
      anchor: 'arm',
      title: 'Arm proves by running the real exploit',
      body: 'Fill in the target URL and the test accounts. Arm fires the actual attack against your live app. As each candidate is attempted, the descent animates and the proof log fills in. Red marks light as exploits succeed. The lamp is your own; you are watching what it illuminates.'
    },
    {
      anchor: 'hd-gates',
      title: 'The website hands you a patch to apply',
      body: 'Fix generates a patch you download and apply yourself. The website has no working tree, so it cannot write to your repo or re-run the check. Take the patch to your terminal, apply it, run the attack again on your own. That is where this surface stops.'
    }
  ],
  outro: {
    title: 'One surface of four',
    body: 'This is the browser version. The CLI surface runs in your terminal. The CI surface gates your build. The MCP surface hands findings to your coding agent. They all run the same engine and report the same checks. Come back here to see the whole descent at once.'
  }
};
