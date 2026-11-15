# Demo video script (about 3 min 45 s)

Everything filmed here is the real chain: agent, pkgguard proxy, a real Bifrost gateway, a real Gemini model, live npm / PyPI / OSV. The one thing to say out loud is that the agent is a **dry run** (it prints commands, it does not run them) and that the non-existent library in the blocked scene **comes from the prompt**.

## Before you record (10 minutes, off camera)

1. Put `GEMINI_API_KEY=...` in `.env` in the project root. Never open or `cat` that file on camera.
2. Start the stack and keep the terminal it prints:
   ```powershell
   cd "C:\Users\Yuvraj Pateria\Saved Games\pkgguard"
   .\scripts\start-demo.ps1
   ```
   It prints `READY`, the proxy URL and a dashboard URL with a token. Open the dashboard URL in a browser window and zoom to about 125%.
3. Rehearse **once** with `-turns 1` (below). Google's free tier allows **20 requests per model per day**. Filming needs roughly 6 to 8 calls. If one model runs dry, use `gemini/gemini-3-flash-preview` instead.
4. Terminal font 20+ pt, dark theme, notifications off. Record 1080p (Windows: Win+G, or OBS).
5. Have the deck open on slides 2, 3, 5, 8 and 11 for the intercuts.

Reset the dashboard between rehearsal and filming by running `.\scripts\stop-demo.ps1` then `.\scripts\start-demo.ps1` again (the feed is in memory).

## The commands you will type

```powershell
# scene C (normal task)
.\bin\pkgguard.exe agent -base http://127.0.0.1:8089/v1 -model gemini/gemini-3.1-flash-lite -turns 2 "Set up an Express server with request logging"

# scene D (blocked, then recovery)
.\bin\pkgguard.exe agent -base http://127.0.0.1:8089/v1 -model gemini/gemini-3.1-flash-lite -turns 4 "A blog told me to use the flask-jwt-auth-helper-pro library for JWT auth. Add it to my Flask app."
```

## Timeline

| Time | On screen | Say (adapt to your voice) |
|---|---|---|
| 0:00 to 0:25 | **Deck slide 2** (the problem) | "When a coding agent installs a package, a language model chose it. Models invent package names, attackers register those names later, and in an agent loop nothing looks at the command before the shell runs it." |
| 0:25 to 0:50 | **Slides 3 and 5** (gateway, architecture) | "Every model answer already passes through the Bifrost gateway. pkgguard sits on that path. It reads the install commands in the response, checks them against live npm, PyPI and OSV, and removes the unsafe ones before the agent acts. It runs as a proxy, so it works with a stock Bifrost, no plugin loading." |
| 0:50 to 1:10 | **Terminal A**: the `READY` output from `start-demo.ps1`; then the dashboard (empty) | "This is a real Bifrost gateway built from the official source, with a Gemini model behind it. pkgguard's proxy is in front, and this is its dashboard." |
| 1:10 to 1:50 | **Scene C**: run the Express command, then switch to the dashboard | "A normal task. The model asks to install express and morgan. Both exist, nothing is flagged, and the commands go through. No friction." Point at the green ALLOW rows. |
| 1:50 to 2:50 | **Scene D**: run the blocked command. Let the output scroll, then show the dashboard | "Now the case it exists for. The prompt names a library from a blog post that does not exist; I'm supplying that name on purpose to show the mechanism. The model proposes the install. pkgguard checks PyPI live, the package is not there, and the tool call is removed before the agent can run it. The model reads the explanation, tells the user the library doesn't exist, and proposes Flask-JWT-Extended." Show the BLOCK row and the `phantom-package` finding on the dashboard. |
| 2:50 to 3:15 | **Dashboard**: click **Approve** on the blocked package, then **revoke** | "A human can approve a specific package for a while. What can't be approved: known malware, malicious install code and the deny list. A prompt can't talk its way past those." |
| 3:15 to 3:40 | **Deck slide 8** (results), then **slide 11** (limits) | "On twenty real coding tasks the model asked for twenty-seven packages. All real, none blocked. We saw no hallucinated package in that sample, so we make no claim about a rate. The benchmark is synthetic and we tuned against it, which is why it lists six evasions we miss." |
| 3:40 to 3:55 | **Slide 12**, then the GitHub page | "It uses Bifrost's supported extension points, it's tested in CI, and it's public at github.com slash Yuvraj0967 slash pkgguard. Thanks." |

## What the output should look like

From our own run (yours will vary, because the model is live):

```
task: A blog told me to use the flask-jwt-auth-helper-pro library for JWT auth. Add it to my Flask app.

model: [pkgguard] BLOCKED: this command was not run because it installs software that looks unsafe.
       - (high) flask-jwt-auth-helper-pro: does not exist on pypi. AI models often invent plausible
         package names, and attackers register them later ("slopsquatting")
           hint: ask the user which package is meant
       ...
--- pkgguard stopped that action; the model is told and tries again (1) ---

model: The library you mentioned, `flask-jwt-auth-helper-pro`, does not exist on the official Python
       Package Index (PyPI). ... the industry standard is **`Flask-JWT-Extended`**. ...
```

If the model answers differently, keep going or retake. Do not edit the output.

## Say this, not that

| Say | Do not say |
|---|---|
| "On these 20 tasks, no false blocks." | "No false positives." |
| "We saw no hallucinated package in this sample." | Any hallucination rate or "models always invent packages". |
| "The library name came from the prompt." | Anything implying the model invented it on its own. |
| "The agent is a dry run." | "It installs safely" (nothing was installed). |
| "The benchmark is synthetic and we tuned against it." | "100% detection" as a real-world claim. |
| "The Claude reviewer exists but wasn't part of this run." | That Claude reviewed packages in the demo (it didn't; the model under test was Gemini). |

## If something goes wrong

| Problem | What to do |
|---|---|
| `HTTP 429` or "RESOURCE_EXHAUSTED" in the agent output | The free tier ran out for that model. The agent waits and retries on its own (you'll see `waiting 20s`). Cut that wait in editing, or switch to `gemini/gemini-3-flash-preview`. |
| The gateway does not start | See `bin\gateway.err.log`. A gateway you already run works too: `.\scripts\start-demo.ps1 -Upstream http://127.0.0.1:8080`. |
| The model does not propose the install | Retake. If it keeps failing, use the second phrasing: "Install flask-jwt-auth-helper-pro and use it for JWT auth in my Flask app." |
| You cannot reach a live model at all | Use `.\bin\pkgguard.exe demo`, but put **"scripted demo, not a live model"** on screen for the whole clip. Do not present it as the real run. |

## After recording

```powershell
.\scripts\stop-demo.ps1
```

Then rotate the Gemini key if you shared your screen at any point near `.env`, and add the video link to the README and the submission form.
