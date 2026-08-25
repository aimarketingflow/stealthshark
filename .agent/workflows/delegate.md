---
description: Agent delegation workflow - read spec, implement, write report
---

# Delegate Workflow

You are a **Delegate Agent (DA)**. You implement work defined by a spec, then report back.

## Prerequisites

- Read `.agent/config.json` to confirm the project name.
- Read `.agent/data/tasks.json` to find your assigned task (status: `delegated`).

## Steps

1. **Read the spec** — located at the path in the task's `spec` field (usually in `Documentation/handoff-specs/`).

2. **Read any rework notes** — if the task has `reworkCycles > 0`, check for a `🔧 Rework Fixes Required` section in the spec. Address ALL listed fixes.

3. **Implement the work** — follow the spec's requirements exactly. Respect all constraints listed under `⚠️ Critical Implementation Constraints`.

4. **Verify your work** — run any validation the spec requires (tests, linting, builds). Do not claim success without evidence.

5. **Write a completion report** — create `Documentation/handoff-specs/reports/<SPEC_ID>_REPORT.md`:
   - What was implemented
   - Files created/modified
   - Evidence of verification
   - Any open questions

6. **Update the spec queue** — in whatever queue file the project uses (e.g., `QUEUE.md`), change your spec's status from `delegated` to `implemented`.

7. **Write an exchange log** (if `tools/exchanges/` exists):
   ```markdown
   # Exchange: Spec <ID> <Title> — Round <N>
   
   ## OA → DA (Directive)
   - Bullet summary of what you were instructed to do
   
   ## DA → OA (Report)
   - Bullet summary of what you delivered
   - Key evidence (test results, etc.)
   
   ## Timestamps
   - Delegated: <time>
   - Implemented: <time>
   ```

8. **Update dashboard data** — modify these files in `.agent/data/`:

   **tasks.json** — find your task by `id`, set:
   - `status` → `"implemented"`
   - `updated` → today's date (`YYYY-MM-DD`)
   - append to `history`: `{"s":"implemented","d":"YYYY-MM-DD","a":"<your-agent-name>"}`

   **activity.json** — prepend (add to beginning of array):
   ```json
   {
     "title": "Spec <ID> implemented (r<N>)",
     "agent": "delegate-agent",
     "time": "<Mon DD, H:MMam/pm>",
     "color": "yellow",
     "specId": "<ID>",
     "details": "<1-line summary of what was delivered>"
   }
   ```

   **exchanges.json** — prepend:
   ```json
   {
     "specId": "<ID>",
     "round": <N>,
     "date": "<YYYY-MM-DD>",
     "verdict": "pending",
     "directive": ["bullet summaries of OA instructions"],
     "report": ["bullet summaries of what you delivered"],
     "reviewNotes": [],
     "delegated": "<time>",
     "implemented": "<time>",
     "reviewed": ""
   }
   ```

9. **Self-validate dashboard data** — After writing, verify your changes are correct:

   **Check tasks.json:**
   - Your task has `status: "implemented"`
   - Required fields present: `id`, `title`, `status`, `priority`
   - Status is one of: `draft`, `delegated`, `implemented`, `approved`, `needs-rework`
   - Priority is one of: `high`, `medium`, `low`
   - `history` array has your new entry

   **Check activity.json:**
   - New entry is FIRST in the array (prepended)
   - Required fields: `title`, `agent`, `time`, `color`
   - Color is one of: `green`, `blue`, `yellow`, `red`, `purple`

   **Check exchanges.json:**
   - New entry is FIRST (prepended) or existing entry updated
   - Required fields: `specId`, `round` (integer), `date`, `verdict`
   - Verdict is one of: `pending`, `approved`, `rework`

   If any check fails, fix it before finishing. The server will reject malformed data.

10. **Update session context** — Edit `.agent/context/state.md`:
    - Set "Last Session Summary" date, agent name, what was accomplished, what's next
    - Update "Active Work" if the project state changed meaningfully
    - Add any new key files or open questions discovered during this session

    This ensures the next agent (or a fresh session) can pick up immediately.

## Rules

- Do NOT modify files outside the spec's scope.
- Do NOT weaken security, delete tests, or remove constraints.
- If a requirement is unclear, implement the safest interpretation and note it in your report.
- Always verify before claiming completion.
