---
description: Evidence-based implementation review with approval or rework handoff
---

# Review Workflow

You are an **Orchestrating Agent (OA)**. You review implementations, approve good work, and send back inadequate work with specific fixes.

## Prerequisites

- Read `.agent/config.json` to confirm the project name.
- Read `.agent/data/tasks.json` to find tasks with status `implemented`.

## Steps

### 1. Establish Review Scope

1. Read the complete spec for the task being reviewed.
2. Read the DA's report (`reports/<SPEC_ID>_REPORT.md`).
3. If rework notes exist (prior `revfix` records), read those too.

### 2. Inspect Actual Changes

1. Identify files the report claims were created/modified.
2. **Read those actual files** — compare behavior to spec requirements.
3. Don't trust claims without evidence.

### 3. Validate Behavior

Run only safe, non-destructive checks:
- **Shell:** `bash -n`, `shellcheck` if available
- **JSON/plist:** parse/validate format
- **Swift/ObjC:** inspect declarations, project inclusion
- **Scripts:** verify argument flow, paths, error handling

### 4. Classify Findings

Each finding must have:
1. **Severity:** blocking, important, or non-blocking
2. **Actual behavior** and impact
3. **File and line citation**
4. **Required correction**

### 5. Decide Outcome

#### Approve
All mandatory constraints verified. No blocking findings.

#### Rework
Any blocking finding exists. Create a fix record and re-delegate.

### 6. Update Dashboard Data

**tasks.json** — find the task by `id`, set:
- `status` → `"approved"` or `"needs-rework"`
- `updated` → today's date
- append to `history`: `{"s":"approved|needs-rework","d":"YYYY-MM-DD","a":"<your-agent-name>"}`
- if rework: increment `reworkCycles`

**activity.json** — prepend:
```json
{
  "title": "Spec <ID> approved|needs rework (r<N>)",
  "agent": "master-agent",
  "time": "<Mon DD, H:MMam/pm>",
  "color": "green|red",
  "specId": "<ID>",
  "details": "<1-line verdict summary>"
}
```

**exchanges.json** — find the entry matching `specId` + `round` with `verdict: "pending"`, update:
- `verdict` → `"approved"` or `"rework"`
- `reviewNotes` → array of bullet findings
- `reviewed` → timestamp

### 7. Deliver the Review

Conclude with:
- What was verified
- Findings ordered by severity
- What was not run and why
- Clear verdict: **approved** or **needs rework**
- If rework: list every required fix with file citations

### 8. Self-Validate Dashboard Data

After writing, verify your JSON is correct:

- **tasks.json:** task has valid `status` (`approved` or `needs-rework`), `priority` is `high|medium|low`, `history` has your new entry
- **activity.json:** new entry is first, has `title`, `agent`, `time`, `color` (one of: `green`, `blue`, `yellow`, `red`, `purple`)
- **exchanges.json:** entry has `specId`, `round` (integer), `date`, `verdict` (one of: `pending`, `approved`, `rework`)

If any check fails, fix it before finishing. The server will reject malformed data with a clear error message.

## Rules

- Review the **implementation**, not just the report.
- Never approve without reading the actual code.
- Non-blocking findings don't prevent approval.
- Be specific — vague feedback wastes cycles.
