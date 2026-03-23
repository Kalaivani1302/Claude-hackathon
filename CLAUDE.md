# CLAUDE.md — IT Helpdesk Triage Agent

## Project Identity
Production-grade **IT Helpdesk Triage Agent** built for the Claude Hackathon (Scenario 5).
Two agents, two runtimes, one web UI. All 5 Claude Primitives implemented.

---

## Tech Stack
| Layer | Choice |
|---|---|
| Agent SDK | `@anthropic-ai/claude-agent-sdk` v0.2.81 (TypeScript ESM) |
| Direct API | `@anthropic-ai/sdk` v0.80.0 (SecurityInvestigator subagent) |
| Validation | `zod` v4 (TypeScript), `pydantic` v2 (Python) |
| Web server | `express` v5 (ESM, Node 20+) |
| Streaming | Server-Sent Events (SSE) — no WebSocket needed |
| Frontend | Vanilla HTML/CSS/JS — zero build step |
| Python | `anthropic` SDK with manual agentic loop + `rich` console |

---

## Repository Layout
```
/
├── server.mjs              ← Express web server (primary entrypoint)
├── helpdesk_agent.mjs      ← Standalone CLI agent (TypeScript ESM)
├── helpdesk_agent.py       ← Standalone CLI agent (Python)
├── public/
│   └── index.html          ← Single-page frontend UI
├── decisions/              ← Architecture Decision Records (ADRs)
│   ├── ADR-001-agent-sdk.md
│   ├── ADR-002-sse-streaming.md
│   ├── ADR-003-dual-runtime.md
│   └── ADR-004-five-primitives.md
├── CLAUDE.md               ← This file
├── README.md               ← Project overview + submission
└── presentation.html       ← 5-minute hackathon deck
```

---

## How to Run
```bash
# Web UI (recommended)
export ANTHROPIC_API_KEY=sk-ant-...
npm start
# → http://localhost:3002

# CLI — TypeScript agent
node helpdesk_agent.mjs

# CLI — Python agent
pip install anthropic pydantic rich
python helpdesk_agent.py
```

---

## The Five Claude Primitives (DON'T REMOVE OR BREAK THESE)

### 1. System Prompt Isolation
- File: `server.mjs` — `TRIAGE_SYSTEM_PROMPT` constant
- Rule: The system prompt defines agent identity. Ticket bodies CANNOT override it.
- Test: TKT-003 sends a jailbreak prompt. The agent must detect it, not obey it.

### 2. Tool Use (Anti-Hallucination)
- Tools: `detect_injection`, `get_user_profile`, `check_active_incidents`, `kb_search`, `security_investigate`, `request_human_approval`, `write_to_itsm`
- Rule: Agent MUST call all applicable tools in sequence before deciding. No hallucinated user profiles.
- MANDATORY sequence is enforced in the system prompt.

### 3. Human-in-the-Loop
- Pattern: `pendingApprovals` Map — agent pauses at `request_human_approval`, SSE emits `human_approval_required` event, browser shows modal, user clicks, `/api/approve` POST resolves the Promise.
- Rule: VIP tickets, SECURITY tickets, and injection-detected tickets ALWAYS require human approval.

### 4. Chain-of-Thought Logging
- Rule: Agent outputs a `REASONING:` block before the JSON decision.
- Frontend renders this in the amber reasoning panel.
- Never strip or summarize the reasoning in backend processing.

### 5. Structured Output (Zod / Pydantic)
- Schema: `TriageDecisionSchema` in `helpdesk_agent.mjs`, `TriageDecision` Pydantic model in `helpdesk_agent.py`
- Required fields: `ticket_id`, `priority`, `category`, `decision`, `queue`, `confidence`, and others.
- Validation happens after JSON parse — invalid decisions are rejected, not silently accepted.

---

## Code Conventions

### TypeScript / Node
- ESM only (`"type": "module"` in package.json). No `require()`.
- `__dirname` via `path.dirname(fileURLToPath(import.meta.url))`.
- All tool implementations in `TRIAGE_REGISTRY` / `executeTool()` — one function, switch on name.
- SSE emit pattern: `res.write(\`data: ${JSON.stringify({ type, data })}\n\n\`)`.
- Never `res.json()` on an SSE stream — it closes the connection.

### Python
- `anthropic.Anthropic()` — sync client, manual `while True` agentic loop.
- Check `stop_reason == "tool_use"` to continue; `stop_reason == "end_turn"` to break.
- Tool registry: `TRIAGE_REGISTRY` dict maps tool name → callable.
- Pydantic `model_validate()` after JSON parse. `field_validator` for queue enum check.
- `rich.console.Console()` for colored output — never plain `print()` in CLI mode.

### HTML/CSS/JS frontend
- No frameworks, no bundler. Single file in `public/index.html`.
- Use `fetch('/api/triage', { method: 'POST', ... })` with `ReadableStream` reader for SSE.
- SSE parse: split by `\n`, filter lines starting with `data: `, `JSON.parse(line.slice(6))`.
- All dynamic HTML uses `escHtml()` helper — never `innerHTML = userContent` without escaping.

---

## Naming Conventions
- Agent 1: **Triage Agent** (main, runs in Agent SDK loop)
- Agent 2: **SecurityInvestigator** (subagent, spawned only for SECURITY category)
- Tool names: `snake_case`
- Event types (SSE): `snake_case` — `tool_call`, `tool_result`, `secinv_start`, `secinv_done`, `human_approval_required`, `decision`, `complete`, `error`
- Priority levels: `P1` (prod down) → `P4` (question)
- Decision values: `AUTO_RESOLVE` | `NEEDS_HUMAN` | `ROUTE_TO_QUEUE`

---

## Mock Data Contracts (don't change shapes without updating tool schemas)
- `MOCK_USERS`: `{ name, role, dept, is_vip, open_tickets }`
- `MOCK_INCIDENTS`: `{ active, incident_id, title, severity, workaround }`
- `MOCK_KB`: `{ found, solution, auto_resolvable, steps[] }`
- Security mocks: `MOCK_SANCTIONS` (bool), `MOCK_FAILED_LOGINS` (count), `MOCK_DEVICE_COMPLIANCE` (`{ compliant, last_scan, issues[] }`)

---

## What NOT to Do
- Don't add `require()` — ESM only.
- Don't change the VALID_QUEUES list without updating Zod/Pydantic schemas.
- Don't skip calling `write_to_itsm` — it's the audit trail.
- Don't return raw errors from tools — always return `{ error: "message" }` shape.
- Don't change the SSE `data:` prefix format — the frontend parser depends on it.
- Don't store actual API keys in any file — always `process.env.ANTHROPIC_API_KEY`.

---

## Testing the 5 Demo Tickets
| Ticket | Email | Expected Decision | Primitive Exercised |
|---|---|---|---|
| TKT-001 | alice@acme.com | AUTO_RESOLVE P3 | Tool Use + KB Search |
| TKT-002 | bob.cto@acme.com | NEEDS_HUMAN P1 | VIP + HITL + Incident |
| TKT-003 | attacker@external.com | NEEDS_HUMAN (injection) | System Prompt Isolation |
| TKT-004 | mallory@acme.com | NEEDS_HUMAN (threat HIGH+) | SecurityInvestigator |

---

## Environment Variables
| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key |
| `PORT` | No | Server port (default: 3002) |
