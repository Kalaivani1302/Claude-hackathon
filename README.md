# Team Kalaivani — IT Helpdesk Triage Agent

## Participants
- Kalaivani Karuppanan (Architect · Developer · PM · Tester)

## Scenario
**Scenario 5: Agentic Solution (Claude Agent SDK)** — IT Helpdesk Domain

> *200 IT support requests a day, triaged by hand. Every ticket costs 12 minutes of a human's time. Build the agent.*

---

## What We Built

A **production-grade, dual-agent IT Helpdesk Triage system** that automatically classifies, investigates, and routes incoming support tickets — with a live web UI, real-time streaming, and a built-in human override gate.

**Agent 1 — Triage Agent** is the primary orchestrator. It processes every ticket through a mandatory 7-tool sequence: injection detection → user profile lookup → active incident check → knowledge base search → (conditionally) security investigation → human approval gate → ITSM write. It cannot skip steps or hallucinate results — every decision is grounded in tool output.

**Agent 2 — SecurityInvestigator** is a purpose-built subagent spawned only when the Triage Agent classifies a ticket as `SECURITY`. It runs its own 3-tool investigation loop (sanctions check, failed login count, device compliance) and returns a structured threat assessment (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) that feeds back into the triage decision.

The system implements **all 5 Claude Primitives**: System Prompt Isolation (the agent identity cannot be overridden by ticket content), Tool Use as the anti-hallucination layer, Human-in-the-Loop with an async approval modal, Chain-of-Thought reasoning logged to the UI, and Zod/Pydantic structured output validation on every decision.

The frontend (`public/index.html`) is a zero-dependency single-page app that streams tool call events, renders a SecurityInvestigator sub-panel, shows an amber reasoning block, and pops a modal when human approval is needed. There is no build step.

---

## Challenges Attempted

| # | Challenge | Status | Notes |
|---|---|---|---|
| 1 | Core Triage Agent with 7 MCP tools | ✅ Done | Full mandatory tool sequence enforced via system prompt |
| 2 | SecurityInvestigator subagent | ✅ Done | Spawned on SECURITY category; threat level feeds parent decision |
| 3 | System Prompt Isolation + injection detection | ✅ Done | Regex pre-scan + model-level isolation; TKT-003 is the live demo |
| 4 | Human-in-the-Loop gate | ✅ Done | Async Promise/Map pattern; modal with Approve/Reject/Escalate |
| 5 | Chain-of-Thought logging | ✅ Done | REASONING: block rendered in amber panel before decision card |
| 6 | Structured Output (Zod + Pydantic) | ✅ Done | Both runtimes validate; queue enum enforced with field_validator |
| 7 | Real-time web UI (SSE streaming) | ✅ Done | Tool calls stream live with icons; no WebSocket needed |
| 8 | Dual runtime (TypeScript + Python) | ✅ Done | Both implementations, same agent logic and tool contracts |
| 9 | VIP handling and priority bumping | ✅ Done | CTO ticket gets +1 bump to P1 + forced NEEDS_HUMAN |
| 10 | Active incident correlation | ✅ Done | VPN incident links INC-2024-0847 to TKT-002 decision |

---

## Key Decisions

**1. Claude Agent SDK + direct Anthropic client (hybrid architecture)**
The Triage Agent uses the Claude Agent SDK with custom MCP tools via `createSdkMcpServer`. The SecurityInvestigator uses the raw `@anthropic-ai/sdk` client with a manual while loop — it is a lightweight subprocess that does not need file/web/terminal access, so the full Agent SDK would be unnecessary overhead. See [ADR-001](decisions/ADR-001-agent-sdk.md).

**2. Server-Sent Events over WebSocket**
The agent blocks mid-loop waiting for human approval. SSE is unidirectional, HTTP/1.1 compatible, and requires no upgrade negotiation. The approval signal travels back over a separate POST. This keeps the architecture simple enough to deploy anywhere. See [ADR-002](decisions/ADR-002-sse-streaming.md).

**3. pendingApprovals Map with Promise resolve pattern**
The human gate needed to pause the agent mid-execution until a browser click. Solution: store a resolve callback in a Map keyed by ticket_id. SSE sends human_approval_required. Browser POSTs to /api/approve. Server calls resolve. Agent continues. No polling, no database, no extra infra. See [ADR-003](decisions/ADR-003-hitl-pattern.md).

**4. Mandatory tool sequence in system prompt**
Rather than letting the model decide when to call tools, the system prompt specifies the exact numbered sequence. This makes behavior deterministic and auditable — a requirement for an IT security workflow where skipped steps create compliance gaps.

---

## How to Run It

**Prerequisites:** Node.js 20+, an Anthropic API key with available credits.

```bash
# 1. Clone and install
git clone https://github.com/Kalaivani1302/Claude-hackathon.git
cd Claude-hackathon
npm install

# 2. Set API key
export ANTHROPIC_API_KEY=sk-ant-api03-...   # Linux/Mac
set ANTHROPIC_API_KEY=sk-ant-api03-...      # Windows CMD

# 3. Start web server
npm start
# Server running at http://localhost:3002

# 4. Open browser to http://localhost:3002
#    Click "Run Triage Agent" on any demo ticket

# --- Alternative: CLI mode ---
node helpdesk_agent.mjs         # TypeScript agent, 4 demo tickets
pip install anthropic pydantic rich
python helpdesk_agent.py        # Python agent, same tickets
```

**Demo tickets and what to expect:**

| Ticket | Who | Expected outcome |
|---|---|---|
| TKT-001 | alice@acme.com | Password reset KB hit → AUTO_RESOLVE P3 |
| TKT-002 | bob.cto@acme.com (VIP) | VPN + active incident → NEEDS_HUMAN P1 + approval modal |
| TKT-003 | attacker@external.com | Prompt injection detected → NEEDS_HUMAN + Security-Response |
| TKT-004 | mallory@acme.com (contractor) | DB access → SecurityInvestigator → HIGH threat → NEEDS_HUMAN |

---

## Architecture

```
Browser (SSE)          Express :3002             Claude claude-opus-4-6
    |                      |                          |
    |-- POST /api/triage -->|                          |
    |                      |-- runTriageAgent() ------>|
    |<-- SSE stream --------|   |                      |
    |  tool_call events     |   Tool 1: detect_injection
    |  tool_result events   |   Tool 2: get_user_profile
    |  secinv sub-panel     |   Tool 3: check_active_incidents
    |  reasoning block      |   Tool 4: kb_search
    |  decision JSON        |   Tool 5: security_investigate --> SecurityInvestigator
    |                      |                                    (3-tool subagent loop)
    |  human_approval_req  |   Tool 6: request_human_approval
    |  [modal appears] <---|              | pauses here |
    |-- POST /api/approve ->|             | resolved    |
    |                      |   Tool 7: write_to_itsm
    |<-- complete ----------|<-- decision JSON ----------|
```

---

## If We Had Another Day

1. **Real ITSM integration** — swap mock write_to_itsm for ServiceNow REST API. The tool contract is already defined; it is a one-function swap.
2. **Persistent memory per user** — store ticket history so the agent can detect patterns ("3rd VPN ticket this month — escalate to infra review").
3. **Confidence-calibration evals** — run 100 synthetic tickets, measure precision/recall vs. human baseline. Current confidence scores are model-generated and need empirical validation.
4. **Request queue under load** — current server has no concurrency limit. Add p-queue with concurrency 5 before production.
5. **Auth on /api/approve** — the endpoint is unauthenticated. In production it needs a JWT tied to the approver identity for the audit trail.
6. **Word-by-word reasoning streaming** — currently reasoning arrives as one chunk. With stream: true on the Anthropic client it could render token by token.
7. **Test harness** — vitest with 20 deterministic ticket fixtures, mocked Anthropic client, assertions on decision shape and queue routing.

---

## How We Used Claude Code

**What worked brilliantly:**
- Architecture in one pass. Described the 5 primitives and 2-agent design in a single prompt; Claude designed the pendingApprovals Promise pattern and the SSE event taxonomy from scratch.
- Dual runtime. Asked Claude to implement the same agent in Python and TypeScript. It correctly chose pydantic and rich for Python and zod and ESM modules for TypeScript without being told.
- The human-in-the-loop pattern. The async Map<ticketId, resolve> trick for pausing an SSE stream mid-agent-loop was entirely Claude's suggestion. It works and it is elegant.
- Frontend without a framework. Single-file HTML with streaming SSE, modal, and event rendering in 400 lines. Zero build step.

**What surprised us:**
- Claude correctly identified that the SecurityInvestigator did not need the full Agent SDK and recommended the raw client + manual loop before we did.
- The injection detection regex list was generated in one shot and caught all four attack patterns without tuning.

**Where it saved the most time:**
- Express SSE server plus agent loop plus tool registry: roughly 2 hours of work completed in 15 minutes.
- Debugging ESM __dirname issues on Node 20 — Claude knew the fileURLToPath pattern immediately.
