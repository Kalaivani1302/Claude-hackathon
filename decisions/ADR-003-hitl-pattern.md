# ADR-003: Human-in-the-Loop via Promise/Map Pattern

**Status:** Accepted
**Date:** 2025-01-23

## Context

The Triage Agent must pause mid-execution and wait for a human to approve or reject a proposed action before continuing. The agent runs inside an async function that writes to an SSE stream. The human responds via a separate HTTP request.

## Problem

How do you pause an async agent loop that is in the middle of executing, emit an event to the browser, and then resume execution only after the browser sends a POST back?

## Decision

```javascript
const pendingApprovals = new Map();  // ticket_id → resolve function

// Inside executeTool("request_human_approval"):
return new Promise((resolve) => {
  emit("human_approval_required", input);      // SSE → browser shows modal
  pendingApprovals.set(input.ticket_id, resolve);
});

// Inside POST /api/approve handler:
const resolve = pendingApprovals.get(ticket_id);
pendingApprovals.delete(ticket_id);
resolve({ status: decision, timestamp: ... });  // unblocks the agent
```

## Rationale

- **Simplest correct solution.** No message queue, no pub/sub, no Redis, no WebSocket. Just JavaScript Promises and a Map.
- **Agent-transparent.** From the Triage Agent's perspective, `request_human_approval` is just another tool that returns a value. It doesn't know it's waiting for a human.
- **Idiomatic Node.js.** Using native Promise resolve as a callback is a well-understood pattern (same as `promisify`).
- **Safe for demo scale.** One approval pending per ticket_id. In production you'd add a timeout to prevent indefinite blocking.

## Consequences

- If the browser closes without approving, the agent hangs indefinitely. Production mitigation: `setTimeout(() => resolve({ status: 'timeout' }), 300_000)` with a 5-minute SLA.
- The Map is in-memory — server restart loses pending approvals. For production, persist to Redis with TTL.
- Cannot handle concurrent tickets with the same ticket_id — by design, ticket IDs are unique (TKT-001 through TKT-004 in demo).
