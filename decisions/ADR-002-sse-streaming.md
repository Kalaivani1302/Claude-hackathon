# ADR-002: Server-Sent Events for Real-Time Agent Streaming

**Status:** Accepted
**Date:** 2025-01-23

## Context

The Triage Agent runs a potentially multi-turn loop that can take 10–60 seconds. The UI needs to show progress in real time: which tool is being called, what the result was, when the SecurityInvestigator starts, what the final decision is.

Candidates:
- **WebSocket** — bidirectional, requires upgrade handshake, stateful connection management
- **SSE (Server-Sent Events)** — unidirectional server→client, plain HTTP, built into all browsers
- **Long polling** — inefficient for high-frequency events
- **Streaming HTTP response** — what SSE is, essentially, with a standard format

## Decision

Use SSE via a single `POST /api/triage` endpoint that holds the connection open and writes `data: {...}\n\n` frames as the agent progresses.

Human approval travels back via a separate `POST /api/approve` — a normal JSON request, not a second SSE stream.

## Rationale

- The communication is asymmetric: server pushes many events, client sends one (the approval). SSE maps to this naturally.
- SSE is HTTP/1.1 and works through every proxy, load balancer, and CDN without configuration.
- Express 5 handles chunked transfer encoding automatically — no extra library.
- Browser `fetch()` + `ReadableStream` reader works without `EventSource` API, allowing `POST` body (ticket data) instead of query params.

## Consequences

- SSE connections time out at 2 minutes on some proxies — acceptable for demo; production needs heartbeat pings (`:\n\n` frames).
- One SSE connection per triage request — correct for this use case; a production system with concurrent tickets would need a session ID multiplexing scheme.
- The approval `POST` and the SSE stream are decoupled via the `pendingApprovals` Map — this is the key design insight documented in ADR-003.
