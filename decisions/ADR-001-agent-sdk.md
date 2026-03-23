# ADR-001: Hybrid Agent Architecture — Agent SDK + Direct Anthropic Client

**Status:** Accepted
**Date:** 2025-01-23

## Context

Scenario 5 requires the Claude Agent SDK. We have two logical agents:
1. **Triage Agent** — orchestrates the full workflow, needs 7 custom tools, runs in a loop
2. **SecurityInvestigator** — a focused subprocess, needs 3 investigation tools, runs once per SECURITY ticket

## Decision

- **Triage Agent** uses `@anthropic-ai/claude-agent-sdk` with `createSdkMcpServer` + `tool()` helpers. This gives us the full SDK lifecycle, permission model, and MCP integration for the main orchestrator.
- **SecurityInvestigator** uses the raw `@anthropic-ai/sdk` Anthropic client with a manual `while (true)` agentic loop.

## Rationale

The SecurityInvestigator does not need file access, web access, shell access, or MCP servers. It only needs to call 3 deterministic mock tools and return a JSON blob. Using the full Agent SDK for it would add:
- Subprocess spawning overhead
- Permission prompt surface area
- Complexity in passing the `emit` callback for SSE streaming

The raw client is 20 lines vs 80+ lines for the SDK equivalent, with no loss of capability for this use case.

## Consequences

- Two different import patterns in the same file (`claude-agent-sdk` + `@anthropic-ai/sdk`) — documented in CLAUDE.md
- SecurityInvestigator cannot be given Agent-SDK-managed tools without refactoring
- This hybrid approach correctly models real production systems: orchestrators use heavy SDKs; leaf agents use minimal clients
