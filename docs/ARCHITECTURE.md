# Architecture Guide

See the [README](../README.md) for the full system architecture overview.

## Component Flow
```
Evaluation Platform → Honeypot API → Scam Detection → AI Agent → Intelligence Extraction → Callback
```

## Key Files

- `supabase/functions/honeypot-detect/index.ts` — Main API handler, scam detection, intelligence extraction, AI agent, callback logic
- `supabase/functions/_shared/detectProbe.ts` — Probe pattern detection utilities
- `supabase/functions/_shared/sanitizeAIResponse.ts` — AI response sanitization to prevent data leakage
- `supabase/migrations/001_initial_schema.sql` — Database schema for sessions, messages, and extracted intelligence
