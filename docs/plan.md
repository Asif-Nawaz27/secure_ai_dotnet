# Plan — SecureAI.Dotnet: Securing AI Features Inside .NET Applications

This document is the persisted, approved plan for the `ContosoHR.Assistant` reference
solution and its companion article. It is written once at project start and updated
if scope changes; it is not a running log (see `git log` for that).

## Scenario

`ContosoHR.Assistant`: an internal HR assistant. Employees ask questions in natural
language. The assistant can:

1. Retrieve answers from an HR policy document corpus (RAG).
2. Call tools: `GetMyPayslip(month)`, `GetEmployeeRecord(employeeId)`,
   `SubmitLeaveRequest(startDate, endDate, type)`.
3. Return a formatted answer rendered in a web UI.

This is a **confused-deputy problem**: the LLM runs with the application's identity,
but must only ever act with the calling user's authority. Every control in this repo
exists to enforce that boundary.

## Confirmed parameters

| Parameter | Value |
|---|---|
| Target framework | `net9.0` (built with the installed .NET 10 SDK; net9.0 runtime present) |
| AI stack | Microsoft.Extensions.AI abstractions + Semantic Kernel orchestration |
| Model provider | Azure OpenAI via `IChatClient`, with a deterministic fake `IChatClient` for tests — no live network calls in CI |
| Vector store | Qdrant via Docker Compose, in-memory fallback for local/dev without Docker |
| Authentication | Simulated Entra ID / OIDC — a local mock OIDC provider issues tokens with claims shaped like real Entra ID (`oid`, `roles`, `groups`), so the auth code path matches production without needing a real tenant |
| Human confirmation flow | Synchronous — a write/irreversible tool call returns a `PendingAction` in the same chat turn; the client confirms via a follow-up call in the same session before execution |
| Repo name | `SecureAI.Dotnet` (this directory is the repo root) |
| Article length | 2,500–3,500 words, in `article/securing-ai-features-in-dotnet.md` |

## Repo layout

```
.
  .editorconfig
  .gitignore
  .env.example
  Directory.Build.props
  SecureAI.Dotnet.sln
  docker-compose.yml
  README.md
  docs/
    plan.md                 (this file)
    threat-model.md
  src/
    ContosoHR.Api/
    ContosoHR.Assistant/
    ContosoHR.Assistant.Security/
    ContosoHR.Data/
  tests/
    ContosoHR.Security.Tests/
    ContosoHR.Integration.Tests/
  samples/
    attack-payloads/
  scripts/
    redteam.ps1
    redteam.sh
  .github/workflows/ci.yml
  article/
    securing-ai-features-in-dotnet.md
```

## Component design

### `ContosoHR.Assistant.Security` (standalone, no HR-domain dependency)

The package a reader could lift into their own project. Contains only guardrails,
no HR types.

- `IPromptGuard` pipeline: `InputScreeningGuard` (risk score, not boolean — detects
  instruction-override phrasing, base64/unicode/homoglyph/zero-width encoding,
  imperative density), `IndirectInjectionGuard` (sanitizes retrieved chunks, tags
  provenance as `[source: x, untrusted]`), `SpotlightingGuard` (datamarking of
  untrusted spans), `OutputSchemaGuard` (JSON schema validation + bounded repair-
  prompt retry).
- `ToolAuthorizationPolicy` — resolves identity solely from the host-supplied
  `ClaimsPrincipal`; never trusts an LLM-supplied identity argument.
- `PendingActionStore` — the synchronous confirmation handshake for write/irreversible
  tools.
- `ToolCallBudget` — per-request tool-call cap and loop breaker.
- `RagAccessFilter` — the pre-filter contract handed to the vector store query, plus
  a post-retrieval re-verification check (defense in depth).
- `PiiRedactionProcessor` — OpenTelemetry processor scrubbing PII from prompt/
  completion telemetry, deny-by-default for prompt bodies in production.
- `SecurityEventLogger` — structured guard-decision events (user, risk score, layer,
  action) for SIEM ingestion.
- Every vulnerable variant (e.g. naive prompt concatenation, trust-the-LLM-supplied-
  employeeId) is preserved beside its fix, marked
  `// ⚠️ VULNERABLE — see docs/threat-model.md#T0x`, and is not reachable from the
  default `AddContosoAssistantSecurity()` DI registration — only test code references
  it directly.

### `ContosoHR.Assistant`

Chat orchestration (Semantic Kernel over `IChatClient`), the three tools, and prompt
assembly using **structural separation**: system instructions, retrieved context, and
user input are distinct, labeled message blocks — never concatenated into one string.

### `ContosoHR.Data`

EF Core, per-user/per-tenant scoped queries, document ACL metadata, and the Qdrant
client wrapper that implements the RAG pre-filter contract.

### `ContosoHR.Api`

Minimal API host: simulated OIDC auth, ASP.NET Core rate limiting partitioned by
user, token-budget middleware, `Microsoft.Extensions.Http.Resilience` pipeline,
output-boundary sanitization (markdown/HTML hardening + CSP).

### Tests

- `ContosoHR.Security.Tests` — the attack suite, driven by `samples/attack-payloads/`,
  against a deterministic fake `IChatClient` that replays recorded responses. No live
  network calls.
- `ContosoHR.Integration.Tests` — `WebApplicationFactory` end-to-end tests, including
  the three seeded users at different privilege levels.

## R1–R10 → file mapping

This table reflects where each requirement actually landed, updated at the end of
implementation (a few names changed from the original plan below as the design
solidified — noted where relevant).

| Req | What it is | Primary files |
|---|---|---|
| R1 | Trust boundaries and threat model | `docs/threat-model.md` |
| R2 | Prompt injection defense in depth | `src/ContosoHR.Assistant.Security/IPromptGuard.cs`, `src/ContosoHR.Assistant.Security/Guards/{InputScreeningGuard,IndirectInjectionGuard,SpotlightingGuard,OutputSchemaGuard}.cs` |
| R3 | Tool calling as an authorization boundary | `src/ContosoHR.Assistant/Tools/{SecureHrTools,HrToolAuthorization,HrToolCatalog,ToolArgumentValidators}.cs`, `src/ContosoHR.Assistant.Security/{ToolSideEffect,PendingAction,ToolCallBudget}.cs`, `src/ContosoHR.Assistant/SecureChatOrchestrator.cs` |
| R4 | RAG authorization and retrieval isolation | `src/ContosoHR.Data/AclFilteredDocumentSearch.cs` (named this, not `RagAccessFilter`), pre-filter + orchestrator re-check |
| R5 | Identity, secrets, and configuration | `src/ContosoHR.Api/Chat/AzureOpenAIChatClientFactory.cs`, `src/ContosoHR.Api/Configuration/SecretShapedConfigurationGuard.cs`, `.github/workflows/ci.yml` |
| R6 | Data leakage, logging, telemetry | `src/ContosoHR.Api/Observability/{AiTelemetry,PiiRedactionProcessor,TelemetryEnrichedSecurityEventLog}.cs` (moved to ContosoHR.Api, not Assistant.Security, since OpenTelemetry SDK wiring belongs at the host layer), `src/ContosoHR.Assistant.Security/SecurityEventLog.cs` |
| R7 | Abuse, cost, and availability | `src/ContosoHR.Api/Abuse/{ITokenBudgetStore,RequestLimits}.cs`, rate limiting + resilience handler registered inline in `Program.cs` (no separate `RateLimiting/` folder — small enough to stay in the composition root) |
| R8 | Output handling at the boundary | `src/ContosoHR.Api/Rendering/{IMarkdownRenderer,SanitizingMarkdownRenderer}.cs`, CSP middleware in `Program.cs` |
| R9 | Content safety | `src/ContosoHR.Api/ContentSafety/{IContentSafetyClassifier,AzureContentSafetyClassifier,HeuristicContentSafetyClassifier}.cs` |
| R10 | Testing | `tests/ContosoHR.Security.Tests/`, `tests/ContosoHR.Integration.Tests/`, `samples/attack-payloads/`, `scripts/redteam.{ps1,sh}` |

## Working method (as specified by the requester)

1. **This step** — plan + scaffold, stop for check-in.
2. Vulnerable baseline + failing attack tests, show the red suite.
3. Implement R1–R10 one at a time; after each, run the full attack suite and report
   which payloads newly pass.
4. Write the article last, extracting every snippet from the finished code.
5. Self-review: re-read the article against the repo, flag any unsupported claim.

## Definition of done

- [x] `dotnet build` clean with warnings as errors; `dotnet test` fully green
      (39/39 across both test projects as of the last full run).
- [x] Every payload in `samples/attack-payloads/` has a recorded expected outcome
      and an assertion — enforced mechanically by
      `AttackCorpusCompletenessTests.cs`.
- [x] Vulnerable variants exist, are marked, and are unreachable from the default DI
      graph — verified by reading `AddContosoHrAssistant`/`AddContosoHrApi`.
- [x] No secrets in git history; secret scan wired into CI (`.github/workflows/ci.yml`,
      Gitleaks) with `.gitleaks.toml` allowlisting the one known false positive (a
      synthetic test fixture). Gitleaks itself was not run locally in this session
      (not installed); a manual grep pass for secret-shaped patterns across tracked
      files found nothing beyond that fixture.
- [~] `docker compose up` → working demo, documented in `README.md` with three test
      users. Written and code-reviewed carefully, but **not exercised against a
      live Docker daemon** in this session — see README.md's note on the mock-oidc
      issuer-consistency rough edge. What IS verified live (in-process, via
      `WebApplicationFactory`): the real host, real middleware pipeline, and real
      endpoints, for all three seeded users, via `ContosoHR.Integration.Tests`.
- [x] Article compiles-by-copy: every code snippet's file path was re-checked
      against the actual file during self-review (see chat history); one stale
      test-method reference was found and fixed during that pass.
- [x] Every article claim traces to a passing test — test names cited in the
      article were grepped against the actual test files to confirm they exist.
- [x] Limitations section written and honest.
