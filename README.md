# SecureAI.Dotnet — ContosoHR.Assistant

A reference ASP.NET Core application that demonstrates how to secure LLM features — prompt injection defenses, tool-call authorization, RAG access control, PII-safe telemetry, and cost limits — with each control backed by a passing attack test

## What this is

`ContosoHR.Assistant` is an internal HR Q&A assistant. It answers policy questions
from a document corpus (RAG) and can call tools (`GetMyPayslip`, `GetEmployeeRecord`,
`SubmitLeaveRequest`) on the employee's behalf — never on the LLM's say-so. See
[`docs/threat-model.md`](docs/threat-model.md) for why that distinction is the whole
point of this repo, and [`docs/plan.md`](docs/plan.md) for how each requirement
(R1–R10) maps to files in this tree.

Every vulnerable pattern the article discusses has a preserved, clearly-marked
counterpart in the code (e.g. `VulnerableChatOrchestrator` next to
`SecureChatOrchestrator`) — the vulnerable versions are never reachable from the
default DI graph (`AddContosoHrAssistant` / `AddContosoHrApi`), only from tests that
exercise them directly to prove the vulnerability and the fix.

## Repo layout

```
src/
  ContosoHR.Api/                 ASP.NET Core Minimal API host
  ContosoHR.Assistant/           Chat orchestration, tools, prompt assembly
  ContosoHR.Assistant.Security/  All guardrails, isolated and reusable
  ContosoHR.Data/                EF Core-free in-memory data access + RAG retrieval
tests/
  ContosoHR.Security.Tests/      xUnit — the attack suite (deterministic, fake IChatClient)
  ContosoHR.Integration.Tests/   WebApplicationFactory end-to-end tests
samples/attack-payloads/         Injection corpus + corpus.json (payload → expected outcome)
scripts/                         redteam.ps1 / redteam.sh — manual gate against a live instance
docs/                            Plan and threat model
article/                         The companion article
config/mock-oidc/                Simulated Entra ID users/clients/scopes for docker-compose
```

## Building and testing

```bash
dotnet build
dotnet test
```

## Running the demo

```bash
docker compose up --build
```

This starts Qdrant, a mock OIDC provider seeded with three users, and the API on
`http://localhost:5000`. By default `USE_FAKE_CHAT_CLIENT=true`, so no Azure OpenAI
resource or credentials are needed — `DemoChatClient` answers from the retrieved
policy documents with simple rule-based tool calling, enough to see every control
(guard pipeline, ACL-filtered retrieval, tool authorization, confirmation flow) run
for real.

> **Note on the mock OIDC container:** `docker compose up` and the full auth chain
> were written and reviewed carefully but not exercised end-to-end against a live
> Docker daemon in this repo's development session — getting the issuer claim
> consistent between the compose-internal (`mock-oidc:8080`) and host-exposed
> (`localhost:8080`) network paths is a known rough edge with OIDC test containers.
> If token validation fails locally, check that `ISSUER_URI` in `docker-compose.yml`
> matches whatever host/port you're actually using to reach the container. The
> reliably-verified proof that the auth-dependent code paths work is
> `ContosoHR.Integration.Tests` (`TestAuthHandler` exercises the same claims-based
> authorization logic without depending on a live OIDC container) — all 7 tests pass.

### The three seeded users

| Employee id | Name | Role | Notes |
|---|---|---|---|
| `alice` | Alice Nguyen | Employee | Reports to `carol`. Can only see her own payslip/record. |
| `carol` | Carol Jimenez | Manager | Can view her direct reports' records (not their salaries via chat, unless HR admin). |
| `dana` | Dana Okafor | HrAdmin | Can view any employee's record, including the Restricted compensation-bands document. |

Get a token for a user from the mock OIDC provider's token endpoint (resource-owner
password grant — test-only, never do this against a real IdP):

```bash
curl -s -X POST http://localhost:8080/connect/token \
  -d "client_id=contoso-hr-web" \
  -d "grant_type=password" \
  -d "username=alice" \
  -d "password=alice" \
  -d "scope=openid profile contoso-hr-assistant" \
  | jq -r .access_token
```

Then call the API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/connect/token -d "client_id=contoso-hr-web" -d "grant_type=password" -d "username=alice" -d "password=alice" -d "scope=openid profile contoso-hr-assistant" | jq -r .access_token)

curl -s -X POST http://localhost:5000/api/chat \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"message":"What is the PTO policy?"}'
```

### Manual red-team gate

```bash
export CONTOSO_HR_TOKEN=$TOKEN
./scripts/redteam.sh http://localhost:5000
# or: ./scripts/redteam.ps1 -BaseUrl http://localhost:5000
```

Replays `samples/attack-payloads/corpus.json` against the live instance and reports
PASS/FAIL/MANUAL-REVIEW per payload — see the script's header comment for why some
categories can't be judged by a single automated string check.

## Local secrets and Azure identity

No API keys are ever committed or read from configuration —
`SecretShapedConfigurationGuard` fails startup if one shows up anyway. Azure OpenAI
and Azure AI Content Safety authenticate via `DefaultAzureCredential` (Managed
Identity in Azure; your `az login` / IDE credentials locally).

For local dev against a real Azure OpenAI resource:

```bash
dotnet user-secrets init --project src/ContosoHR.Api
dotnet user-secrets set "AZURE_OPENAI_ENDPOINT" "https://your-resource.openai.azure.com/" --project src/ContosoHR.Api
```

Set `USE_FAKE_CHAT_CLIENT=false` to use it.

### RBAC for the Azure OpenAI resource

Whichever identity `DefaultAzureCredential` resolves to (a user-assigned managed
identity in Azure; your developer identity locally) should be granted only the
**Cognitive Services OpenAI User** role, scoped to the specific Azure OpenAI
resource — not Contributor, not Owner, and not a subscription-wide assignment. That
role permits chat/embedding calls and nothing else (no key management, no resource
configuration changes). Assign it with:

```bash
az role assignment create \
  --assignee <principal-id> \
  --role "Cognitive Services OpenAI User" \
  --scope /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.CognitiveServices/accounts/<resource-name>
```

### Data retention and residency

Azure OpenAI does not use prompts or completions submitted through the API to train
its models, and (outside of the optional, separately-enabled abuse-monitoring
retention) does not retain them beyond transient processing — see [Microsoft's Azure
OpenAI data, privacy, and security
documentation](https://learn.microsoft.com/en-us/legal/cognitive-services/openai/data-privacy)
for the current, authoritative statement and how to configure or request
modified/no abuse-monitoring retention for your resource. Choose your Azure OpenAI
resource's region to match your data-residency requirements — Azure OpenAI does not
move data outside the resource's configured region/geography.
