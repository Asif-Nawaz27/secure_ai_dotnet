using System.Security.Claims;

namespace ContosoHR.Data;

/// <summary>
/// Retrieval contract for the RAG corpus. <paramref name="caller"/> exists on this
/// interface from day one specifically so that an authorization-aware implementation
/// (docs/threat-model.md#T05) is a drop-in replacement — see
/// docs/plan.md's R4 mapping. The naive implementation in this assembly ignores it.
/// </summary>
public interface IPolicyDocumentSearch
{
    IReadOnlyList<PolicyDocument> Search(string query, ClaimsPrincipal caller, int maxResults = 3);
}
