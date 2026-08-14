using System.Security.Claims;

namespace ContosoHR.Data;

/// <summary>
/// Fixed pair for NaiveKeywordDocumentSearch — see docs/threat-model.md#T05.
///
/// The ACL predicate is applied as a PRE-filter: documents outside the caller's role
/// are excluded from the candidate set before scoring/ranking ever happens. This
/// matters because a post-filter (score everything, then throw away what the caller
/// can't see) still leaks information through side channels the caller CAN observe —
/// fewer results than expected, a different top-ranked result, timing differences
/// from ranking a larger candidate set, or (in a real vector store) similarity
/// scores that are only high because a restricted document was the closest match.
/// None of that happens here: excluded documents never enter the ranking at all, so
/// there is nothing about them for the caller to observe, directly or indirectly.
///
/// In production this same pre-filter would be pushed into the vector store's query
/// itself (e.g. Qdrant's payload-based filtering) rather than filtering an
/// in-memory list — the principle is identical either way: the filter runs as part
/// of retrieval, not after it.
/// </summary>
public sealed class AclFilteredDocumentSearch(IReadOnlyList<PolicyDocument> corpus) : IPolicyDocumentSearch
{
    public AclFilteredDocumentSearch() : this(SeedData.Documents)
    {
    }

    public IReadOnlyList<PolicyDocument> Search(string query, ClaimsPrincipal caller, int maxResults = 3)
    {
        var callerRole = caller.ResolveEmployeeRole();
        var permitted = corpus.Where(doc => doc.AllowedRoles.Contains(callerRole));

        var queryTerms = Tokenize(query);
        if (queryTerms.Count == 0)
        {
            return [];
        }

        return permitted
            .Select(doc => (Document: doc, Score: ScoreOverlap(queryTerms, Tokenize(doc.Content))))
            .Where(match => match.Score > 0)
            .OrderByDescending(match => match.Score)
            .Take(maxResults)
            .Select(match => match.Document)
            .ToList();
    }

    private static int ScoreOverlap(HashSet<string> queryTerms, HashSet<string> documentTerms) =>
        queryTerms.Count(documentTerms.Contains);

    private static HashSet<string> Tokenize(string text) =>
        text
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(word => word.Trim('.', ',', '?', '!', ':', ';', '"', '\'', '(', ')', '#', '|', '-').ToLowerInvariant())
            .Where(word => word.Length > 2)
            .ToHashSet();
}
