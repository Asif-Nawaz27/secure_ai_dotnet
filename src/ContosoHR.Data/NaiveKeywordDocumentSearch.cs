using System.Security.Claims;

namespace ContosoHR.Data;

// ⚠️ VULNERABLE — see docs/threat-model.md#T05.
//
// This retrieval implementation ranks every document in the corpus by keyword
// overlap and returns the top matches, completely ignoring `PolicyDocument
// .Classification` and `.AllowedRoles`. A low-privilege employee's query can match
// a Restricted document just as easily as a Public one — nothing here stops that
// document's content from being handed to the model and, from there, to the user.
//
// This is deliberately preserved as the baseline "before" state. The fixed
// counterpart (R4) applies the ACL as a pre-filter in the retrieval query itself —
// not as a check bolted on afterward — and is what production wiring uses instead.
// Never register this type in the default DI graph.
public sealed class NaiveKeywordDocumentSearch(IReadOnlyList<PolicyDocument> corpus) : IPolicyDocumentSearch
{
    public NaiveKeywordDocumentSearch() : this(SeedData.Documents)
    {
    }

    public IReadOnlyList<PolicyDocument> Search(string query, ClaimsPrincipal caller, int maxResults = 3)
    {
        var queryTerms = Tokenize(query);
        if (queryTerms.Count == 0)
        {
            return [];
        }

        return corpus
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
