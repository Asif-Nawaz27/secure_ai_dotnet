namespace ContosoHR.Api.ContentSafety;

/// <summary>
/// A local, keyword-based stand-in for Azure AI Content Safety — used only when no
/// CONTENT_SAFETY_ENDPOINT is configured (local/demo runs). This is NOT a substitute
/// for a real content-safety model and must never be used in production; it exists
/// so `docker compose up` works without an Azure resource.
///
/// Fail-open by design: if this classifier itself throws, it returns Safe rather
/// than blocking. Since it provides no real protection to begin with, failing
/// closed here would only add friction to a demo without adding any actual safety
/// margin — the opposite tradeoff from AzureContentSafetyClassifier, which fails
/// closed because it IS the real control.
/// </summary>
public sealed class HeuristicContentSafetyClassifier : IContentSafetyClassifier
{
    private static readonly string[] FlaggedTerms =
        ["kill myself", "suicide", "bomb-making", "how to hurt"];

    public Task<ContentSafetyVerdict> ClassifyAsync(string content, CancellationToken cancellationToken = default)
    {
        try
        {
            var lower = content.ToLowerInvariant();
            var hit = FlaggedTerms.FirstOrDefault(lower.Contains);
            return Task.FromResult(hit is null
                ? ContentSafetyVerdict.Safe
                : new ContentSafetyVerdict(false, "SelfHarmOrViolence", $"heuristic match: '{hit}'"));
        }
        catch
        {
            return Task.FromResult(ContentSafetyVerdict.Safe);
        }
    }
}
