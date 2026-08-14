namespace ContosoHR.Api.ContentSafety;

public sealed record ContentSafetyVerdict(bool IsSafe, string? Category = null, string? Reason = null)
{
    public static ContentSafetyVerdict Safe { get; } = new(true);
}

/// <summary>
/// R9: content safety on both input and output. Abstracted so the concrete
/// implementation can be Azure AI Content Safety in production and a local
/// heuristic stand-in in demo/dev — see AzureContentSafetyClassifier and
/// HeuristicContentSafetyClassifier's doc comments for the fail-open-vs-closed
/// decision.
/// </summary>
public interface IContentSafetyClassifier
{
    Task<ContentSafetyVerdict> ClassifyAsync(string content, CancellationToken cancellationToken = default);
}
