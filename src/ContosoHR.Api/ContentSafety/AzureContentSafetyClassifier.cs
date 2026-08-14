using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Azure.Core;

namespace ContosoHR.Api.ContentSafety;

/// <summary>
/// Calls Azure AI Content Safety's text moderation endpoint, authenticated with
/// <see cref="TokenCredential"/> (DefaultAzureCredential in production — R5, no
/// API keys) rather than the SDK's key-based option.
///
/// Fail-CLOSED on any error (network failure, timeout, non-success response): if
/// this call can't complete, ClassifyAsync returns IsSafe = false. This is a
/// deliberate choice, not an oversight — see the class-level tradeoff:
///
///   - The cost of a FALSE BLOCK (content-safety is down, a benign request gets
///     refused) is a support ticket and a frustrated employee.
///   - The cost of a FALSE ALLOW (content-safety is down, something harmful gets
///     through unchecked) is, for an assistant with access to compensation and
///     personal HR data, a compliance incident.
///
/// Given what this assistant can access, reduced availability is the acceptable
/// tradeoff. An application with a lower sensitivity bar might reasonably choose
/// the opposite default — that's exactly why this is a documented decision and not
/// a hardcoded assumption baked into the interface.
/// </summary>
public sealed class AzureContentSafetyClassifier(HttpClient httpClient, TokenCredential credential, string endpoint) : IContentSafetyClassifier
{
    private const string Scope = "https://cognitiveservices.azure.com/.default";
    private const int SeverityBlockThreshold = 4; // Azure Content Safety severities are 0,2,4,6.

    public async Task<ContentSafetyVerdict> ClassifyAsync(string content, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await credential.GetTokenAsync(new TokenRequestContext([Scope]), cancellationToken);

            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                $"{endpoint.TrimEnd('/')}/contentsafety/text:analyze?api-version=2024-09-01")
            {
                Content = JsonContent.Create(new AnalyzeRequest(content, ["Hate", "SelfHarm", "Sexual", "Violence"]))
            };
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.Token);

            using var response = await httpClient.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new ContentSafetyVerdict(false, "ServiceError", $"content safety call failed with status {(int)response.StatusCode}");
            }

            var result = await response.Content.ReadFromJsonAsync<AnalyzeResponse>(cancellationToken);
            var worst = result?.CategoriesAnalysis?.MaxBy(c => c.Severity);
            if (worst is not null && worst.Severity >= SeverityBlockThreshold)
            {
                return new ContentSafetyVerdict(false, worst.Category, $"severity {worst.Severity}");
            }

            return ContentSafetyVerdict.Safe;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new ContentSafetyVerdict(false, "ServiceUnavailable", "content safety call did not complete: " + ex.Message);
        }
    }

    private sealed record AnalyzeRequest(
        [property: JsonPropertyName("text")] string Text,
        [property: JsonPropertyName("categories")] string[] Categories);

    private sealed record AnalyzeResponse(
        [property: JsonPropertyName("categoriesAnalysis")] List<CategoryAnalysis>? CategoriesAnalysis);

    private sealed record CategoryAnalysis(
        [property: JsonPropertyName("category")] string Category,
        [property: JsonPropertyName("severity")] int Severity);
}
