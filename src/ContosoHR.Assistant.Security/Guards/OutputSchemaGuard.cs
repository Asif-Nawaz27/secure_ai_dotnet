using System.Text.Json;
using System.Text.Json.Serialization;

namespace ContosoHR.Assistant.Security.Guards;

public sealed record FinalAnswerPayload(
    [property: JsonPropertyName("answer")] string Answer,
    [property: JsonPropertyName("citedSources")] string[] CitedSources);

/// <summary>
/// R2 layer 5: never trust the model's response shape. Validates a model response
/// against <see cref="FinalAnswerPayload"/>'s schema and, on failure, generates a
/// repair prompt describing exactly what was wrong so the caller can retry with a
/// tighter instruction. <see cref="ValidateWithRetryAsync"/> demonstrates the full
/// validate → repair-prompt → bounded-retry → safe-fallback loop end to end.
///
/// This reference app's main conversational answer is deliberately plain text, not
/// JSON — forcing structured output onto a natural-language HR chat response would
/// fight the UX for no security benefit. This guard is wired up wherever the app
/// genuinely needs structured, machine-checked output (see its unit tests for a
/// worked example); it is not layered onto every chat turn. See the article's
/// limitations section for the reasoning.
/// </summary>
public sealed class OutputSchemaGuard
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public bool TryValidate(string rawResponse, out FinalAnswerPayload? payload, out string? error)
    {
        try
        {
            payload = JsonSerializer.Deserialize<FinalAnswerPayload>(rawResponse, JsonOptions);
            if (payload is null || string.IsNullOrWhiteSpace(payload.Answer))
            {
                error = "Missing or empty required field 'answer'.";
                payload = null;
                return false;
            }

            error = null;
            return true;
        }
        catch (JsonException ex)
        {
            payload = null;
            error = $"Response was not valid JSON matching the expected schema: {ex.Message}";
            return false;
        }
    }

    private const string SchemaDescription = """{ "answer": string, "citedSources": string[] }""";

    public string BuildRepairPrompt(string invalidResponse, string validationError) =>
        $"""
        Your previous response did not match the required JSON schema
        {SchemaDescription}.

        Validation error: {validationError}

        Your previous response was:
        {invalidResponse}

        Reply again with ONLY a JSON object matching the schema above. No prose
        outside the JSON object.
        """;

    /// <summary>
    /// Calls <paramref name="getModelResponse"/> up to <paramref name="maxAttempts"/>
    /// times, feeding a repair prompt back in on each failed validation. Returns
    /// null if every attempt failed, so the caller can fall back safely rather than
    /// propagating a malformed response.
    /// </summary>
    public async Task<FinalAnswerPayload?> ValidateWithRetryAsync(
        Func<string?, Task<string>> getModelResponse,
        int maxAttempts = 3)
    {
        string? repairPrompt = null;

        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            var response = await getModelResponse(repairPrompt);
            if (TryValidate(response, out var payload, out var error))
            {
                return payload;
            }

            repairPrompt = BuildRepairPrompt(response, error!);
        }

        return null;
    }
}
