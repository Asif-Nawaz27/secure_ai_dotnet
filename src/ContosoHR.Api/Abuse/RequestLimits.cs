namespace ContosoHR.Api.Abuse;

/// <summary>
/// R7: input length and conversation-history caps, checked before anything is sent
/// to the model. Without these, an attacker (or a buggy client) can exhaust the
/// context window — or the token budget — with a single oversized request.
/// </summary>
public static class RequestLimits
{
    public const int MaxUserMessageLength = 4_000;

    public const int MaxHistoryTurns = 20;

    public const int EstimatedCharsPerToken = 4;

    public static int EstimateTokens(string userMessage, int historyTurnCount) =>
        (userMessage.Length / EstimatedCharsPerToken) + (historyTurnCount * 50) + 500;
}
