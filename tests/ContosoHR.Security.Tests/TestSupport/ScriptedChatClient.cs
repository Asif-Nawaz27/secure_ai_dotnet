using Microsoft.Extensions.AI;

namespace ContosoHR.Security.Tests.TestSupport;

/// <summary>
/// A deterministic <see cref="IChatClient"/> fake that replays scripted responses.
/// No network calls, no real model — required by R10 so the attack suite runs the
/// same way in CI every time. Each responder receives a snapshot of the messages
/// sent for that turn, so a test can assert on prompt structure (e.g. "is the
/// injected document content sitting inside the system message?") and/or simulate
/// what a susceptible model would do with that input.
/// </summary>
public sealed class ScriptedChatClient(params Func<IReadOnlyList<ChatMessage>, ChatResponse>[] responders) : IChatClient
{
    private readonly Queue<Func<IReadOnlyList<ChatMessage>, ChatResponse>> _responders = new(responders);

    /// <summary>Every request this client received, in order, one entry per call.</summary>
    public List<IReadOnlyList<ChatMessage>> CapturedRequests { get; } = [];

    public static ScriptedChatClient WithResponses(params ChatResponse[] responses) =>
        new([.. responses.Select(response => (Func<IReadOnlyList<ChatMessage>, ChatResponse>)(_ => response))]);

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var snapshot = messages.ToList();
        CapturedRequests.Add(snapshot);

        if (_responders.Count == 0)
        {
            throw new InvalidOperationException(
                $"ScriptedChatClient ran out of scripted responses after {CapturedRequests.Count} request(s).");
        }

        var responder = _responders.Dequeue();
        return Task.FromResult(responder(snapshot));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("ScriptedChatClient does not support streaming.");

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public void Dispose()
    {
    }
}
