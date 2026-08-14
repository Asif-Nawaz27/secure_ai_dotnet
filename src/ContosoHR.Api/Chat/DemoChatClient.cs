using Microsoft.Extensions.AI;

namespace ContosoHR.Api.Chat;

/// <summary>
/// A small rule-based stand-in for a real model, used by default in local/demo runs
/// (<c>USE_FAKE_CHAT_CLIENT=true</c> in .env.example) so <c>docker compose up</c>
/// produces a working demo without an Azure OpenAI resource or credentials. This is
/// NOT the deterministic test double used by the attack suite — see
/// ContosoHR.Security.Tests/TestSupport/ScriptedChatClient.cs for that; this class
/// exists purely so a human can `curl` the running API and get a plausible answer.
/// </summary>
public sealed class DemoChatClient : IChatClient
{
    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageList = messages.ToList();

        var priorToolResult = messageList
            .LastOrDefault(m => m.Role == ChatRole.Tool)?
            .Contents.OfType<FunctionResultContent>()
            .FirstOrDefault();

        if (priorToolResult is not null)
        {
            return Task.FromResult(new ChatResponse(new ChatMessage(
                ChatRole.Assistant,
                $"Here's what I found: {priorToolResult.Result}")));
        }

        var userContent = messageList.LastOrDefault(m => m.Role == ChatRole.User)?.Text ?? string.Empty;

        // Intent-match only the employee's actual question, not the retrieved
        // reference material sharing the same user-role message — otherwise a
        // question about expenses could false-trigger the leave-request intent
        // just because the retrieved handbook text happens to mention "leave".
        var question = ExtractQuestion(userContent);
        var lower = question.ToLowerInvariant();

        if (options?.Tools is { Count: > 0 } tools)
        {
            if (lower.Contains("payslip") || lower.Contains("pay stub"))
            {
                var tool = tools.FirstOrDefault(t => t.Name == "GetMyPayslip");
                if (tool is not null)
                {
                    var month = DateTime.UtcNow.ToString("yyyy-MM");
                    return Task.FromResult(ToolCallResponse(tool.Name, new Dictionary<string, object?> { ["month"] = month }));
                }
            }

            if ((lower.Contains("submit") || lower.Contains("request")) && lower.Contains("leave"))
            {
                var tool = tools.FirstOrDefault(t => t.Name == "SubmitLeaveRequest");
                if (tool is not null)
                {
                    var start = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(14));
                    var end = start.AddDays(4);
                    return Task.FromResult(ToolCallResponse(tool.Name, new Dictionary<string, object?>
                    {
                        ["startDate"] = start.ToString("yyyy-MM-dd"),
                        ["endDate"] = end.ToString("yyyy-MM-dd"),
                        ["leaveType"] = "Vacation"
                    }));
                }
            }
        }

        var snippet = ExtractReferenceSnippet(userContent);
        var answer = snippet is null
            ? "I couldn't find anything relevant to that in the HR policy documents. Could you rephrase your question?"
            : $"Based on the HR policy documents: {snippet}";

        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, answer)));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("DemoChatClient does not support streaming.");

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public void Dispose()
    {
    }

    private static ChatResponse ToolCallResponse(string toolName, IDictionary<string, object?> arguments) =>
        new(new ChatMessage(ChatRole.Assistant, [new FunctionCallContent(Guid.NewGuid().ToString("N"), toolName, arguments)]));

    private static string ExtractQuestion(string userContent)
    {
        const string marker = "Employee question:";
        var index = userContent.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        return index < 0 ? userContent : userContent[(index + marker.Length)..].Trim();
    }

    private static string? ExtractReferenceSnippet(string question)
    {
        const string marker = "Reference material";
        var index = question.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        var start = question.IndexOf('\n', index);
        if (start < 0)
        {
            return null;
        }

        var snippet = question[(start + 1)..].Trim();
        return snippet.Length > 280 ? snippet[..280] + "…" : snippet;
    }
}
