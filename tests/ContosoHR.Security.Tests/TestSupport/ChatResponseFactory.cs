using Microsoft.Extensions.AI;

namespace ContosoHR.Security.Tests.TestSupport;

/// <summary>Small builders so scripted test responses read as intent, not boilerplate.</summary>
public static class ChatResponseFactory
{
    public static ChatResponse Text(string text) =>
        new(new ChatMessage(ChatRole.Assistant, text));

    public static ChatResponse ToolCall(string callId, string toolName, IDictionary<string, object?>? arguments = null) =>
        new(new ChatMessage(ChatRole.Assistant, [new FunctionCallContent(callId, toolName, arguments)]));

    public static ChatResponse ToolCalls(params (string CallId, string ToolName, IDictionary<string, object?>? Arguments)[] calls) =>
        new(new ChatMessage(
            ChatRole.Assistant,
            [.. calls.Select(call => (AIContent)new FunctionCallContent(call.CallId, call.ToolName, call.Arguments))]));
}
