using System.Security.Claims;
using System.Text;
using ContosoHR.Assistant.Tools;
using ContosoHR.Data;
using Microsoft.Extensions.AI;

namespace ContosoHR.Assistant;

// ⚠️ VULNERABLE — see docs/threat-model.md#T01, #T02, #T05, #T07.
//
// Three separate problems live in this one orchestrator:
//
//  1. Structural (T01/T02): system instructions, retrieved (untrusted) document
//     content, and the user's own message are concatenated into a single string and
//     sent as ONE message with role "system". There is no boundary a model — or any
//     downstream filter — could use to tell "instructions from Contoso" apart from
//     "text that arrived from a document or from the user." A document that
//     contains an embedded instruction (docs/threat-model.md#T02, see
//     SeedData.BenefitsFaq) reads to the model exactly the same as a real system
//     instruction.
//
//  2. Retrieval (T05): document search runs via NaiveKeywordDocumentSearch, which
//     ignores the caller's entitlements entirely.
//
//  3. Tool-call budget (T07): every requested function call is executed, with no
//     cap on how many round trips a single request can trigger.
//
// Never register this type in the default DI graph — see
// ContosoHR.Assistant/DependencyInjection/ServiceCollectionExtensions.cs.
public sealed class VulnerableChatOrchestrator(
    IChatClient chatClient,
    IPolicyDocumentSearch documentSearch,
    IEmployeeDirectory employeeDirectory,
    ILeaveRequestStore leaveRequests) : IChatOrchestrator
{
    // Not a security control — a sanity ceiling so a misbehaving chat client can't
    // hang the process forever. The fixed orchestrator's ToolCallBudget (R3) is the
    // actual control, and it is far stricter than this number.
    private const int SafetyIterationCeiling = 1_000;

    public async Task<AssistantAnswer> RespondAsync(
        string userMessage,
        ClaimsPrincipal caller,
        IReadOnlyList<ChatTurn> history,
        CancellationToken cancellationToken = default)
    {
        var retrievedDocuments = documentSearch.Search(userMessage, caller);

        var prompt = new StringBuilder()
            .AppendLine("You are the Contoso HR Assistant. Answer employee questions using the reference material below.")
            .AppendLine();

        prompt.AppendLine("Reference material:");
        foreach (var document in retrievedDocuments)
        {
            prompt.AppendLine(document.Content);
            prompt.AppendLine();
        }

        if (history.Count > 0)
        {
            prompt.AppendLine("Conversation so far:");
            foreach (var turn in history)
            {
                prompt.AppendLine($"{turn.Role}: {turn.Text}");
            }

            prompt.AppendLine();
        }

        prompt.AppendLine($"Employee question: {userMessage}");

        var tools = BuildTools(caller);
        var messages = new List<ChatMessage> { new(ChatRole.System, prompt.ToString()) };
        var options = new ChatOptions { Tools = [.. tools.Values] };

        for (var iteration = 0; iteration < SafetyIterationCeiling; iteration++)
        {
            var response = await chatClient.GetResponseAsync(messages, options, cancellationToken);
            messages.AddRange(response.Messages);

            var functionCalls = response.Messages
                .SelectMany(m => m.Contents)
                .OfType<FunctionCallContent>()
                .ToList();

            if (functionCalls.Count == 0)
            {
                return new AssistantAnswer(response.Text);
            }

            foreach (var call in functionCalls)
            {
                if (!tools.TryGetValue(call.Name, out var tool))
                {
                    continue;
                }

                object? result;
                try
                {
                    result = await tool.InvokeAsync(new AIFunctionArguments(call.Arguments), cancellationToken);
                }
                catch (Exception ex)
                {
                    result = $"Error: {ex.Message}";
                }

                messages.Add(new ChatMessage(ChatRole.Tool, [new FunctionResultContent(call.CallId, result)]));
            }
        }

        throw new InvalidOperationException($"Exceeded the {SafetyIterationCeiling}-iteration safety ceiling.");
    }

    // This orchestrator never creates a PendingAction — see docs/threat-model.md#T04 —
    // so there is nothing to confirm.
    public Task<AssistantAnswer> ConfirmPendingActionAsync(
        string pendingActionId,
        ClaimsPrincipal caller,
        bool approve,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "VulnerableChatOrchestrator has no confirmation flow — write tools execute immediately.");

    private Dictionary<string, AIFunction> BuildTools(ClaimsPrincipal caller)
    {
        var hrTools = new VulnerableHrTools(employeeDirectory, leaveRequests, caller);

        AIFunction[] functions =
        [
            AIFunctionFactory.Create(hrTools.GetMyPayslip),
            AIFunctionFactory.Create(hrTools.GetEmployeeRecord),
            AIFunctionFactory.Create(hrTools.SubmitLeaveRequest)
        ];

        return functions.ToDictionary(f => f.Name);
    }
}
