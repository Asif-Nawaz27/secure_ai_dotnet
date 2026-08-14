using ContosoHR.Assistant;
using ContosoHR.Assistant.DependencyInjection;
using ContosoHR.Data;
using ContosoHR.Security.Tests.TestSupport;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;

namespace ContosoHR.Security.Tests;

/// <summary>
/// R3's synchronous confirmation flow, exercised end to end: a write tool call
/// returns a PendingAction instead of executing, and only
/// ConfirmPendingActionAsync — called by the SAME employee — actually commits it.
/// </summary>
public sealed class PendingActionConfirmationTests
{
    [Fact]
    public async Task ApprovingAPendingAction_CommitsTheLeaveRequest()
    {
        var leaveRequests = new InMemoryLeaveRequestStore();
        var chatClient = ScriptedChatClient.WithResponses(
            ChatResponseFactory.ToolCall(
                "call-1",
                "SubmitLeaveRequest",
                new Dictionary<string, object?>
                {
                    ["startDate"] = "2026-09-01",
                    ["endDate"] = "2026-09-05",
                    ["leaveType"] = "Vacation"
                }));

        var services = new ServiceCollection().AddContosoHrAssistant();
        services.AddSingleton<IChatClient>(chatClient);
        services.AddSingleton<ILeaveRequestStore>(leaveRequests);
        var orchestrator = services.BuildServiceProvider().GetRequiredService<IChatOrchestrator>();

        var initial = await orchestrator.RespondAsync("Please submit my leave for next week.", TestPrincipals.Alice, []);
        Assert.NotNull(initial.PendingAction);
        Assert.Empty(leaveRequests.GetForEmployee(SeedData.AliceId));

        var confirmed = await orchestrator.ConfirmPendingActionAsync(initial.PendingAction!.Id, TestPrincipals.Alice, approve: true);

        Assert.Single(leaveRequests.GetForEmployee(SeedData.AliceId));
        Assert.DoesNotContain("no longer available", confirmed.Text);
    }

    [Fact]
    public async Task RejectingAPendingAction_DoesNotCommitTheLeaveRequest()
    {
        var leaveRequests = new InMemoryLeaveRequestStore();
        var chatClient = ScriptedChatClient.WithResponses(
            ChatResponseFactory.ToolCall(
                "call-1",
                "SubmitLeaveRequest",
                new Dictionary<string, object?>
                {
                    ["startDate"] = "2026-09-01",
                    ["endDate"] = "2026-09-05",
                    ["leaveType"] = "Vacation"
                }));

        var services = new ServiceCollection().AddContosoHrAssistant();
        services.AddSingleton<IChatClient>(chatClient);
        services.AddSingleton<ILeaveRequestStore>(leaveRequests);
        var orchestrator = services.BuildServiceProvider().GetRequiredService<IChatOrchestrator>();

        var initial = await orchestrator.RespondAsync("Please submit my leave for next week.", TestPrincipals.Alice, []);

        await orchestrator.ConfirmPendingActionAsync(initial.PendingAction!.Id, TestPrincipals.Alice, approve: false);

        Assert.Empty(leaveRequests.GetForEmployee(SeedData.AliceId));
    }

    [Fact]
    public async Task ConfirmingSomeoneElsesPendingAction_IsRejected()
    {
        var leaveRequests = new InMemoryLeaveRequestStore();
        var chatClient = ScriptedChatClient.WithResponses(
            ChatResponseFactory.ToolCall(
                "call-1",
                "SubmitLeaveRequest",
                new Dictionary<string, object?>
                {
                    ["startDate"] = "2026-09-01",
                    ["endDate"] = "2026-09-05",
                    ["leaveType"] = "Vacation"
                }));

        var services = new ServiceCollection().AddContosoHrAssistant();
        services.AddSingleton<IChatClient>(chatClient);
        services.AddSingleton<ILeaveRequestStore>(leaveRequests);
        var orchestrator = services.BuildServiceProvider().GetRequiredService<IChatOrchestrator>();

        var initial = await orchestrator.RespondAsync("Please submit my leave for next week.", TestPrincipals.Alice, []);

        // Carol tries to approve Alice's pending leave request.
        await orchestrator.ConfirmPendingActionAsync(initial.PendingAction!.Id, TestPrincipals.Carol, approve: true);

        Assert.Empty(leaveRequests.GetForEmployee(SeedData.AliceId));
    }
}
