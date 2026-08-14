using System.Security.Claims;

namespace ContosoHR.Assistant;

public interface IChatOrchestrator
{
    Task<AssistantAnswer> RespondAsync(
        string userMessage,
        ClaimsPrincipal caller,
        IReadOnlyList<ChatTurn> history,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Confirms (or rejects) a <see cref="Security.PendingAction"/> returned from a
    /// prior <see cref="RespondAsync"/> call — the synchronous human-confirmation
    /// flow (docs/plan.md's R3 section). <paramref name="caller"/> must be the same
    /// employee the pending action was created for.
    /// </summary>
    Task<AssistantAnswer> ConfirmPendingActionAsync(
        string pendingActionId,
        ClaimsPrincipal caller,
        bool approve,
        CancellationToken cancellationToken = default);
}
