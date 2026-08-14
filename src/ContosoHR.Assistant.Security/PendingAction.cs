using System.Collections.Concurrent;

namespace ContosoHR.Assistant.Security;

/// <summary>
/// A write or irreversible tool call the model requested but that has not executed
/// yet — it is waiting on the caller (the same authenticated user, checked by
/// <see cref="EmployeeId"/>) to confirm it via a follow-up call in the same session.
/// This is the synchronous confirmation flow: the orchestrator returns this in the
/// same chat turn instead of invoking the tool, and only invokes it once the caller
/// approves through <c>IChatOrchestrator.ConfirmPendingActionAsync</c>.
/// </summary>
public sealed record PendingAction(
    string Id,
    string ToolName,
    IReadOnlyDictionary<string, object?> Arguments,
    string EmployeeId,
    DateTimeOffset CreatedAtUtc);

public interface IPendingActionStore
{
    PendingAction Create(string toolName, IReadOnlyDictionary<string, object?> arguments, string employeeId);

    bool TryGet(string id, out PendingAction? action);

    void Remove(string id);
}

public sealed class InMemoryPendingActionStore : IPendingActionStore
{
    private readonly ConcurrentDictionary<string, PendingAction> _actions = new();

    public PendingAction Create(string toolName, IReadOnlyDictionary<string, object?> arguments, string employeeId)
    {
        var action = new PendingAction(Guid.NewGuid().ToString("N"), toolName, arguments, employeeId, DateTimeOffset.UtcNow);
        _actions[action.Id] = action;
        return action;
    }

    public bool TryGet(string id, out PendingAction? action) => _actions.TryGetValue(id, out action);

    public void Remove(string id) => _actions.TryRemove(id, out _);
}
