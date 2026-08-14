namespace ContosoHR.Assistant.Security;

/// <summary>
/// Every tool the orchestrator can call must be classified by side effect. Only
/// <see cref="ReadOnly"/> tools may execute the moment the model requests them;
/// <see cref="Write"/> and <see cref="Irreversible"/> tools must be deferred behind
/// a <see cref="PendingAction"/> confirmation. See docs/plan.md's R3 section.
/// </summary>
public enum ToolSideEffect
{
    ReadOnly,
    Write,
    Irreversible
}
