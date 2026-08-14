namespace ContosoHR.Assistant.Security;

/// <summary>
/// R3's loop breaker: the maximum number of model↔tool round trips a single request
/// may take. This is the actual control — the vulnerable orchestrator's
/// SafetyIterationCeiling was a crash-prevention valve, not a security boundary.
/// </summary>
public sealed record ToolCallBudget(int MaxRoundTrips = 4);
