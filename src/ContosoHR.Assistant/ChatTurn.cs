using ContosoHR.Assistant.Security;

namespace ContosoHR.Assistant;

public sealed record ChatTurn(string Role, string Text);

/// <summary>
/// <paramref name="PendingAction"/> is set when the model requested a write or
/// irreversible tool call that is now waiting on caller confirmation — see
/// docs/threat-model.md#T04. <paramref name="Text"/> is always a safe, displayable
/// message either way (e.g. "I can do that, but first I need your confirmation.").
/// </summary>
public sealed record AssistantAnswer(string Text, PendingAction? PendingAction = null);
