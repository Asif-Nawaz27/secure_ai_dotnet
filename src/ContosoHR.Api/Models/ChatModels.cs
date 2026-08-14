namespace ContosoHR.Api.Models;

public sealed record ChatRequest(string Message, List<ChatTurnDto>? History);

public sealed record ChatTurnDto(string Role, string Text);

public sealed record ConfirmRequest(string PendingActionId, bool Approve);

public sealed record ChatResponseDto(string Html, string? PendingActionId);
