using ContosoHR.Api.Abuse;
using ContosoHR.Api.ContentSafety;
using ContosoHR.Api.Models;
using ContosoHR.Api.Rendering;
using ContosoHR.Assistant;
using ContosoHR.Assistant.Security;
using ContosoHR.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace ContosoHR.Api.Controllers;

/// <summary>
/// Every HTTP endpoint ContosoHR.Api exposes. Routes and behavior are unchanged
/// from the original Minimal API mapping in Program.cs — only the hosting model
/// moved, so ContosoHR.Integration.Tests needed no changes.
/// </summary>
[ApiController]
[Authorize]
public sealed class ApiController(
    IChatOrchestrator orchestrator,
    ITokenBudgetStore tokenBudget,
    IContentSafetyClassifier contentSafety,
    IMarkdownRenderer markdownRenderer,
    IPolicyDocumentSearch documentSearch,
    ILogger<ApiController> logger) : ControllerBase
{
    [HttpGet("/health")]
    [AllowAnonymous]
    public IActionResult Health() => Ok(new { status = "healthy" });

    [HttpPost("/api/chat")]
    [EnableRateLimiting("chat")]
    public async Task<IActionResult> Chat(ChatRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Message))
        {
            return BadRequest(new { error = "message is required." });
        }

        if (request.Message.Length > RequestLimits.MaxUserMessageLength)
        {
            return BadRequest(new { error = $"message exceeds the {RequestLimits.MaxUserMessageLength} character limit." });
        }

        var history = (request.History ?? []).Take(RequestLimits.MaxHistoryTurns).ToList();
        var userId = User.GetSubjectId();

        var estimatedTokens = RequestLimits.EstimateTokens(request.Message, history.Count);
        if (!tokenBudget.TryConsume(userId, estimatedTokens, out var remaining))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { error = "Monthly usage limit reached." });
        }

        var inputSafety = await contentSafety.ClassifyAsync(request.Message, cancellationToken);
        if (!inputSafety.IsSafe)
        {
            return Ok(new ChatResponseDto("I can't help with that request.", null));
        }

        try
        {
            var answer = await orchestrator.RespondAsync(
                request.Message,
                User,
                history.Select(h => new ChatTurn(h.Role, h.Text)).ToList(),
                cancellationToken);

            var outputSafety = await contentSafety.ClassifyAsync(answer.Text, cancellationToken);
            var safeText = outputSafety.IsSafe
                ? answer.Text
                : "I found an answer but it didn't pass a safety check, so I'm not able to show it. Please rephrase your question.";

            return Ok(new ChatResponseDto(markdownRenderer.ToHtml(safeText), answer.PendingAction?.Id));
        }
        catch (Exception ex)
        {
            // R7: never leak provider error details or upstream quota state to the client.
            logger.LogError(ex, "Chat request failed for user {UserId}", userId);
            return StatusCode(StatusCodes.Status502BadGateway, new { error = "The assistant is temporarily unavailable. Please try again shortly." });
        }
    }

    [HttpPost("/api/chat/confirm")]
    [EnableRateLimiting("chat")]
    public async Task<IActionResult> ConfirmChat(ConfirmRequest request, CancellationToken cancellationToken)
    {
        var answer = await orchestrator.ConfirmPendingActionAsync(request.PendingActionId, User, request.Approve, cancellationToken);
        return Ok(new ChatResponseDto(markdownRenderer.ToHtml(answer.Text), answer.PendingAction?.Id));
    }

    [HttpGet("/api/documents/search")]
    [EnableRateLimiting("document-search")]
    public IActionResult SearchDocuments([FromQuery] string query)
    {
        var results = documentSearch.Search(query, User);
        return Ok(results.Select(d => new { d.Id, d.FileName }));
    }
}
