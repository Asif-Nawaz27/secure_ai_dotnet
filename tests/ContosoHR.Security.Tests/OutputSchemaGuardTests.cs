using ContosoHR.Assistant.Security.Guards;

namespace ContosoHR.Security.Tests;

/// <summary>
/// R2 layer 5, tested standalone — see OutputSchemaGuard's doc comment for why it
/// isn't wired into the main conversational answer path in this reference app.
/// </summary>
public sealed class OutputSchemaGuardTests
{
    private readonly OutputSchemaGuard _guard = new();

    [Fact]
    public void TryValidate_WellFormedJson_Succeeds()
    {
        var succeeded = _guard.TryValidate(
            """{ "answer": "You have 15 PTO days per year.", "citedSources": ["employee-handbook.md"] }""",
            out var payload,
            out var error);

        Assert.True(succeeded);
        Assert.Null(error);
        Assert.Equal("You have 15 PTO days per year.", payload!.Answer);
        Assert.Equal(["employee-handbook.md"], payload.CitedSources);
    }

    [Fact]
    public void TryValidate_MalformedJson_FailsWithError()
    {
        var succeeded = _guard.TryValidate("this is not json", out var payload, out var error);

        Assert.False(succeeded);
        Assert.Null(payload);
        Assert.NotNull(error);
    }

    [Fact]
    public void TryValidate_MissingAnswerField_Fails()
    {
        var succeeded = _guard.TryValidate("""{ "citedSources": [] }""", out var payload, out var error);

        Assert.False(succeeded);
        Assert.Null(payload);
        Assert.NotNull(error);
    }

    [Fact]
    public void BuildRepairPrompt_IncludesTheValidationErrorAndTheOriginalResponse()
    {
        var repairPrompt = _guard.BuildRepairPrompt("not json", "Response was not valid JSON.");

        Assert.Contains("not json", repairPrompt);
        Assert.Contains("Response was not valid JSON.", repairPrompt);
    }

    [Fact]
    public async Task ValidateWithRetryAsync_RecoversAfterARepairPrompt()
    {
        var attempt = 0;
        var repairPromptsSeen = new List<string?>();

        var result = await _guard.ValidateWithRetryAsync(repairPrompt =>
        {
            repairPromptsSeen.Add(repairPrompt);
            attempt++;
            return Task.FromResult(attempt == 1
                ? "not valid json"
                : """{ "answer": "Fixed on retry.", "citedSources": [] }""");
        });

        Assert.NotNull(result);
        Assert.Equal("Fixed on retry.", result!.Answer);
        Assert.Equal(2, attempt);
        Assert.Null(repairPromptsSeen[0]);
        Assert.NotNull(repairPromptsSeen[1]);
    }

    [Fact]
    public async Task ValidateWithRetryAsync_GivesUpAfterMaxAttemptsAndReturnsNull()
    {
        var result = await _guard.ValidateWithRetryAsync(_ => Task.FromResult("still not json"), maxAttempts: 2);

        Assert.Null(result);
    }
}
