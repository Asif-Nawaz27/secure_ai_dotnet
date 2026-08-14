using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ContosoHR.Data;
using ContosoHR.Integration.Tests.TestSupport;

namespace ContosoHR.Integration.Tests;

/// <summary>
/// End-to-end tests against the real host (see ContosoHrApiFactory) — the closest
/// thing in this repo to "does docker compose up actually work," short of running
/// docker compose itself. Exercises all three seeded privilege levels.
/// </summary>
public sealed class ChatEndpointTests(ContosoHrApiFactory factory) : IClassFixture<ContosoHrApiFactory>
{
    [Fact]
    public async Task Health_ReturnsOkWithoutAuthentication()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Chat_WithoutAuthentication_ReturnsUnauthorized()
    {
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/chat", new { message = "What is the PTO policy?" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(SeedData.AliceId)]
    [InlineData(SeedData.CarolId)]
    [InlineData(SeedData.DanaId)]
    public async Task Chat_AsEachSeededUser_ReturnsASuccessfulAnswer(string employeeId)
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-User", employeeId);

        var response = await client.PostAsJsonAsync("/api/chat", new { message = "What is the expense reimbursement policy?" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("html").GetString()));
    }

    [Fact]
    public async Task Chat_MessageOverLengthLimit_ReturnsBadRequest()
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-User", SeedData.AliceId);

        var response = await client.PostAsJsonAsync("/api/chat", new { message = new string('a', 5_000) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Chat_SubmitLeaveRequest_ReturnsAPendingActionRatherThanExecutingImmediately()
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-User", SeedData.AliceId);

        var response = await client.PostAsJsonAsync(
            "/api/chat",
            new { message = "Please submit a leave request for next week." });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.TryGetProperty("pendingActionId", out var pendingId) && pendingId.ValueKind == JsonValueKind.String);
    }
}
