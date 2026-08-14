using System.Security.Claims;
using System.Threading.RateLimiting;
using Azure.Identity;
using ContosoHR.Api.Abuse;
using ContosoHR.Api.Chat;
using ContosoHR.Api.Configuration;
using ContosoHR.Api.ContentSafety;
using ContosoHR.Api.DependencyInjection;
using ContosoHR.Api.Observability;
using ContosoHR.Assistant.DependencyInjection;
using ContosoHR.Assistant.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.AI;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// R5: identity, secrets, configuration.
// ---------------------------------------------------------------------------
SecretShapedConfigurationGuard.ThrowIfKeyShapedValuesArePresent(builder.Configuration);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Simulated Entra ID / OIDC: a mock provider (docker-compose's mock-oidc
        // service) issues tokens shaped like real Entra ID claims (oid/sub, roles),
        // so this exact auth wiring is what production would use against a real
        // tenant — only the authority/audience values change.
        options.Authority = builder.Configuration["OIDC_AUTHORITY"] ?? "http://localhost:8080";
        options.Audience = builder.Configuration["OIDC_AUDIENCE"] ?? "contoso-hr-assistant";
        options.RequireHttpsMetadata = builder.Environment.IsProduction();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            NameClaimType = ClaimTypes.NameIdentifier,
            RoleClaimType = ClaimTypes.Role
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddControllers();

// ---------------------------------------------------------------------------
// AI pipeline: ContosoHR.Assistant's default (hardened) DI graph, plus this
// process's choice of IChatClient.
// ---------------------------------------------------------------------------
builder.Services.AddContosoHrAssistant();
builder.Services.AddContosoHrApi();

var useFakeChatClient = builder.Configuration.GetValue("USE_FAKE_CHAT_CLIENT", true);
if (useFakeChatClient)
{
    builder.Services.AddSingleton<IChatClient>(new DemoChatClient());
}
else
{
    var endpoint = builder.Configuration["AZURE_OPENAI_ENDPOINT"]
        ?? throw new InvalidOperationException("AZURE_OPENAI_ENDPOINT must be set when USE_FAKE_CHAT_CLIENT is false.");
    var deployment = builder.Configuration["AZURE_OPENAI_CHAT_DEPLOYMENT"] ?? "gpt-4o-mini";
    builder.Services.AddSingleton(AzureOpenAIChatClientFactory.Create(endpoint, deployment));
}

// R6 telemetry decorator over the guard-decision log AddContosoHrAssistant already registered.
builder.Services.AddSingleton<ISecurityEventLog>(sp =>
    new TelemetryEnrichedSecurityEventLog(new LoggerSecurityEventLog(sp.GetRequiredService<ILogger<LoggerSecurityEventLog>>())));

// ---------------------------------------------------------------------------
// R7: abuse, cost, availability.
// ---------------------------------------------------------------------------
builder.Services.AddSingleton<ITokenBudgetStore>(
    new InMemoryMonthlyTokenBudgetStore(builder.Configuration.GetValue("MONTHLY_TOKEN_CAP", 200_000)));

builder.Services.AddHttpClient("ContosoHR.Downstream").AddStandardResilienceHandler();

builder.Services.AddRateLimiter(options =>
{
    options.OnRejected = async (context, cancellationToken) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
        }

        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsync("Too many requests. Please try again shortly.", cancellationToken);
    };

    options.AddPolicy("chat", httpContext => RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? httpContext.Connection.Id,
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 20,
            Window = TimeSpan.FromMinutes(1)
        }));

    options.AddPolicy("document-search", httpContext => RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? httpContext.Connection.Id,
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 60,
            Window = TimeSpan.FromMinutes(1)
        }));
});

// ---------------------------------------------------------------------------
// R9: content safety. Azure AI Content Safety when configured; a local heuristic
// stand-in otherwise (never in production — see HeuristicContentSafetyClassifier).
// ---------------------------------------------------------------------------
var contentSafetyEndpoint = builder.Configuration["CONTENT_SAFETY_ENDPOINT"];
if (!string.IsNullOrWhiteSpace(contentSafetyEndpoint) && !useFakeChatClient)
{
    builder.Services.AddSingleton<IContentSafetyClassifier>(sp => new AzureContentSafetyClassifier(
        sp.GetRequiredService<IHttpClientFactory>().CreateClient("ContosoHR.Downstream"),
        new DefaultAzureCredential(),
        contentSafetyEndpoint));
}
else
{
    builder.Services.AddSingleton<IContentSafetyClassifier, HeuristicContentSafetyClassifier>();
}

// ---------------------------------------------------------------------------
// R6: OpenTelemetry instrumentation, with the deny-by-default redaction posture
// for prompt/completion bodies in Production.
// ---------------------------------------------------------------------------
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddSource(AiTelemetry.SourceName)
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddProcessor(new PiiRedactionProcessor(includePromptAndCompletionBodies: !builder.Environment.IsProduction())))
    .WithMetrics(metrics => metrics
        .AddMeter(AiTelemetry.SourceName)
        .AddAspNetCoreInstrumentation());

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.Use(async (context, next) =>
{
    // R8 defense-in-depth at the HTTP layer: even with SanitizingMarkdownRenderer
    // stripping executable content, a CSP means an injection that somehow survives
    // rendering still can't load a remote script.
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self'; img-src 'self'; object-src 'none'");
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    await next();
});

// All endpoints live in Controllers/ApiController.cs.
app.MapControllers();

app.Run();

// Exposed so WebApplicationFactory<Program> can find this host in integration tests.
public partial class Program;
