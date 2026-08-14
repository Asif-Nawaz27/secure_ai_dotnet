using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ContosoHR.Integration.Tests.TestSupport;

/// <summary>
/// Boots the real ContosoHR.Api host — the actual default DI graph, actual
/// middleware pipeline, actual endpoints — swapping only the real JwtBearer
/// authentication for <see cref="TestAuthHandler"/> (no live mock-oidc container in
/// the test process) and forcing USE_FAKE_CHAT_CLIENT so no live Azure OpenAI call
/// happens either. Everything else — guards, tool authorization, rate limiting,
/// rendering — runs exactly as it would in docker-compose.
/// </summary>
public sealed class ContosoHrApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["USE_FAKE_CHAT_CLIENT"] = "true"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(TestAuthHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
        });
    }
}
