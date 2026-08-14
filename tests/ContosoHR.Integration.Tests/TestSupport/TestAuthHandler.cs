using System.Security.Claims;
using System.Text.Encodings.Web;
using ContosoHR.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ContosoHR.Integration.Tests.TestSupport;

/// <summary>
/// Replaces the real JwtBearer handler in integration tests — the app validates
/// tokens issued by a mock OIDC provider (docker-compose's mock-oidc service),
/// which isn't running in the test process. This handler authenticates every
/// request using whatever employee id is in the "X-Test-User" header, with the
/// same claim shape (ClaimTypes.NameIdentifier, ClaimTypes.Role) the real handler
/// would produce, so downstream code (GetSubjectId, ResolveEmployeeRole) is
/// exercised identically either way.
/// </summary>
public sealed class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Test";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Test-User", out var employeeId) || string.IsNullOrWhiteSpace(employeeId))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var role = employeeId.ToString() switch
        {
            SeedData.CarolId => EmployeeRole.Manager,
            SeedData.DanaId => EmployeeRole.HrAdmin,
            _ => EmployeeRole.Employee
        };

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, employeeId.ToString()),
                new Claim(ClaimTypes.Role, role.ToString())
            ],
            SchemeName);

        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
