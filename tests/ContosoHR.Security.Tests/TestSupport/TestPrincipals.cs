using System.Security.Claims;
using ContosoHR.Data;

namespace ContosoHR.Security.Tests.TestSupport;

/// <summary>
/// Claims shaped like what the mock OIDC provider issues in docker-compose — the
/// subject id lands in <see cref="ClaimTypes.NameIdentifier"/> either way, so tests
/// exercise the exact same identity-resolution path production code does.
/// </summary>
public static class TestPrincipals
{
    public static ClaimsPrincipal Alice { get; } = Create(SeedData.AliceId, EmployeeRole.Employee);

    public static ClaimsPrincipal Carol { get; } = Create(SeedData.CarolId, EmployeeRole.Manager);

    public static ClaimsPrincipal Dana { get; } = Create(SeedData.DanaId, EmployeeRole.HrAdmin);

    private static ClaimsPrincipal Create(string employeeId, EmployeeRole role)
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, employeeId),
                new Claim(ClaimTypes.Role, role.ToString())
            ],
            authenticationType: "TestAuth");

        return new ClaimsPrincipal(identity);
    }
}
