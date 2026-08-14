using System.Security.Claims;

namespace ContosoHR.Data;

public static class ClaimsPrincipalRoleExtensions
{
    public static EmployeeRole ResolveEmployeeRole(this ClaimsPrincipal principal)
    {
        var roleClaim = principal.FindFirst(ClaimTypes.Role)?.Value;
        return Enum.TryParse<EmployeeRole>(roleClaim, out var role) ? role : EmployeeRole.Employee;
    }
}
