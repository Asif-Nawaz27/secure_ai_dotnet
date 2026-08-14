using System.Security.Claims;
using ContosoHR.Assistant.Security;
using ContosoHR.Data;

namespace ContosoHR.Assistant.Tools;

/// <summary>
/// The actual authorization decision for cross-employee lookups — see
/// docs/threat-model.md#T03. Lives in ContosoHR.Assistant (not
/// ContosoHR.Assistant.Security) because it encodes an HR-specific policy
/// (manager-of relationship, HR admin override), and the security package must stay
/// domain-agnostic.
/// </summary>
public static class HrToolAuthorization
{
    public static bool CanViewEmployeeRecord(ClaimsPrincipal caller, string targetEmployeeId, IEmployeeDirectory directory)
    {
        var callerId = caller.GetSubjectId();
        if (string.Equals(callerId, targetEmployeeId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (caller.IsInRole(nameof(EmployeeRole.HrAdmin)))
        {
            return true;
        }

        if (caller.IsInRole(nameof(EmployeeRole.Manager)))
        {
            var target = directory.FindById(targetEmployeeId);
            return target?.ManagerId is not null && string.Equals(target.ManagerId, callerId, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }
}
