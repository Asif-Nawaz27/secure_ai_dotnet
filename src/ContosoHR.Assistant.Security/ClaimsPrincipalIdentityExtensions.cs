using System.Security.Claims;

namespace ContosoHR.Assistant.Security;

/// <summary>
/// The single place identity is read out of a <see cref="ClaimsPrincipal"/>. Tool
/// implementations must call this rather than trusting an id supplied by the model —
/// see docs/threat-model.md#T03. This type has no HR-domain dependency, matching the
/// requirement that this package be reusable outside ContosoHR.
/// </summary>
public static class ClaimsPrincipalIdentityExtensions
{
    /// <summary>
    /// Resolves the authenticated caller's subject id from the standard
    /// <see cref="ClaimTypes.NameIdentifier"/> claim (mapped from "sub"/"oid" by the
    /// OIDC handler). Throws rather than returning an empty/null id, because a tool
    /// that silently falls back to "no identity" is exactly the confused-deputy bug
    /// this method exists to prevent.
    /// </summary>
    public static string GetSubjectId(this ClaimsPrincipal principal)
    {
        var subjectId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new InvalidOperationException(
                "Caller has no subject id claim. Refusing to resolve an identity-scoped operation.");
        }

        return subjectId;
    }
}
