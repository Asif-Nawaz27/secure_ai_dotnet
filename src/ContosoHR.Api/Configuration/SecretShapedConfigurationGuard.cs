using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

namespace ContosoHR.Api.Configuration;

/// <summary>
/// R5: fails startup if a key-shaped string is found in configuration. This is a
/// last-resort belt-and-suspenders check, not a substitute for the Gitleaks CI step
/// (.github/workflows/ci.yml) or for actually using DefaultAzureCredential instead
/// of keys — it exists to catch the case where someone pastes a real key into
/// appsettings.json or an environment variable during local debugging and forgets
/// to remove it before the app (and the mistake) goes further.
/// </summary>
public static partial class SecretShapedConfigurationGuard
{
    // Matches common cloud-provider API key shapes: long base64/hex-ish tokens
    // (32+ chars), and a few well-known prefixed formats (Azure/OpenAI-style,
    // AWS-style, GitHub-style). Deliberately conservative — false positives here
    // just mean fixing a config value; false negatives mean a leaked key ships.
    [GeneratedRegex(@"^(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|[A-Za-z0-9+/]{32,}={0,2})$")]
    private static partial Regex KeyShapedValuePattern();

    private static readonly string[] AllowedKeyNameSuffixes = ["Id", "Name", "Url", "Endpoint", "Deployment", "DeploymentName"];

    // Deliberately scoped to THIS app's own configuration surface, not the whole
    // flattened tree. ASP.NET Core's default configuration includes every
    // environment variable on the host process by way of AddEnvironmentVariables()
    // — scanning all of those produces false positives on unrelated ambient
    // variables (CI runners, IDE tooling, OS services) that happen to look
    // key-shaped but have nothing to do with this app. The realistic mistake this
    // guard exists to catch — someone pastes a real key into this app's own
    // settings — only ever shows up under one of these prefixes.
    private static readonly string[] RelevantKeyPrefixes =
        ["AZURE_OPENAI", "AzureOpenAI", "OIDC_", "CONTENT_SAFETY", "ContentSafety", "QDRANT", "ConnectionStrings"];

    public static void ThrowIfKeyShapedValuesArePresent(IConfiguration configuration)
    {
        var offenders = FindKeyShapedValues(configuration).ToList();
        if (offenders.Count > 0)
        {
            throw new InvalidOperationException(
                "Refusing to start: configuration contains one or more key-shaped values at "
                + string.Join(", ", offenders)
                + ". This app authenticates with DefaultAzureCredential / Managed Identity — no "
                + "API keys belong in configuration. Remove the value and use `dotnet user-secrets` "
                + "or Managed Identity instead.");
        }
    }

    public static IEnumerable<string> FindKeyShapedValues(IConfiguration configuration)
    {
        foreach (var section in configuration.AsEnumerable())
        {
            if (section.Value is null)
            {
                continue;
            }

            if (!RelevantKeyPrefixes.Any(prefix => section.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var keyName = section.Key.Contains(':') ? section.Key[(section.Key.LastIndexOf(':') + 1)..] : section.Key;
            if (AllowedKeyNameSuffixes.Any(suffix => keyName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (KeyShapedValuePattern().IsMatch(section.Value))
            {
                yield return section.Key;
            }
        }
    }
}
