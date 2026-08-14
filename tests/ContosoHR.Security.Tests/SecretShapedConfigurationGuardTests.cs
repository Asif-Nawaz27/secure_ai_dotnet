using ContosoHR.Api.Configuration;
using Microsoft.Extensions.Configuration;

namespace ContosoHR.Security.Tests;

/// <summary>
/// Regression coverage for a real bug caught while wiring up integration tests: the
/// guard originally scanned the entire flattened configuration tree, which includes
/// every environment variable ASP.NET Core's default host loads — not just this
/// app's own settings. That flagged unrelated ambient host/CI environment variables
/// (e.g. a machine-specific service GUID) as "key-shaped," which would have crashed
/// startup on unrelated developer machines for no real security reason.
/// </summary>
public sealed class SecretShapedConfigurationGuardTests
{
    [Fact]
    public void UnrelatedAmbientEnvironmentVariable_IsNotFlagged()
    {
        var configuration = BuildConfiguration(("IGCCSVC_DB", "3f2a9c8e7b1d4f6a9c0e2b5d8f1a3c6e9b2d5f8a1c4e7b0d3f6a9c2e5b8d1f4a"));

        var offenders = SecretShapedConfigurationGuard.FindKeyShapedValues(configuration).ToList();

        Assert.Empty(offenders);
    }

    [Fact]
    public void KeyShapedValueUnderARelevantPrefix_IsFlagged()
    {
        var configuration = BuildConfiguration(("AZURE_OPENAI_API_KEY", "sk-abcdefghijklmnopqrstuvwx1234567890"));

        var offenders = SecretShapedConfigurationGuard.FindKeyShapedValues(configuration).ToList();

        Assert.Contains("AZURE_OPENAI_API_KEY", offenders);
    }

    [Fact]
    public void EndpointAndDeploymentNameValues_AreNeverFlaggedEvenIfLong()
    {
        var configuration = BuildConfiguration(
            ("AZURE_OPENAI_ENDPOINT", "https://contoso-openai-resource-name.openai.azure.com/"),
            ("AZURE_OPENAI_CHAT_DEPLOYMENT", "gpt-4o-mini-2024-07-18-deployment-name"));

        var offenders = SecretShapedConfigurationGuard.FindKeyShapedValues(configuration).ToList();

        Assert.Empty(offenders);
    }

    private static IConfiguration BuildConfiguration(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();
}
