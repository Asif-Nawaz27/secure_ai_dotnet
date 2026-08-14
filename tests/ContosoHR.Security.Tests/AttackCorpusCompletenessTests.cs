using System.Text.Json;

namespace ContosoHR.Security.Tests;

/// <summary>
/// R10: "every payload in samples/attack-payloads/ has a recorded expected outcome
/// and an assertion." This test enforces that mechanically — corpus.json is the
/// source of truth, and every entry must point at a payload file that exists, a
/// non-empty expected outcome, and a testRef naming a real method in this assembly.
/// </summary>
public sealed class AttackCorpusCompletenessTests
{
    private static readonly string PayloadsDirectory = ResolvePayloadsDirectory();

    private sealed record CorpusEntry(
        string Id,
        string ThreatId,
        string Category,
        string File,
        string Description,
        string ExpectedOutcome,
        string TestRef);

    [Fact]
    public async Task EveryCorpusEntry_HasAnExistingPayloadFileAndARecordedExpectedOutcome()
    {
        var entries = await LoadCorpusAsync();
        Assert.NotEmpty(entries);

        foreach (var entry in entries)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.ExpectedOutcome), $"{entry.Id} has no expected outcome recorded.");
            Assert.False(string.IsNullOrWhiteSpace(entry.TestRef), $"{entry.Id} has no test reference recorded.");

            var payloadPath = Path.Combine(PayloadsDirectory, entry.File);
            Assert.True(File.Exists(payloadPath), $"{entry.Id} references missing payload file '{entry.File}'.");
        }
    }

    [Fact]
    public async Task EveryCorpusEntry_TestRefNamesAMethodThatActuallyExistsInThisAssembly()
    {
        var entries = await LoadCorpusAsync();
        var thisAssembly = typeof(AttackCorpusCompletenessTests).Assembly;

        foreach (var entry in entries)
        {
            foreach (var testRef in entry.TestRef.Split(','))
            {
                var lastDot = testRef.LastIndexOf('.');
                var typeName = testRef[..lastDot];
                var methodName = testRef[(lastDot + 1)..];

                var type = thisAssembly.GetType(typeName);
                Assert.True(type is not null, $"{entry.Id}'s testRef '{testRef}' names a type that doesn't exist: {typeName}");

                var method = type!.GetMethod(methodName);
                Assert.True(method is not null, $"{entry.Id}'s testRef '{testRef}' names a method that doesn't exist: {methodName}");
            }
        }
    }

    [Fact]
    public async Task EveryPayloadFileOnDisk_IsReferencedByAtLeastOneCorpusEntry()
    {
        var entries = await LoadCorpusAsync();
        var referencedFiles = entries.Select(e => e.File).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var orphaned = Directory.GetFiles(PayloadsDirectory, "*.txt")
            .Select(Path.GetFileName)
            .Where(fileName => !referencedFiles.Contains(fileName!))
            .ToList();

        Assert.Empty(orphaned);
    }

    private static async Task<List<CorpusEntry>> LoadCorpusAsync()
    {
        var json = await File.ReadAllTextAsync(Path.Combine(PayloadsDirectory, "corpus.json"));
        var entries = JsonSerializer.Deserialize<List<CorpusEntry>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return entries ?? [];
    }

    private static string ResolvePayloadsDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "samples", "attack-payloads")))
        {
            directory = directory.Parent;
        }

        return directory is null
            ? throw new DirectoryNotFoundException("Could not locate samples/attack-payloads from the test output directory.")
            : Path.Combine(directory.FullName, "samples", "attack-payloads");
    }
}
