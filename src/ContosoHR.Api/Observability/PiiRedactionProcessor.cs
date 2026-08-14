using System.Diagnostics;
using System.Text.RegularExpressions;
using OpenTelemetry;

namespace ContosoHR.Api.Observability;

/// <summary>
/// R6: scrubs PII from prompt/completion telemetry before export. Classifiers are
/// configurable (<see cref="Classifiers"/>) rather than hardcoded, and prompt/
/// completion body attributes are dropped entirely — not just redacted — whenever
/// <see cref="IncludePromptAndCompletionBodies"/> is false, which is the deny-by-
/// default posture this app uses in the Production environment (see
/// AddContosoHrApiTelemetry). Redacting in place is a fallback for non-production
/// environments where seeing a redacted shape is still useful for debugging;
/// production doesn't even get that.
/// </summary>
public sealed partial class PiiRedactionProcessor(bool includePromptAndCompletionBodies) : BaseProcessor<Activity>
{
    public bool IncludePromptAndCompletionBodies { get; } = includePromptAndCompletionBodies;

    public static IReadOnlyList<(string Name, Regex Pattern)> Classifiers { get; } =
    [
        ("email", EmailPattern()),
        ("ssn", SsnPattern()),
        ("currency_amount", CurrencyAmountPattern())
    ];

    private static readonly string[] PromptAndCompletionAttributeNames =
        ["gen_ai.prompt", "gen_ai.completion", "assistant.user_message", "assistant.final_answer"];

    public override void OnEnd(Activity activity)
    {
        foreach (var attributeName in PromptAndCompletionAttributeNames)
        {
            var value = activity.GetTagItem(attributeName) as string;
            if (value is null)
            {
                continue;
            }

            if (!IncludePromptAndCompletionBodies)
            {
                activity.SetTag(attributeName, null);
                continue;
            }

            activity.SetTag(attributeName, Redact(value));
        }
    }

    public static string Redact(string value)
    {
        var redacted = value;
        foreach (var (name, pattern) in Classifiers)
        {
            redacted = pattern.Replace(redacted, $"[REDACTED:{name}]");
        }

        return redacted;
    }

    [GeneratedRegex(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")]
    private static partial Regex EmailPattern();

    [GeneratedRegex(@"\b\d{3}-\d{2}-\d{4}\b")]
    private static partial Regex SsnPattern();

    [GeneratedRegex(@"\$\s?\d{1,3}(,\d{3})*(\.\d+)?")]
    private static partial Regex CurrencyAmountPattern();
}
