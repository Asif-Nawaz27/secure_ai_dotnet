using System.Text.RegularExpressions;

namespace ContosoHR.Assistant.Security.Guards;

/// <summary>
/// R2 layer 3: sanitizes retrieved (untrusted) content and tags it with provenance
/// so the model — and any downstream guard — can tell "text that arrived from a
/// document" apart from real instructions. See docs/threat-model.md#T02.
/// </summary>
public sealed partial class IndirectInjectionGuard : IPromptGuard
{
    public string LayerName => "IndirectInjection";

    public PromptGuardVerdict Evaluate(string content, IReadOnlyDictionary<string, string>? context = null)
    {
        var reasons = new List<string>();
        var score = 0.0;

        if (HtmlCommentPattern().IsMatch(content))
        {
            reasons.Add("HTML comment block present (a common indirect-injection hiding spot)");
            score = Math.Max(score, 0.6);
        }

        if (InstructionLikePattern().IsMatch(content))
        {
            reasons.Add("instruction-shaped language embedded in document content");
            score = Math.Max(score, 0.5);
        }

        return new PromptGuardVerdict(score, score >= 0.6, reasons.Count == 0 ? null : string.Join("; ", reasons));
    }

    /// <summary>
    /// Strips control structures that are common indirect-injection vectors — HTML
    /// comments, script/style blocks, and raw HTML tags — then tags the remainder
    /// with its source and untrusted status, exactly as it is presented to the model.
    /// This is transformation, not scoring, which is why it lives alongside
    /// <see cref="Evaluate"/> rather than being expressed through it.
    /// </summary>
    public string SanitizeAndTag(string documentContent, string sourceFileName)
    {
        var stripped = HtmlCommentPattern().Replace(documentContent, string.Empty);
        stripped = ScriptOrStylePattern().Replace(stripped, string.Empty);
        stripped = HtmlTagPattern().Replace(stripped, string.Empty);

        return $"[source: {sourceFileName}, untrusted]\n{stripped.Trim()}";
    }

    [GeneratedRegex(@"<!--.*?-->", RegexOptions.Singleline)]
    private static partial Regex HtmlCommentPattern();

    [GeneratedRegex(@"<(script|style)\b[^>]*>.*?</\1>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex ScriptOrStylePattern();

    [GeneratedRegex(@"<[^>]+>")]
    private static partial Regex HtmlTagPattern();

    [GeneratedRegex(@"(?i)\b(system override|ignore (all|prior|previous) instructions|do not mention this)\b")]
    private static partial Regex InstructionLikePattern();
}
