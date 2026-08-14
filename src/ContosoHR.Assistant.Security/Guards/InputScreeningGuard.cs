using System.Text;
using System.Text.RegularExpressions;

namespace ContosoHR.Assistant.Security.Guards;

/// <summary>
/// R2 layer 2: heuristic detection of instruction-override language, encoded/
/// obfuscated payloads (base64, literal unicode escapes, zero-width characters,
/// homoglyphs), and excessive imperative density. Returns a risk score, not a
/// boolean — see <see cref="IPromptGuard"/>'s doc comment. This layer alone is not
/// sufficient; it is one signal among several (docs/threat-model.md's core
/// principle). A determined attacker can phrase an override without ever matching
/// these heuristics — that is exactly why R3/R4's authorization boundary exists.
/// </summary>
public sealed partial class InputScreeningGuard : IPromptGuard
{
    public string LayerName => "InputScreening";

    private static readonly string[] OverridePhrases =
    [
        "ignore all previous instructions",
        "ignore previous instructions",
        "ignore all prior instructions",
        "ignore the above",
        "disregard the above",
        "disregard all prior",
        "you are now",
        "new instructions:",
        "system override",
        "system prompt",
        "reveal your instructions",
        "reveal your system prompt",
        "repeat everything above",
        "do anything now",
        "unrestricted assistant",
        "no access controls",
        "no restrictions"
    ];

    // Zero-width space, zero-width non-joiner, zero-width joiner, BOM/zero-width
    // no-break space, word joiner.
    private static readonly char[] ZeroWidthCharacters =
        ['​', '‌', '‍', '﻿', '⁠'];

    // A deliberately small, conservative set of Cyrillic characters that are
    // visually indistinguishable from common Latin letters in most UI fonts —
    // enough to demonstrate the technique, not an exhaustive confusables table.
    private static readonly HashSet<char> HomoglyphCharacters =
    [
        'а', 'е', 'о', 'р', 'с', 'х', 'у', 'і', 'ѕ', // а е о р с х у і ѕ
        'А', 'В', 'Е', 'К', 'М', 'Н', 'О', 'Р', 'С', 'Т' // А В Е К М Н О Р С Т
    ];

    private static readonly string[] ImperativeMarkers =
    [
        "ignore", "disregard", "reveal", "override", "act as", "pretend",
        "stay in character", "you must", "never refuse", "always", "do not mention"
    ];

    public PromptGuardVerdict Evaluate(string content, IReadOnlyDictionary<string, string>? context = null)
    {
        var reasons = new List<string>();
        var score = 0.0;

        score += ScoreOverridePhrases(content, reasons);
        score += ScoreEncodedPayloads(content, reasons);
        score += ScoreZeroWidthCharacters(content, reasons);
        score += ScoreHomoglyphs(content, reasons);
        score += ScoreImperativeDensity(content, reasons);

        var clamped = Math.Clamp(score, 0.0, 1.0);
        return new PromptGuardVerdict(clamped, clamped >= 0.6, reasons.Count == 0 ? null : string.Join("; ", reasons));
    }

    private static double ScoreOverridePhrases(string content, List<string> reasons)
    {
        var lower = content.ToLowerInvariant();
        var hits = OverridePhrases.Count(phrase => lower.Contains(phrase, StringComparison.Ordinal));
        if (hits == 0)
        {
            return 0;
        }

        reasons.Add($"{hits} instruction-override phrase(s) detected");
        return Math.Min(0.4 + ((hits - 1) * 0.15), 0.7);
    }

    private static double ScoreEncodedPayloads(string content, List<string> reasons)
    {
        var score = 0.0;

        foreach (var match in Base64Pattern().Matches(content).Cast<Match>())
        {
            if (match.Value.Length < 16 || !TryDecodeBase64(match.Value, out var decoded))
            {
                continue;
            }

            if (OverridePhrases.Any(phrase => decoded.Contains(phrase, StringComparison.OrdinalIgnoreCase)))
            {
                reasons.Add("base64-decoded content contains an instruction-override phrase");
                score = Math.Max(score, 0.85);
            }
            else
            {
                reasons.Add("base64-looking payload present");
                score = Math.Max(score, 0.2);
            }
        }

        if (UnicodeEscapePattern().IsMatch(content))
        {
            reasons.Add("literal unicode escape sequence present");
            score = Math.Max(score, 0.3);
        }

        return score;
    }

    private static double ScoreZeroWidthCharacters(string content, List<string> reasons)
    {
        if (content.IndexOfAny(ZeroWidthCharacters) < 0)
        {
            return 0;
        }

        reasons.Add("zero-width character(s) present");
        return 0.5;
    }

    private static double ScoreHomoglyphs(string content, List<string> reasons)
    {
        var hits = content.Count(HomoglyphCharacters.Contains);
        if (hits == 0)
        {
            return 0;
        }

        reasons.Add($"{hits} homoglyph character(s) present");
        return Math.Min(0.1 * hits, 0.4);
    }

    private static double ScoreImperativeDensity(string content, List<string> reasons)
    {
        var sentences = content.Split(['.', '!', '?'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (sentences.Length == 0)
        {
            return 0;
        }

        var imperativeCount = sentences.Count(sentence =>
            ImperativeMarkers.Any(marker => sentence.Contains(marker, StringComparison.OrdinalIgnoreCase)));
        var density = (double)imperativeCount / sentences.Length;

        if (density < 0.3)
        {
            return 0;
        }

        reasons.Add($"high imperative density ({density:P0} of sentences)");
        return Math.Min(density, 0.5);
    }

    private static bool TryDecodeBase64(string value, out string decoded)
    {
        try
        {
            var bytes = Convert.FromBase64String(value);
            decoded = Encoding.UTF8.GetString(bytes);
            return decoded.All(c => !char.IsControl(c) || char.IsWhiteSpace(c));
        }
        catch (FormatException)
        {
            decoded = string.Empty;
            return false;
        }
    }

    [GeneratedRegex(@"[A-Za-z0-9+/]{16,}={0,2}")]
    private static partial Regex Base64Pattern();

    [GeneratedRegex(@"(?:\\u[0-9a-fA-F]{4}){3,}")]
    private static partial Regex UnicodeEscapePattern();
}
