using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace ContosoHR.Api.Rendering;

/// <summary>
/// Fixed pair for NaiveMarkdownRenderer — see docs/threat-model.md#T09.
///
/// Model output is untrusted (docs/threat-model.md's core principle). Every
/// transform below either (a) HTML-encodes text so it can never become live markup,
/// or (b) drops a construct entirely rather than trying to render it "safely" —
/// link and image destinations are exactly the kind of thing a prompt injection
/// tries to control, so they are removed, not sanitized-in-place. A production
/// version could maintain a small allowlist of trusted hosts (e.g. the app's own
/// asset domain) and render those as real, encoded-href anchors; this reference
/// implementation keeps the bar simple and maximally safe by allowing none.
/// </summary>
public sealed partial class SanitizingMarkdownRenderer : IMarkdownRenderer
{
    public string ToHtml(string markdown)
    {
        var withoutImages = ImagePattern().Replace(markdown, "[image removed]");
        var withoutLinks = LinkPattern().Replace(withoutImages, match => match.Groups[1].Value);

        var encoded = HtmlEncoder.Default.Encode(withoutLinks);

        return BoldPattern().Replace(encoded, "<b>$1</b>");
    }

    [GeneratedRegex(@"\*\*(.+?)\*\*")]
    private static partial Regex BoldPattern();

    [GeneratedRegex(@"(?<!!)\[(.+?)\]\((.+?)\)")]
    private static partial Regex LinkPattern();

    [GeneratedRegex(@"!\[(.*?)\]\((.+?)\)")]
    private static partial Regex ImagePattern();
}
