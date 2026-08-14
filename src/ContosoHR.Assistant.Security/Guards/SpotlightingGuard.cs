namespace ContosoHR.Assistant.Security.Guards;

/// <summary>
/// R2 layer 4: datamarking spotlighting. Interleaves a rare marker character
/// through untrusted content so the model has a strong, structural signal — not
/// just a prose instruction it can be talked out of — that this text is data, not
/// commands. See Microsoft's "Defending Against Indirect Prompt Injection Attacks
/// With Spotlighting" for the technique this is based on.
///
/// Tradeoff: datamarking roughly increases token count for the marked span and can
/// slightly hurt the model's ability to answer questions ABOUT that content (exact
/// quoting in particular), because the marker characters are noise to the model
/// too. The alternative — encoding-based spotlighting (e.g. base64 the whole block)
/// — avoids interleaving noise but costs an explicit decode step and is usually
/// more token-expensive still. Datamarking was chosen here because the assistant
/// mostly needs to summarize/answer from policy documents, not quote them verbatim.
/// </summary>
public sealed class SpotlightingGuard
{
    private const char Marker = '^';

    public string Datamark(string untrustedContent)
    {
        var words = untrustedContent.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return words.Length == 0 ? untrustedContent : Marker + string.Join(Marker, words) + Marker;
    }
}
