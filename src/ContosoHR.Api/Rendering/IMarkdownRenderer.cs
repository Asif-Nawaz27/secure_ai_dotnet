namespace ContosoHR.Api.Rendering;

public interface IMarkdownRenderer
{
    string ToHtml(string markdown);
}
