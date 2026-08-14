using ContosoHR.Api.Rendering;
using Microsoft.Extensions.DependencyInjection;

namespace ContosoHR.Api.DependencyInjection;

/// <summary>
/// Composition root for ContosoHR.Api's own concerns (output rendering, and later
/// rate limiting / resilience / content safety). Same pattern as
/// ContosoHR.Assistant.DependencyInjection.ServiceCollectionExtensions: this method
/// decides the default implementation, so tests that resolve through it flip from
/// red to green as fixed implementations replace vulnerable ones, with no test
/// changes required.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddContosoHrApi(this IServiceCollection services)
    {
        // R8 fixed default — see docs/threat-model.md#T09. NaiveMarkdownRenderer
        // remains in the codebase for contrast/tests but is never registered here.
        services.AddSingleton<IMarkdownRenderer, SanitizingMarkdownRenderer>();

        return services;
    }
}
