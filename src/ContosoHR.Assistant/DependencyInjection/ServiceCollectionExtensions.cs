using ContosoHR.Assistant.Security;
using ContosoHR.Assistant.Security.Guards;
using ContosoHR.Data;
using Microsoft.Extensions.DependencyInjection;

namespace ContosoHR.Assistant.DependencyInjection;

/// <summary>
/// The composition root for ContosoHR.Assistant. This is the one place that decides
/// which implementation is "the default" — callers (ContosoHR.Api, tests) resolve
/// <see cref="IChatOrchestrator"/> and <see cref="IPolicyDocumentSearch"/> and never
/// choose an implementation themselves. As each control from docs/plan.md's R1–R10
/// mapping lands, its registration replaces the vulnerable one here; the vulnerable
/// types remain in the codebase (tests exercise them directly for contrast) but stop
/// being reachable through this method — see the Definition of Done in docs/plan.md.
///
/// Callers must register an <see cref="Microsoft.Extensions.AI.IChatClient"/>
/// themselves — this method does not choose between the real Azure OpenAI client and
/// the deterministic test fake.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddContosoHrAssistant(this IServiceCollection services)
    {
        services.AddLogging();

        services.AddSingleton<IEmployeeDirectory, InMemoryEmployeeDirectory>();
        services.AddSingleton<ILeaveRequestStore, InMemoryLeaveRequestStore>();

        // R4 fixed default — see docs/threat-model.md#T05. NaiveKeywordDocumentSearch
        // remains in the codebase for contrast/tests but is never registered here.
        services.AddSingleton<IPolicyDocumentSearch, AclFilteredDocumentSearch>();

        // R2 guard pipeline.
        services.AddSingleton<IPromptGuard, InputScreeningGuard>();
        services.AddSingleton<IndirectInjectionGuard>();
        services.AddSingleton<SpotlightingGuard>();

        // R3 tool-authorization boundary support.
        services.AddSingleton<IPendingActionStore, InMemoryPendingActionStore>();
        services.AddSingleton(new ToolCallBudget());

        // R6 (minimum bar): every guard decision logged as a structured event.
        services.AddSingleton<ISecurityEventLog, LoggerSecurityEventLog>();

        // R2/R3/R4 fixed default — see docs/threat-model.md#T01, #T02, #T03, #T04,
        // #T05, #T07. VulnerableChatOrchestrator remains in the codebase for
        // contrast/tests but is never registered here.
        services.AddScoped<IChatOrchestrator, SecureChatOrchestrator>();

        return services;
    }
}
