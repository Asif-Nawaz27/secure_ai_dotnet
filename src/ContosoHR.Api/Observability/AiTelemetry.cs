using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace ContosoHR.Api.Observability;

/// <summary>
/// R6: OpenTelemetry instrumentation for the AI pipeline — latency (via Activity
/// spans), token counts, tool-call counts, and guard verdict counts. Both the
/// ActivitySource and Meter names below must be registered with the OpenTelemetry
/// SDK (see AddContosoHrApiTelemetry) or these become no-ops.
/// </summary>
public static class AiTelemetry
{
    public const string SourceName = "ContosoHR.Assistant";

    public static readonly ActivitySource ActivitySource = new(SourceName);

    private static readonly Meter Meter = new(SourceName);

    public static readonly Histogram<double> RequestLatencyMs =
        Meter.CreateHistogram<double>("contoso_hr.assistant.request_latency_ms", unit: "ms");

    public static readonly Counter<long> PromptTokens =
        Meter.CreateCounter<long>("contoso_hr.assistant.prompt_tokens");

    public static readonly Counter<long> CompletionTokens =
        Meter.CreateCounter<long>("contoso_hr.assistant.completion_tokens");

    public static readonly Counter<long> ToolCalls =
        Meter.CreateCounter<long>("contoso_hr.assistant.tool_calls");

    public static readonly Counter<long> GuardDecisions =
        Meter.CreateCounter<long>("contoso_hr.assistant.guard_decisions");

    public static readonly Counter<long> GuardBlocks =
        Meter.CreateCounter<long>("contoso_hr.assistant.guard_blocks");
}
