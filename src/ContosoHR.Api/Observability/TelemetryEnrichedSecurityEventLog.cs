using ContosoHR.Assistant.Security;

namespace ContosoHR.Api.Observability;

/// <summary>
/// Decorates the base <see cref="ISecurityEventLog"/> (structured logging) with the
/// R6 metrics side of guard-decision telemetry, so every guard verdict shows up both
/// as a log line for SIEM ingestion and as a counter for dashboards/alerting.
/// </summary>
public sealed class TelemetryEnrichedSecurityEventLog(ISecurityEventLog inner) : ISecurityEventLog
{
    public void Record(GuardDecision decision)
    {
        inner.Record(decision);

        AiTelemetry.GuardDecisions.Add(1, new KeyValuePair<string, object?>("layer", decision.Layer));
        if (decision.Blocked)
        {
            AiTelemetry.GuardBlocks.Add(1, new KeyValuePair<string, object?>("layer", decision.Layer));
        }
    }
}
