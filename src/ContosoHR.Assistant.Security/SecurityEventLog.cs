using Microsoft.Extensions.Logging;

namespace ContosoHR.Assistant.Security;

/// <summary>
/// One structured record of a guard (or authorization) decision — R6's minimum bar:
/// user, risk score, which layer fired, and what action was taken. Every guard in
/// this package logs through this contract rather than writing ad hoc log lines, so
/// a SIEM only needs one event shape to ingest.
/// </summary>
public sealed record GuardDecision(string Layer, double RiskScore, bool Blocked, string? Reason, string? UserId);

public interface ISecurityEventLog
{
    void Record(GuardDecision decision);
}

public sealed class LoggerSecurityEventLog(ILogger<LoggerSecurityEventLog> logger) : ISecurityEventLog
{
    public void Record(GuardDecision decision) =>
        logger.LogInformation(
            "guard_decision layer={Layer} risk_score={RiskScore} blocked={Blocked} user={UserId} reason={Reason}",
            decision.Layer,
            decision.RiskScore,
            decision.Blocked,
            decision.UserId,
            decision.Reason);
}
