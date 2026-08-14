namespace ContosoHR.Assistant.Security;

/// <summary>
/// Contract for one layer in the prompt-injection defense-in-depth pipeline
/// (docs/plan.md R2). Each layer returns a risk assessment rather than a plain
/// allow/deny boolean — see docs/threat-model.md's core principle: none of these
/// layers is sufficient alone, and the combination is mitigation, not elimination.
/// The only real boundary is authorization at the tool and data layer (R3, R4).
///
/// No implementation of this interface exists yet — that absence is itself the
/// vulnerability tracked by docs/threat-model.md#T13 in the baseline build. R2 adds
/// the concrete guards (input screening, indirect-injection handling, spotlighting,
/// output validation) and wires them into the default DI graph.
/// </summary>
public interface IPromptGuard
{
    string LayerName { get; }

    PromptGuardVerdict Evaluate(string content, IReadOnlyDictionary<string, string>? context = null);
}

/// <param name="RiskScore">0.0 (benign) to 1.0 (certain attack). A score, not a boolean — see the interface doc.</param>
/// <param name="ShouldBlock">This layer's recommendation. Downstream policy decides what to do with it.</param>
public sealed record PromptGuardVerdict(double RiskScore, bool ShouldBlock, string? Reason = null);
