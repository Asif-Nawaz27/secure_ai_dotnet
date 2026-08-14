using ContosoHR.Assistant.Security;

namespace ContosoHR.Assistant.Tools;

public static class HrToolCatalog
{
    /// <summary>
    /// Unknown tool names fail safe to <see cref="ToolSideEffect.Irreversible"/> —
    /// the most restrictive class — rather than defaulting to ReadOnly. A tool this
    /// catalog has never heard of should never be auto-executed.
    /// </summary>
    public static ToolSideEffect ClassifyBySideEffect(string toolName) => toolName switch
    {
        "GetMyPayslip" => ToolSideEffect.ReadOnly,
        "GetEmployeeRecord" => ToolSideEffect.ReadOnly,
        "SubmitLeaveRequest" => ToolSideEffect.Write,
        _ => ToolSideEffect.Irreversible
    };
}
