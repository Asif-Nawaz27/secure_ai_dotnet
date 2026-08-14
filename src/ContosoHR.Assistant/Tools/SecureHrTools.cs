using System.ComponentModel;
using System.Security.Claims;
using ContosoHR.Assistant.Security;
using ContosoHR.Data;

namespace ContosoHR.Assistant.Tools;

/// <summary>
/// Fixed pair for VulnerableHrTools — see docs/threat-model.md#T03. Identity for
/// every operation is resolved from the caller's ClaimsPrincipal; GetEmployeeRecord
/// additionally checks <see cref="HrToolAuthorization"/> before returning anything,
/// and every argument is validated before use (docs/plan.md's R3 "treat tool
/// arguments as hostile input" requirement). Returning null on denial rather than
/// throwing keeps the shape identical to "not found" from the model's perspective —
/// it learns nothing about whether the id exists versus is just off-limits.
///
/// SubmitLeaveRequest's logic is unchanged from the vulnerable version — what
/// changed is that the orchestrator no longer invokes it the moment the model asks;
/// see docs/threat-model.md#T04 and SecureChatOrchestrator's PendingAction gate.
/// </summary>
public sealed class SecureHrTools(IEmployeeDirectory directory, ILeaveRequestStore leaveRequests, ClaimsPrincipal caller)
{
    private static readonly GetEmployeeRecordArgumentsValidator EmployeeRecordValidator = new();
    private static readonly SubmitLeaveRequestArgumentsValidator LeaveRequestValidator = new();

    [Description("Get the current employee's payslip for a given month, formatted as YYYY-MM.")]
    public PayslipDto? GetMyPayslip(string month)
    {
        var employeeId = caller.GetSubjectId();
        var payslip = directory.FindPayslip(employeeId, month);
        return payslip is null ? null : new PayslipDto(payslip.Month, payslip.GrossPay, payslip.NetPay);
    }

    [Description("Get an employee's HR record (department, role, salary) by employee id. Only permitted for your own id, your direct reports if you are a manager, or any id if you are an HR admin.")]
    public EmployeeRecordDto? GetEmployeeRecord(string employeeId)
    {
        var validation = EmployeeRecordValidator.Validate(new GetEmployeeRecordArguments(employeeId));
        if (!validation.IsValid)
        {
            return null;
        }

        if (!HrToolAuthorization.CanViewEmployeeRecord(caller, employeeId, directory))
        {
            return null;
        }

        var employee = directory.FindById(employeeId);
        return employee is null
            ? null
            : new EmployeeRecordDto(employee.Id, employee.DisplayName, employee.Department, employee.Role.ToString(), employee.MonthlySalary);
    }

    [Description("Submit a leave request for the current employee. startDate and endDate are ISO 8601 dates (YYYY-MM-DD).")]
    public LeaveRequestResultDto SubmitLeaveRequest(string startDate, string endDate, string leaveType)
    {
        var validation = LeaveRequestValidator.Validate(new SubmitLeaveRequestArguments(startDate, endDate, leaveType));
        if (!validation.IsValid)
        {
            return new LeaveRequestResultDto(false, string.Join(" ", validation.Errors.Select(e => e.ErrorMessage)));
        }

        var employeeId = caller.GetSubjectId();
        var request = new LeaveRequest(employeeId, DateOnly.Parse(startDate), DateOnly.Parse(endDate), leaveType, DateTimeOffset.UtcNow);
        leaveRequests.Submit(request);
        return new LeaveRequestResultDto(true, $"Leave request submitted for {startDate} to {endDate}.");
    }
}
