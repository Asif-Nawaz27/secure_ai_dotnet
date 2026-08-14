using System.ComponentModel;
using System.Security.Claims;
using ContosoHR.Assistant.Security;
using ContosoHR.Data;

namespace ContosoHR.Assistant.Tools;

// ⚠️ VULNERABLE — see docs/threat-model.md#T03 and #T04.
//
// GetEmployeeRecord trusts the `employeeId` argument the model supplies instead of
// deriving identity from the caller's ClaimsPrincipal — the confused-deputy bug:
// the LLM executes with the application's credentials, and this method lets the
// model's choice of argument stand in for authorization. Any authenticated employee
// can read any other employee's HR record simply by getting the assistant to call
// this function with an id that isn't their own.
//
// SubmitLeaveRequest executes immediately: a write, semi-irreversible action happens
// purely because the model decided to call the function, with no human confirmation
// step between "model wants to do this" and "it happened."
//
// GetMyPayslip is the one method here that is NOT part of the vulnerability — it
// already resolves the employee id from the caller's claims rather than an argument,
// which is exactly the pattern GetEmployeeRecord should have followed. It is kept
// alongside the two vulnerable methods so the fixed pair (R3) can be a drop-in
// same-shape replacement.
//
// This class is never registered in the default DI graph — see
// ContosoHR.Assistant/DependencyInjection/ServiceCollectionExtensions.cs.
public sealed class VulnerableHrTools(
    IEmployeeDirectory directory,
    ILeaveRequestStore leaveRequests,
    ClaimsPrincipal caller)
{
    [Description("Get the current employee's payslip for a given month, formatted as YYYY-MM.")]
    public PayslipDto? GetMyPayslip(string month)
    {
        var employeeId = caller.GetSubjectId();
        var payslip = directory.FindPayslip(employeeId, month);
        return payslip is null ? null : new PayslipDto(payslip.Month, payslip.GrossPay, payslip.NetPay);
    }

    [Description("Get an employee's HR record (department, role, salary) by employee id.")]
    public EmployeeRecordDto? GetEmployeeRecord(string employeeId)
    {
        var employee = directory.FindById(employeeId);
        return employee is null
            ? null
            : new EmployeeRecordDto(employee.Id, employee.DisplayName, employee.Department, employee.Role.ToString(), employee.MonthlySalary);
    }

    [Description("Submit a leave request for the current employee. startDate and endDate are ISO 8601 dates (YYYY-MM-DD).")]
    public LeaveRequestResultDto SubmitLeaveRequest(string startDate, string endDate, string leaveType)
    {
        var employeeId = caller.GetSubjectId();
        var request = new LeaveRequest(
            employeeId,
            DateOnly.Parse(startDate),
            DateOnly.Parse(endDate),
            leaveType,
            DateTimeOffset.UtcNow);

        leaveRequests.Submit(request);
        return new LeaveRequestResultDto(true, $"Leave request submitted for {startDate} to {endDate}.");
    }
}
