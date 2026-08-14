namespace ContosoHR.Data;

public sealed record LeaveRequest(
    string EmployeeId,
    DateOnly StartDate,
    DateOnly EndDate,
    string LeaveType,
    DateTimeOffset SubmittedAt);
