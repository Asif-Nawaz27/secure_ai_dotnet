namespace ContosoHR.Assistant.Tools;

public sealed record PayslipDto(string Month, decimal GrossPay, decimal NetPay);

public sealed record EmployeeRecordDto(string Id, string DisplayName, string Department, string Role, decimal MonthlySalary);

public sealed record LeaveRequestResultDto(bool Success, string Message);
