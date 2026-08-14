namespace ContosoHR.Data;

public sealed record Employee(
    string Id,
    string DisplayName,
    EmployeeRole Role,
    string Department,
    string? ManagerId,
    decimal MonthlySalary);
