namespace ContosoHR.Data;

public sealed record Payslip(string EmployeeId, string Month, decimal GrossPay, decimal NetPay);
