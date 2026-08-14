namespace ContosoHR.Data;

/// <summary>
/// Seeded, read-only employee directory backing the demo. This class performs no
/// authorization — it answers "does this employee exist" for whatever id it is
/// given. Callers (tools) are responsible for deciding whether the caller is
/// entitled to ask about that id (see docs/threat-model.md#T03).
/// </summary>
public sealed class InMemoryEmployeeDirectory : IEmployeeDirectory
{
    private readonly Dictionary<string, Employee> _employees =
        SeedData.Employees.ToDictionary(e => e.Id, StringComparer.OrdinalIgnoreCase);

    private readonly ILookup<string, Payslip> _payslips =
        SeedData.Payslips.ToLookup(p => p.EmployeeId, StringComparer.OrdinalIgnoreCase);

    public Employee? FindById(string employeeId) =>
        _employees.GetValueOrDefault(employeeId);

    public Payslip? FindPayslip(string employeeId, string month) =>
        _payslips[employeeId].FirstOrDefault(p => p.Month == month);
}
