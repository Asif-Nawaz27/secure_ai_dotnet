namespace ContosoHR.Data;

public interface IEmployeeDirectory
{
    Employee? FindById(string employeeId);

    Payslip? FindPayslip(string employeeId, string month);
}
