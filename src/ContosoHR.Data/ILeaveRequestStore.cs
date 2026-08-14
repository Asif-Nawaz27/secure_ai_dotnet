namespace ContosoHR.Data;

public interface ILeaveRequestStore
{
    void Submit(LeaveRequest request);

    IReadOnlyList<LeaveRequest> GetForEmployee(string employeeId);
}
