using System.Collections.Concurrent;

namespace ContosoHR.Data;

public sealed class InMemoryLeaveRequestStore : ILeaveRequestStore
{
    private readonly ConcurrentBag<LeaveRequest> _requests = [];

    public void Submit(LeaveRequest request) => _requests.Add(request);

    public IReadOnlyList<LeaveRequest> GetForEmployee(string employeeId) =>
        [.. _requests.Where(r => string.Equals(r.EmployeeId, employeeId, StringComparison.OrdinalIgnoreCase))];
}
