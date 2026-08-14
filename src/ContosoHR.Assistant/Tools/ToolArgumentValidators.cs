using FluentValidation;

namespace ContosoHR.Assistant.Tools;

/// <summary>
/// Tool arguments come from the model — treat them as hostile user input (R3).
/// These records/validators mirror the tool method signatures so every argument is
/// validated before it reaches domain logic, independent of whatever authorization
/// checks also apply.
/// </summary>
public sealed record GetEmployeeRecordArguments(string EmployeeId);

public sealed class GetEmployeeRecordArgumentsValidator : AbstractValidator<GetEmployeeRecordArguments>
{
    public GetEmployeeRecordArgumentsValidator()
    {
        RuleFor(x => x.EmployeeId)
            .NotEmpty()
            .Matches("^[a-z0-9-]{1,64}$")
            .WithMessage("employeeId must be a simple lowercase identifier.");
    }
}

public sealed record SubmitLeaveRequestArguments(string StartDate, string EndDate, string LeaveType);

public sealed class SubmitLeaveRequestArgumentsValidator : AbstractValidator<SubmitLeaveRequestArguments>
{
    public static readonly string[] AllowedLeaveTypes = ["Vacation", "Sick", "Unpaid", "Bereavement", "Parental"];

    public SubmitLeaveRequestArgumentsValidator()
    {
        RuleFor(x => x.StartDate)
            .Must(BeAValidDate)
            .WithMessage("startDate must be an ISO 8601 date (YYYY-MM-DD).");

        RuleFor(x => x.EndDate)
            .Must(BeAValidDate)
            .WithMessage("endDate must be an ISO 8601 date (YYYY-MM-DD).");

        RuleFor(x => x.LeaveType)
            .Must(type => AllowedLeaveTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
            .WithMessage($"leaveType must be one of: {string.Join(", ", AllowedLeaveTypes)}.");

        RuleFor(x => x)
            .Must(HaveStartOnOrBeforeEnd)
            .WithMessage("startDate must not be after endDate.")
            .When(x => BeAValidDate(x.StartDate) && BeAValidDate(x.EndDate));
    }

    private static bool BeAValidDate(string value) => DateOnly.TryParse(value, out _);

    private static bool HaveStartOnOrBeforeEnd(SubmitLeaveRequestArguments arguments) =>
        DateOnly.Parse(arguments.StartDate) <= DateOnly.Parse(arguments.EndDate);
}
