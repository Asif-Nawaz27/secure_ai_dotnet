using System.Collections.Concurrent;

namespace ContosoHR.Api.Abuse;

/// <summary>
/// R7: a per-user, per-calendar-month token budget enforced BEFORE the provider
/// call — not after, which would mean the money is already spent by the time you
/// notice. <see cref="TryConsume"/> reserves the estimated tokens for the request
/// up front; callers that end up using fewer tokens than estimated simply leave
/// some budget unused, which is the conservative direction to be wrong in.
/// </summary>
public interface ITokenBudgetStore
{
    bool TryConsume(string userId, int estimatedTokens, out int remainingTokens);
}

public sealed class InMemoryMonthlyTokenBudgetStore(int monthlyTokenCap = 200_000) : ITokenBudgetStore
{
    private readonly ConcurrentDictionary<(string UserId, string Month), int> _usage = new();

    public bool TryConsume(string userId, int estimatedTokens, out int remainingTokens)
    {
        var key = (userId, DateTime.UtcNow.ToString("yyyy-MM"));
        var updated = _usage.AddOrUpdate(key, estimatedTokens, (_, existing) => existing + estimatedTokens);

        if (updated > monthlyTokenCap)
        {
            _usage.AddOrUpdate(key, 0, (_, existing) => Math.Max(0, existing - estimatedTokens));
            remainingTokens = Math.Max(0, monthlyTokenCap - (updated - estimatedTokens));
            return false;
        }

        remainingTokens = monthlyTokenCap - updated;
        return true;
    }
}
