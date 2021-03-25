using System;
using System.Threading.Tasks;

namespace Kiwoon.Gateway.Domain.RateLimit
{
    public interface IRateLimitStore
    {
        public Task<int> GetRequestCountMin(string ip);
        public Task<int> GetRequestCountHr(string ip);
        public Task<bool> IncrementRequestCount(string ip);
        public Task ResetRequestCount(string ip);
        public DateTime GetTimeOfHrExpiration();
        public DateTime GetTimeOfMinExpiration();
    }
}
