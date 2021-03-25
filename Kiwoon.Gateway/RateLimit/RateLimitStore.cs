using System;
using System.Text;
using System.Threading.Tasks;
using Kiwoon.Gateway.Domain.RateLimit;
using Microsoft.Extensions.Caching.Distributed;

namespace Kiwoon.Gateway.RateLimit
{
    public class RateLimitStore : IRateLimitStore
    {
        private readonly IDistributedCache _cache;

        public RateLimitStore(IDistributedCache cache)
        {
            _cache = cache;
        }

        public async Task<int> GetRequestCountMin(string ip)
        {
            var attempt = int.TryParse(Encoding.UTF8.GetString(await _cache.GetAsync(ip + "min") ?? Array.Empty<byte>()), out var val);
            if (!attempt) throw new InvalidOperationException(nameof(RateLimitStore));
            return val;
        }

        public async Task<int> GetRequestCountHr(string ip)
        {
            var attempt = int.TryParse(Encoding.UTF8.GetString(await _cache.GetAsync(ip + "hr") ?? Array.Empty<byte>()), out var val);
            if (!attempt) throw new InvalidOperationException(nameof(RateLimitStore));
            return val;
        }

        public async Task<bool> IncrementRequestCount(string ip)
        {
            try
            {
                var minVal = int.TryParse(
                    Encoding.UTF8.GetString(await _cache.GetAsync(ip + "min") ?? Array.Empty<byte>()), out var minParse)
                    ? minParse
                    : 0;
                var hrVal = int.TryParse(
                    Encoding.UTF8.GetString(await _cache.GetAsync(ip + "hr") ?? Array.Empty<byte>()), out var hrParse)
                    ? hrParse
                    : 0;

                await _cache.SetAsync(ip + "min", Encoding.UTF8.GetBytes((minVal + 1).ToString()),
                    new(){AbsoluteExpiration = GetTimeOfMinExpiration()});
                await _cache.SetAsync(ip + "hr", Encoding.UTF8.GetBytes((hrVal + 1).ToString()), 
                    new(){AbsoluteExpiration = GetTimeOfHrExpiration()});
            }
            catch
            {
                return false;
            }

            return true;
        }

        public async Task ResetRequestCount(string ip)
        {
            await _cache.SetAsync(ip + "min", default);
            await _cache.SetAsync(ip + "hr", default);
        }

        public DateTime GetTimeOfHrExpiration() => DateTime.UtcNow.AddMinutes(60 - DateTime.UtcNow.Minute);
        public DateTime GetTimeOfMinExpiration() => DateTime.UtcNow.AddSeconds(60 - DateTime.UtcNow.Second);
    }
}
