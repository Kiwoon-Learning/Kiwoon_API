using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Kiwoon.Gateway.Domain;
using Microsoft.Extensions.Caching.Distributed;

namespace Kiwoon.Gateway.Authorization
{
    public class ExpiredTokenStore : IExpiredTokenStore
    {
        private readonly IDistributedCache _cache;

        public ExpiredTokenStore()
        {
            
        }

        public ExpiredTokenStore(IDistributedCache cache)
        {
            _cache = cache;
        }
        public async Task<bool> IsBlacklistedTokenAsync(JwtSecurityToken token)
        {
            return await _cache.GetAsync(token.RawSignature) != null;
        }

        public async Task AddBlacklistedTokenAsync(JwtSecurityToken token)
        {
            await _cache.SetStringAsync(token.RawSignature, "Blacklist", new DistributedCacheEntryOptions { AbsoluteExpiration = token.ValidTo });
        }
    }
}
