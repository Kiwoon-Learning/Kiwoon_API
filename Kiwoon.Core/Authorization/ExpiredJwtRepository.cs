using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity.Token;
using Microsoft.Extensions.Caching.Distributed;

namespace Kiwoon.Core.Authorization
{
    public class ExpiredJwtRepository : IExpiredTokenRepository
    {
        private readonly IDistributedCache _cache;

        public ExpiredJwtRepository(IDistributedCache cache)
        {
            _cache = cache;
        }

        public async Task<bool> IsBlacklistedTokenAsync(JwtSecurityToken token)
        {
            return await _cache.GetAsync(token.RawSignature) != null;
        }

        public async Task AddBlacklistedTokenAsync(JwtSecurityToken token)
        {
            await _cache.SetStringAsync(token.RawSignature, "Blacklist",
                new DistributedCacheEntryOptions { AbsoluteExpiration = token.ValidTo });
        }

        public async Task<string> GetBlacklistedSecurityTokenAsync(string tokenSignature)
        {
            return Encoding.UTF8.GetString(await _cache.GetAsync(tokenSignature));
        }
    }
}
