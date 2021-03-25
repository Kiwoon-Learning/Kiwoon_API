using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace Kiwoon.Gateway.Domain
{
    public interface IExpiredTokenStore
    {
        public Task<bool> IsBlacklistedTokenAsync(JwtSecurityToken token);
        public Task AddBlacklistedTokenAsync(JwtSecurityToken token);
    }
}
