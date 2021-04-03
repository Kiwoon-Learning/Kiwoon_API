using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace Kiwoon.Domain.Identity.Token
{
    public interface IExpiredTokenRepository
    {
        public Task<bool> IsBlacklistedTokenAsync(JwtSecurityToken token);
        public Task AddBlacklistedTokenAsync(JwtSecurityToken token);
        public Task<string> GetBlacklistedSecurityTokenAsync(string tokenSignature);
    }
}
