using System.Threading.Tasks;

namespace Kiwoon.Domain.Identity.Token
{
    public interface IJwtRepository : IExpiredTokenRepository, ITwoFactorTokenRepository
    {
        public Task<string> CreateTokenAsync(ApplicationUser user);
        public Task<string> CreateEmailConfirmationTokenAsync(ApplicationUser user);
        public Task<string> CreatePasswordRecoveryTokenAsync(ApplicationUser user);

        public Task<bool> ValidateTokenAsync(ApplicationUser user, string token);
    }
}
