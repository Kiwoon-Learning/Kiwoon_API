using System.Threading.Tasks;

namespace Kiwoon.Domain.Identity.Token
{
    public interface ITwoFactorTokenRepository
    {
        public Task<string> CreateTwoFactorRecoveryTokenAsync(ApplicationUser user);
        public Task<string> CreateTwoFactorRememberMeTokenAsync(ApplicationUser user);

        public Task<bool> ValidateTwoFactorRecoveryTokenAsync(ApplicationUser user, string token);
        public Task<bool> ValidateTwoFactorRememberMeTokenAsync(ApplicationUser user, string token);
    }
}
