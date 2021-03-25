using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Domain.User
{
    public interface IJwtStore
    {
        public Task<string> CreateTokenAsync(ApplicationUser user);
        public Task<string> CreateEmailConfirmationTokenAsync(ApplicationUser user);
        public Task<string> CreatePasswordRecoveryTokenAsync(ApplicationUser user);
        public Task<string> CreateTwoFactorRecoveryTokenAsync(ApplicationUser user);
        public Task<string> CreateTwoFactorRememberMeTokenAsync(ApplicationUser user);
        public Task<bool> ValidateEmailConfirmationTokenAsync(ApplicationUser user, string token);
        public Task<bool> ValidatePasswordRecoveryTokenAsync(ApplicationUser user, string token);
        public Task<bool> ValidateTwoFactorRecoveryTokenAsync(ApplicationUser user, string token);
        public Task<bool> ValidateTwoFactorRememberMeTokenAsync(ApplicationUser user, string token);
        public TokenValidationParameters GetValidationParameters();
    }
}
