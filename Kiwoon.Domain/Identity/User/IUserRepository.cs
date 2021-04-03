using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace Kiwoon.Domain.Identity.User
{
    public interface IUserRepository : IGenericRepository<ApplicationIdentityResult, ApplicationUser>, IEmailSender
    {
        public Task<ApplicationIdentityResult> ConfirmEmailAsync(string token);
        public Task<ApplicationIdentityResult> SendConfirmEmailAsync(string email);
        public Task<ApplicationIdentityResult> ChangeEmailAsync(string oldEmail, string newEmail);
        public Task<ApplicationIdentityResult> SendPasswordRecoveryEmailAsync(string email);
        public Task<ApplicationIdentityResult> ConfirmChangePasswordAsync(string newPassword, string token);
        public Task<ApplicationIdentityResult> ChangeUserPasswordAsync(ApplicationUser user, string oldPassword, string newPassword);
        public Task<ApplicationIdentityResult> SetPasswordAsync(ApplicationUser user, string password);
        public Task<ApplicationIdentityResult> EnableTwoFactorAuthentication(ApplicationUser user);
        public Task<ApplicationIdentityResult> DisableTwoFactorAuthentication(ApplicationUser user);
        public Task<ApplicationIdentityResult> SendTwoFactorRecoveryEmailAsync(ApplicationUser user);
        public ApplicationIdentityResult ValidatePassword(ApplicationUser user, string password);
        public Task<ApplicationUser> FindByEmailAsync(string email);
        public Task<ApplicationUser> FindByIdAsync(string id);
        public Task<ApplicationUser> GetUserAsync(ClaimsPrincipal principal);
        public Task<ApplicationUser> GetUserFromTokenAsync(string token);

    }
}
