using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Kiwoon.Domain.Identity.Logins
{
    public interface ILoginRepository : ITwoFactorCodeRepository
    {
        public Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey);

        public Task<ApplicationIdentityResult> AddLoginAsync(ApplicationUser user, string loginProvider,
            string providerKey);

        public Task<ApplicationIdentityResult> RemoveLoginAsync(ApplicationUser user, string loginProvider,
            string providerKey);

        public Task<IList<UserLoginInfo>> GetLoginsForUserAsync(ApplicationUser user);

        public Task<ApplicationIdentityResult> PasswordLogin(string username, string password, bool rememberMe = false,
            string rememberMeToken = "", int twoFactorCode = 0);

        public Task<ApplicationIdentityResult> GoogleLogin(string googleToken);
    }
}
