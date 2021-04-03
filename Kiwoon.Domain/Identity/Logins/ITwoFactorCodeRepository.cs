using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kiwoon.Domain.Identity.Logins
{
    public interface ITwoFactorCodeRepository
    {
        public Task<bool> VerifyTwoFactorCodeAsync(ApplicationUser user, string code);
        public Task<byte[]> GetUserSecretAsync(ApplicationUser user);
    }
}
