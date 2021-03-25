using System.Threading.Tasks;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Domain.User
{
    public interface ITwoFactorStore
    {
        public Task<bool> VerifyTwoFactorCodeAsync(ApplicationUser user, string code);
        public Task<byte[]> GetUserSecretAsync(ApplicationUser user);
    }
}
