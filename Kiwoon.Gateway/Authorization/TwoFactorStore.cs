using System;
using System.Text;
using System.Threading.Tasks;
using Kiwoon.Gateway.Domain.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using SharedModels.Domain;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Authorization
{
    public class TwoFactorStore : ITwoFactorStore
    {
        private readonly IServiceScopeFactory _factory;
        private readonly IDistributedCache _cache;

        public TwoFactorStore(IServiceScopeFactory factory, IDistributedCache cache)
        {
            _factory = factory;
            _cache = cache;
        }

        public async Task<bool> VerifyTwoFactorCodeAsync(ApplicationUser user, string code)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();
            var configuration = scope.GetNotNullService<IConfiguration>();

            user = await userManager.FindByIdAsync(await userManager.GetUserIdAsync(user));
            if (user == null) return false;

            if (!await userManager.GetTwoFactorEnabledAsync(user)) return false;

            var secret = KeyGeneration.DeriveKeyFromMaster(new InMemoryKey(Encoding.UTF8.GetBytes(configuration["TotpKey"])),
                Encoding.UTF8.GetBytes(await userManager.GetUserIdAsync(user)));

            var secretCode = new Totp(secret).ComputeTotp();

            if (await _cache.GetAsync(secretCode) != null)
                return false;
            var result = secretCode == code.Replace(" ", string.Empty).Replace("-", string.Empty);

            if (result)
            {
                var date = default(int);
                if (DateTime.UtcNow.Second > 30)
                    date = 61 - DateTime.UtcNow.Second;
                else
                    date = 31 - DateTime.UtcNow.Second;

                await _cache.SetAsync(secretCode, Encoding.UTF8.GetBytes("Used"), new(){AbsoluteExpiration = DateTime.UtcNow.AddSeconds(date)});
            }

            return result;
        }

        public async Task<byte[]> GetUserSecretAsync(ApplicationUser user)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();
            var configuration = scope.GetNotNullService<IConfiguration>();

            return KeyGeneration.DeriveKeyFromMaster(new InMemoryKey(Encoding.UTF8.GetBytes(configuration["TotpKey"])),
                Encoding.UTF8.GetBytes(await userManager.GetUserIdAsync(user)));
        }
    }
}
