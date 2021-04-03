using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Google.Apis.Auth;
using Kiwoon.Domain;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Logins;
using Kiwoon.Domain.Identity.Token;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using OtpNet;

namespace Kiwoon.Core.Authorization
{
    public class LoginRepository : ILoginRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ServiceBusClient _client;
        private readonly IDistributedCache _cache;
        private readonly IConfiguration _configuration;
        private readonly IJwtRepository _jwtRepo;

        public LoginRepository(UserManager<ApplicationUser> userManager, ServiceBusClient client,
            IDistributedCache cache, IConfiguration configuration, IJwtRepository jwtRepo)
        {
            _userManager = userManager;
            _client = client;
            _cache = cache;
            _configuration = configuration;
            _jwtRepo = jwtRepo;
        }
        public async Task<bool> VerifyTwoFactorCodeAsync(ApplicationUser twoFactorUser, string code)
        {

            var user = await _userManager.FindByIdAsync(twoFactorUser.Id);
            if (user == null) return false;

            if (!user.TwoFactorEnabled) return false;

            var secret = KeyGeneration.DeriveKeyFromMaster(
                new InMemoryKey(Encoding.UTF8.GetBytes(_configuration!["TotpKey"])),
                Encoding.UTF8.GetBytes(user.Id));

            var secretCode = new Totp(secret).ComputeTotp();

            if (await _cache!.GetAsync(secretCode) != null)
                return false;

            var result = secretCode == code.Replace(" ", string.Empty).Replace("-", string.Empty);

            if (result)
            {
                int date;
                if (DateTime.UtcNow.Second > 30)
                    date = 61 - DateTime.UtcNow.Second;
                else
                    date = 31 - DateTime.UtcNow.Second;

                await _cache.SetAsync(secretCode, Encoding.UTF8.GetBytes("Used"),
                    new() { AbsoluteExpiration = DateTime.UtcNow.AddSeconds(date) });
            }

            return result;
        }

        public Task<byte[]> GetUserSecretAsync(ApplicationUser user)
        {
            return Task.FromResult(KeyGeneration.DeriveKeyFromMaster(new InMemoryKey(Encoding.UTF8.GetBytes(_configuration["TotpKey"])),
                Encoding.UTF8.GetBytes(user.Id)));
        }

        public async Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey)
        {
            return await _userManager.FindByLoginAsync(loginProvider, providerKey);
        }

        public async Task<ApplicationIdentityResult> AddLoginAsync(ApplicationUser user, string loginProvider, string providerKey)
        {
            if ((await GetLoginsForUserAsync(user)).Any(x => x.LoginProvider == loginProvider))
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "LoginExists", 
                    Description = $"{loginProvider} login already exists"
                });

            await SendRequestAsync("AddUserLogin",
                new LoginRequest
                {
                    User = user,
                    LoginProvider = loginProvider, 
                    ProviderKey = providerKey
                });

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> RemoveLoginAsync([Required] ApplicationUser user, 
            [Required] string loginProvider, [Required] string providerKey)
        {
            var loginUser = await _userManager.FindByLoginAsync(loginProvider, providerKey);
            if (loginUser.Id != user.Id)
                return IdentityResult.Failed(new IdentityError
                    {Code = "BadLogin", Description = "User does not hold this specified login"});

            await SendRequestAsync("RemoveUserLogin", new LoginRequest
            {
                LoginProvider = loginProvider, 
                ProviderKey = providerKey, 
                User = user
            });

            return IdentityResult.Success;
        }

        public async Task<IList<UserLoginInfo>> GetLoginsForUserAsync([Required] ApplicationUser user)
        {
            return await _userManager.GetLoginsAsync(user);
        }

        public async Task<ApplicationIdentityResult> PasswordLogin([Required] string username,[Required] string password,
            bool rememberMe = false, string rememberMeToken = "", int twoFactorCode = 0)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return IdentityResult.Failed(new IdentityError
                    {Code = "UserNotFound", Description = "User not found or incorrect password"});

            var result = await _userManager.CheckPasswordAsync(user, password);
            if (!result)
                return IdentityResult.Failed(new IdentityError
                    { Code = "UserNotFound", Description = "User not found or incorrect password" });

            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                if (!string.IsNullOrWhiteSpace(rememberMeToken))
                {
                    var rememberMeResult = await _jwtRepo.ValidateTwoFactorRememberMeTokenAsync(user, rememberMeToken);
                    if(rememberMeResult)
                        return new ApplicationIdentityResult(true, await _jwtRepo.CreateTokenAsync(user));
                }

                if (twoFactorCode == 0 || !await VerifyTwoFactorCodeAsync(user, twoFactorCode.ToString()))
                    return IdentityResult.Failed(new IdentityError
                    {
                        Code = "BadTwoFactorCode",
                        Description = "Incorrect two-factor code"
                    });
                if (rememberMe)
                    return new ApplicationIdentityResult(true, $"login-{await _jwtRepo.CreateTokenAsync(user)}", 
                        $"rememberMe-{await _jwtRepo.CreateTwoFactorRememberMeTokenAsync(user)}");
            }

            return new ApplicationIdentityResult(true, await _jwtRepo.CreateTokenAsync(user));
        }

        public async Task<ApplicationIdentityResult> GoogleLogin([Required] string googleToken)
        {
            GoogleJsonWebSignature.Payload payload;
            try
            {
                payload = await GoogleJsonWebSignature.ValidateAsync(googleToken);
            }
            catch (InvalidJwtException)
            {
                // Invalid Google token
                return IdentityResult.Failed(new IdentityError
                    {Code = "BadToken", Description = "Invalid Google token"});
            }

            var user = await FindByLoginAsync("Google", payload.Subject);
            if (user != null)
                return new ApplicationIdentityResult(true, await _jwtRepo.CreateTokenAsync(user));

            user = new ApplicationUser
                { Email = payload.Email, EmailConfirmed = true, UserName = payload.Email };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded) return result;

            var addLoginResult = await AddLoginAsync(user, "Google", payload.Subject);

            if (!addLoginResult.Succeeded) return addLoginResult;

            return new ApplicationIdentityResult(true, await _jwtRepo.CreateTokenAsync(user));
        }

        private async Task SendRequestAsync(string queueName, BusRequest request,
            CancellationToken cancellationToken = default)
        {
            await using var sender = _client.CreateSender(queueName);
            var input = JsonSerializer.SerializeToUtf8Bytes(request, request.GetType());
            await sender.SendMessageAsync(new ServiceBusMessage(input), cancellationToken);
        }
    }
}
