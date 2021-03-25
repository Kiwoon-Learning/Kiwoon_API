using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Threading.Tasks;
using Google.Apis.Auth;
using Kiwoon.Gateway.Domain;
using Kiwoon.Gateway.Domain.Notifications;
using Kiwoon.Gateway.Domain.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IBackgroundTaskQueue _queue;
        private readonly IServiceScopeFactory _factory;

        public LoginController(IBackgroundTaskQueue queue, IServiceScopeFactory factory)
        {
            _queue = queue;
            _factory = factory;
        }
        [HttpGet, Authorize]
        public IActionResult CheckAuth(string policy)
        {
            if (policy == null) return Ok(new ApiResponse(true, 200, "User found"));
            var id = GetUserId();
            if (id == null) return Ok(new ApiResponse(false, 500, "Could not find user id"));

            _queue.QueueBackgroundWorkItem(async (scope, token) =>
            {
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                if (userManager == null) throw new NullReferenceException(nameof(userManager));

                var user = await userManager.FindByIdAsync(id);
                if (user == null) return new ApiQueuedResponse(false, 404, id, "User not found");
                var claims = from claim in await userManager.GetClaimsAsync(user)
                    select string.Equals(claim.Type, policy, StringComparison.InvariantCultureIgnoreCase)
                        ? claim
                        : null;
                return !claims.Any() ? new ApiQueuedResponse(false, 403, id, $"User found but not in policy '{policy}'") : new ApiQueuedResponse(true, 200, id, $"User found and in policy '{policy}");
            });

            return Ok(new ApiResponse(true, 200, "Successfully sent request"));
        }

        [HttpGet("password")]
        public async Task<IActionResult> PasswordLogin(string userName, string password)
        {
            if (userName == null || password == null) return Ok(new ApiResponse(false, 400, "Username or password cannot be empty"));

            using var scope = _factory.CreateScope();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var jwtStore = scope.ServiceProvider.GetService<IJwtStore>();
            if (jwtStore == null || userManager == null) return Ok(new ApiResponse(false, 500, "Could not login user"));

            var user = await userManager.FindByNameAsync(userName);
            if (user == null) return Ok(new ApiResponse(false, 404, "Incorrect username or password"));
            var result = await userManager.CheckPasswordAsync(user, password);
            if (result)
            {
                if (await userManager.GetTwoFactorEnabledAsync(user))
                    return Ok(new ApiResponse(true, 403, "Two factor authentication required"));
            }
            return Ok(!result ? new ApiResponse(false, 404, "Incorrect username or password") : new ApiResponse(true, 200, await jwtStore.CreateTokenAsync(user)));
        }
        [HttpGet("twoFactorPassword")]
        public async Task<IActionResult> TwoFactorLogin(string userName, string password,
            string code, bool rememberMe = false, string rememberMeToken = null)
        {
            if (userName == null || password == null) return Ok(new ApiResponse(false, 400, "Username or password cannot be empty"));

            if ((code == null && rememberMeToken == null) || (code != null && rememberMeToken != null))
                return Ok(new ApiResponse(false, 400, "Code or rememberMe token must be supplied"));

            using var scope = _factory.CreateScope();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var store = scope.ServiceProvider.GetService<ITwoFactorStore>();
            var jwtStore = scope.ServiceProvider.GetService<IJwtStore>();

            if (store == null || userManager == null || jwtStore == null) 
                return Ok(new ApiResponse(false, 500, "Could not login user"));

            var user = await userManager.FindByNameAsync(userName);
            if (user == null) return Ok(new ApiResponse(false, 404, "Incorrect username or password"));

            var result = await userManager.CheckPasswordAsync(user, password);
            if (result)
            {
                if (!await userManager.GetTwoFactorEnabledAsync(user))
                    return Ok(new ApiResponse(false, 400, "User does not have 2FA enabled"));

                if (rememberMeToken != null)
                {
                    if (await jwtStore.ValidateTwoFactorRememberMeTokenAsync(user, rememberMeToken))
                    {
                        return Ok(new ApiResponse(true, 200, await jwtStore.CreateTokenAsync(user)));
                    }

                    return Ok(new ApiResponse(false, 401, "Supplied rememberMe token is incorrect"));
                }
                
                var tfaResult = await store.VerifyTwoFactorCodeAsync(user, code);

                if (!tfaResult)
                    return Ok(new ApiResponse(false, 403, "Incorrect Two-Factor code"));

                if (rememberMe)
                {
                    var remember2FaToken = await jwtStore.CreateTwoFactorRememberMeTokenAsync(user);
                    return Ok(new ApiResponse(true, 200, new { loginToken = await jwtStore.CreateTokenAsync(user) },
                        new { rememberMeToken = remember2FaToken }));
                }

                return Ok(new ApiResponse(true, 200, await jwtStore.CreateTokenAsync(user)));

            }
            return Ok(new ApiResponse(false, 404, "Incorrect username or password"));
        }

        [HttpGet("google")]
        public async Task<IActionResult> GoogleLogin(string securityToken)
        {
            if (securityToken == null) return Ok(new ApiResponse(false, 400, "Token cannot be null"));
            GoogleJsonWebSignature.Payload payload;
            try
            {
                payload = await GoogleJsonWebSignature.ValidateAsync(securityToken);
            }
            catch(InvalidJwtException)
            {
                // Invalid token
                return Ok(new ApiResponse(false, 403, "Google token is invalid"));
            }

            using var scope = _factory.CreateScope();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var jwtStore = scope.ServiceProvider.GetService<IJwtStore>();
            if (userManager == null || jwtStore == null) 
                return Ok(new ApiResponse(false, 500, "Could not login user"));

            var user = await userManager.FindByLoginAsync("Google", payload.Subject);
            if (user != null)
                return Ok(new ApiResponse(true, 200, await jwtStore.CreateTokenAsync(user)));

            user = new ApplicationUser {Email = payload.Email, EmailConfirmed = payload.EmailVerified, UserName = payload.Email};
            var result = await userManager.CreateAsync(user);

            if (!result.Succeeded) return Ok(new ApiResponse(result));

            result = await userManager.AddLoginAsync(user, new UserLoginInfo("Google", payload.Subject,
                await userManager.GetUserNameAsync(user)));
            return Ok(!result.Succeeded ? new ApiResponse(result) : new ApiResponse(true, 200, await jwtStore.CreateTokenAsync(user)));
        }

        public string GetUserId() => User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    }
}
