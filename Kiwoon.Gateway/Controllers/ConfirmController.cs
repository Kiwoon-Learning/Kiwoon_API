using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Kiwoon.Gateway.Domain;
using Kiwoon.Gateway.Domain.Notifications;
using Kiwoon.Gateway.Domain.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SharedModels.Domain;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ConfirmController : ControllerBase
    {
        private readonly IBackgroundTaskQueue _queue;
        private readonly IServiceScopeFactory _factory;

        public ConfirmController(IBackgroundTaskQueue queue, IServiceScopeFactory factory)
        {
            _queue = queue;
            _factory = factory;
        }
        [HttpGet("email")]
        //TODO: Send user to normal website, not api, for confirmation
        public async Task<IActionResult> ConfirmEmail(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return Ok(new ApiResponse(false, 500, "Token cannot be empty"));
            token = HttpUtility.UrlDecode(token);


            using var scope = _factory.CreateScope();
            var userMgr = scope.GetNotNullService<UserManager<ApplicationUser>>();
            var jwtStore = scope.GetNotNullService<IJwtStore>();

            var id = 
                new JwtSecurityToken(token).Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value ?? "";

            var user = await userMgr.FindByIdAsync(id);
            if (user == null || await userMgr.IsEmailConfirmedAsync(user))
                return Ok(new ApiResponse(false, 401, "There was an issue verifying the email"));


            var result = await jwtStore.ValidateEmailConfirmationTokenAsync(user, token);
            if (result)
            {
                _queue.QueueBackgroundWorkItem(async (serviceScope, stoppingToken) =>
                {
                    var userManager = serviceScope.GetNotNullService<UserManager<ApplicationUser>>();

                    user.EmailConfirmed = true;
                    var confirmResult = await userManager.UpdateAsync(user);
                    return new ApiQueuedResponse(confirmResult, id);
                });
            }
            return Ok(!result 
                ? new ApiResponse(false, 401, "There was an issue verifying the email") 
                : new ApiResponse(true, 200, "Successfully confirmed email"));
        }

        [HttpPost("email")]
        [Authorize]
        public IActionResult ResendConfirmEmail()
        {
            var id = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value ?? "";
            if (string.IsNullOrWhiteSpace(id)) return Ok(new ApiResponse(false, 500, "Could not find user id"));

            _queue.QueueBackgroundWorkItem(async (scope, stoppingToken) =>
            {
                var userMgr = scope.GetNotNullService<UserManager<ApplicationUser>>();
                var jwtStore = scope.GetNotNullService<IJwtStore>();

                var user = await userMgr.FindByIdAsync(id);
                if (user == null) return new ApiQueuedResponse(false, 500, id, "Could not find user from id");
                if (await userMgr.IsEmailConfirmedAsync(user))
                    return new ApiQueuedResponse(false, 400, id, "Email is already confirmed");

                var token = await jwtStore.CreateEmailConfirmationTokenAsync(user);

                var emailSender = scope.GetNotNullService<IEmailSender>();
                var configuration = scope.GetNotNullService<IConfiguration>();
                
                await emailSender.SendEmailAsync(await userMgr.GetEmailAsync(user), "Confirmation email resend", 
                    $"Click <a href=\"http://{configuration["Host"]}/api/confirm/email?token={HttpUtility.UrlEncode(token)}\">here</a> to confirm your email");

                return new ApiQueuedResponse(true, 200, id, "Successfully re-sent confirmation");
            });
            return Ok(new ApiResponse(true, 200, "Successfully sent request"));
        }

        [HttpGet("password")]
        public async Task<IActionResult> ConfirmResetPassword(string newPassword, string token)
        {
            using var scope = _factory.CreateScope();

            var id =
                new JwtSecurityToken(token).Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value;
            if (id == null) return Ok(new ApiResponse(false, 400, "Could not get id from token"));

            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var jwtStore = scope.ServiceProvider.GetService<IJwtStore>();
            if (userManager == null || jwtStore == null) return Ok(new ApiResponse(false, 500, "Could not find user"));

            var user = await userManager.FindByIdAsync(id);
            if (user == null) return Ok(new ApiResponse(false,500, "Could not find user"));

            if(userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, newPassword) == PasswordVerificationResult.Success)
                return Ok(new ApiResponse(false, 400, "Please choose a new password"));

            if (await jwtStore.ValidatePasswordRecoveryTokenAsync(user, token))
            {
                _queue.QueueBackgroundWorkItem(async (serviceScope, stoppingToken) =>
                {
                    var userMgr = serviceScope.GetNotNullService<UserManager<ApplicationUser>>();

                    user.PasswordHash = userMgr.PasswordHasher.HashPassword(user, newPassword);
                    await userMgr.UpdateAsync(user);
                    return new ApiQueuedResponse(true, 200, id, "Successfully changed password");
                });
                return Ok(new ApiResponse(true, 200, "Successfully changed password"));
            }

            return Ok(new ApiResponse(false, 403, "Could not change password with specified token"));
        }

        [HttpGet("2fa")]
        public async Task<IActionResult> ConfirmTwoFactorReset(string recoveryToken)
        {
            if (recoveryToken == null) return Ok(new ApiResponse(false, 400, "Recovery token cannot be empty"));

            var token = default(JwtSecurityToken);
            try
            {
                token = new JwtSecurityToken(recoveryToken);
            }
            catch
            {
                return Ok(new ApiResponse(false, 401, "Token is invalid"));
            }


            bool result;
            string id;

            using (var scope = _factory.CreateScope())
            {
                var store = scope.ServiceProvider.GetService<IJwtStore>();
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                if (store == null || userManager == null) return Ok(new ApiResponse(false, 500, "Could not validate token"));

                id = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
                if (string.IsNullOrWhiteSpace(id)) return Ok(new ApiResponse(false, 400, "Could not find user id"));

                var user = await userManager.FindByIdAsync(id);
                if(user == null) return Ok(new ApiResponse(false, 400, "Could not find user"));

                result = await store.ValidateTwoFactorRecoveryTokenAsync(user, recoveryToken);
            }

            if (!result)
                return Ok(new ApiResponse(false, 401, "Token is invalid"));

            _queue.QueueBackgroundWorkItem(async (scope, stoppingToken) =>
            {
                var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();

                var user = await userManager.FindByIdAsync(id);
                if (user == null) return new ApiQueuedResponse(false, 404, id, "User not found");

                return new ApiQueuedResponse(await userManager.SetTwoFactorEnabledAsync(user, false), id);
            });

            return Ok(new ApiResponse(true, 200, "Successfully disabled 2fa"));
        }
    }
}
