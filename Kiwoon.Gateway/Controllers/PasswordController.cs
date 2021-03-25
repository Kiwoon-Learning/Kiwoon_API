using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Kiwoon.Gateway.Domain;
using Kiwoon.Gateway.Domain.Notifications;
using Kiwoon.Gateway.Domain.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SharedModels.Domain;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasswordController : ControllerBase
    {
        private readonly IBackgroundTaskQueue _queue;
        private readonly IServiceScopeFactory _factory;
        private readonly ILogger<PasswordController> _logger;

        public PasswordController(IBackgroundTaskQueue queue, IServiceScopeFactory factory,
            ILogger<PasswordController> logger)
        {
            _queue = queue;
            _factory = factory;
            _logger = logger;
        }
        [HttpPut]
        [Authorize]
        public IActionResult ChangePassword(string currentPass, string newPass)
        {
            if (currentPass == null || newPass == null) return Ok(new ApiResponse(false, 400,
                "Current password or new password cannot be empty"));
            if (currentPass == newPass) return Ok(new ApiResponse(false, 400, "Please choose a new password"));
            var id = GetUserId();
            if (id == null) return Ok(new ApiResponse(false, 500, "Could not find user id"));
            _queue.QueueBackgroundWorkItem(async (scope, token) =>
            {
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                if (userManager == null) throw new NullReferenceException(nameof(userManager));

                var user = await userManager.FindByIdAsync(id);
                if (user == null) return new ApiQueuedResponse(false, 404, id, "User not found");
                var result = await userManager.ChangePasswordAsync(user, currentPass, newPass);
                return new ApiQueuedResponse(result, id);
            });
            return Ok(new ApiResponse(true, 200, "Successfully sent request"));
        }
        [HttpPost]
        [Authorize]
        public IActionResult SetPassword(string password)
        {
            if (password == null) return Ok(new ApiResponse(false, 400, "Password cannot be empty"));

            var id = GetUserId();
            if (id == null) return Ok(new ApiResponse(false, 500, "Could not find user id"));

            _queue.QueueBackgroundWorkItem(async (scope, token) =>
            {
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                if (userManager == null) throw new NullReferenceException(nameof(userManager));

                var user = await userManager.FindByIdAsync(id);
                if (user == null) return new ApiQueuedResponse(false, 404, id, "Could not find user");
                if (user.PasswordHash != null) return new ApiQueuedResponse(false, 400, id, "User already has a password");

                var result = await userManager.AddPasswordAsync(user, password);
                return new ApiQueuedResponse(result, id);
            });

            return Ok(new ApiResponse(true, 200, "Successfully sent request"));
        }

        [HttpGet("forgot")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            if (email == null) return Ok(new ApiResponse(false, 400, "Email cannot be empty"));

            using var scope = _factory.CreateScope();

            UserManager<ApplicationUser> userMgr;
            try
            {
                userMgr = scope.GetNotNullService<UserManager<ApplicationUser>>();
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in ForgotPassword", this);
                return Ok(new ApiResponse(false, 500, "Error in finding user"));
            }

            var user = await userMgr.FindByEmailAsync(email);
            if (user == null) return Ok(new ApiResponse(false, 404, "User not found"));

            _queue.QueueBackgroundWorkItem(async (serviceScope, token) =>
            {
                var userManager = serviceScope.GetNotNullService<UserManager<ApplicationUser>>();
                var sender = serviceScope.GetNotNullService<IEmailSender>();
                var jwtStore = serviceScope.GetNotNullService<IJwtStore>();
                var configuration = serviceScope.GetNotNullService<IConfiguration>();

                var recoveryToken = await jwtStore.CreatePasswordRecoveryTokenAsync(user);

                var uri = $"http://{configuration["Host"]}/api/confirm/password";
                await sender.SendEmailAsync(await userManager.GetEmailAsync(user), "Password recovery", 
                    $"<form method='get' action='{uri}'> <input type='hidden' id='token' name='token' value='{recoveryToken}'/><label for='newPassword'>New Password:</label><br> <input id='newPassword' name='newPassword'/> <button type='submit'>Submit</button></form>"
                    );
                return new ApiQueuedResponse(true, 200, await userManager.GetUserIdAsync(user),
                    "Successfully sent password recovery email");
            });
            return Ok(new ApiResponse(true, 200, "Successfully sent request"));
        }

        public string GetUserId() => User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
    }
}
