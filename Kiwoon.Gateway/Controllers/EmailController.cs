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
using Microsoft.Extensions.DependencyInjection;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmailController : ControllerBase
    {
        private readonly IServiceScopeFactory _factory;
        private readonly IBackgroundTaskQueue _queue;

        public EmailController(IServiceScopeFactory factory, IBackgroundTaskQueue queue)
        {
            _factory = factory;
            _queue = queue;
        }
        [HttpGet]
        public async Task<IActionResult> FindByEmail(string email)
        {
            if (email == null) return Ok(new ApiResponse(false, 400, "Email cannot be empty"));
            using var scope = _factory.CreateScope();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            if (userManager == null) return Ok(new ApiResponse(false, 500, "Could not find user"));

            var user = await userManager.FindByEmailAsync(email);
            return user == null ? Ok(new ApiResponse(false, 404, "User not found")) 
                : Ok(new ApiResponse(true, 200, new ApplicationUserDto(user)));
        }

        [HttpPut, Authorize]
        public IActionResult ChangeEmail(string email, string newEmail)
        {
            if (email == null || newEmail == null) 
                return Ok(new ApiResponse(false, 400, "Email or newEmail cannot be empty"));
            if (string.Equals(email, newEmail, StringComparison.InvariantCultureIgnoreCase))
                return Ok(new ApiResponse(false, 400, "Please choose a new email"));

            var id = GetUserId();
            _queue.QueueBackgroundWorkItem(async (scope, token) =>
            {
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                if (userManager == null) return new ApiQueuedResponse(false, 500, id, "Could not change email");
                var user = await userManager.FindByEmailAsync(email);

                if (user == null) return new ApiQueuedResponse(false, 404, id, $"User not found from email {email}");

                if (await userManager.GetUserIdAsync(user) != id)
                    return new ApiQueuedResponse(false, 404, id, "Incorrect email");

                if (!string.Equals(email, await userManager.GetEmailAsync(user), StringComparison.InvariantCultureIgnoreCase))
                    return new ApiQueuedResponse(false, 403, "Incorrect email");

                var result = await userManager.SetEmailAsync(user, newEmail);
                if (!result.Succeeded) return new ApiQueuedResponse(result, id);

                user.EmailConfirmed = false;
                result = await userManager.UpdateAsync(user);

                if (!result.Succeeded) return new ApiQueuedResponse(result, id);

                result = await userManager.SetUserNameAsync(user, newEmail);
                return new ApiQueuedResponse(result, id);
            });
            return Ok(new ApiResponse(true, 200, "Successfully sent request"));
        }
        [HttpGet("confirm"), Authorize]
        public IActionResult ConfirmEmail(string token)
        {
            if (token == null)
                return Ok(new ApiResponse(false, 400, "Token cannot be empty"));
            var id = GetUserId();
            if (id == null) return Ok(new ApiResponse(false, 401, "Could not find user id"));
            _queue.QueueBackgroundWorkItem(async (scope, cancellationToken) =>
            {
                var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                if (userManager == null) throw new NullReferenceException(nameof(userManager));

                var user = await userManager.FindByIdAsync(id);
                if (user == null) return new ApiQueuedResponse(false, 400, id, "Could not confirm the specified email");
                var result = await userManager.ConfirmEmailAsync(user, token);
                return new ApiQueuedResponse(result, id);
            });
            return Ok(new ApiQueuedResponse(true, 200, id, "Successfully sent request."));
        }

        public string GetUserId() => User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    }
}
