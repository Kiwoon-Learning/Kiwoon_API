using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using Kiwoon.Gateway.Domain;
using Kiwoon.Gateway.Domain.Notifications;
using Kiwoon.Gateway.Domain.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.Configuration;
using SharedModels.Domain.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using OtpNet;
using SharedModels.Domain;

namespace Kiwoon.Gateway.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IBackgroundTaskQueue _queue;
        private readonly IServiceScopeFactory _factory;

        public UserController(IBackgroundTaskQueue queue, IServiceScopeFactory factory)
        {
            _queue = queue;
            _factory = factory;
        }

        [HttpGet]
        [Authorize]
        public IActionResult GetUserFromToken()
        {
            var id = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            if (id == null) return Ok(new ApiResponse(false, 400, "Could not find user id"));

            _queue.QueueBackgroundWorkItem(async (scope, token) =>
            {
                var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();

                var user = await userManager.FindByIdAsync(id);
                return user == null ? new ApiQueuedResponse(false, 404, id, "User not found") : new ApiQueuedResponse(true, 200, 
                    id, new ApplicationUserDto(user));
            });
            return Ok(new ApiResponse(true, 200, "Sent request successfully."));
        }

        
        [HttpGet("receive"), Authorize]
        public async Task<IActionResult> ReceiveMessage()
        {
            var token = Request.Headers[HeaderNames.Authorization].ToString();

            var connection = new HubConnectionBuilder()
                .WithUrl("http://localhost:8888/notificationHub",
                    options =>
                    {
                        options.Headers.Add(HeaderNames.Authorization, token);
                    })
                .Build();
            var apiResponse = default(ApiResponse);
            connection.On<string>("ReceiveMessage", response =>
            {
                apiResponse = JsonSerializer.Deserialize<ApiResponse>(response);
            });
            await connection.StartAsync();
            while (apiResponse == default)
            {
                await Task.Delay(1000);
            }
            return Ok(apiResponse);
        }
        

        [HttpGet("refresh")]
        [Authorize]
        public async Task<IActionResult> RefreshToken()
        {
            //TODO: Expire tokens, ensure null check of users, 2fa recovery code
            using var scope = _factory.CreateScope();
            var store = scope.ServiceProvider.GetService<IJwtStore>();
            var expireStore = scope.ServiceProvider.GetService<IExpiredTokenStore>();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();

            if (store == null || userManager == null || expireStore == null) 
                return Ok(new ApiResponse(false, 500, "Could not generate new token"));

            var id = userManager.GetUserId(User);
            if (id == null) return Ok(new ApiResponse(false, 400, "Could not find user id"));

            var user = await userManager.FindByIdAsync(id);
            if (user == null) return Ok(new ApiResponse(false, 500, "Could not find user from id"));

            var token = await store.CreateTokenAsync(user);
            if (token == null) return Ok(new ApiResponse(false, 500, "Could not generate new token"));

            var oldToken = Request.Headers[HeaderNames.Authorization];
            var tryParse = AuthenticationHeaderValue.TryParse(token, out var jwt);
            if (jwt == null || !tryParse)
                return Ok(new ApiResponse(false, 400, "Could not retrieve token"));

            await expireStore.AddBlacklistedTokenAsync(new JwtSecurityToken(jwt.Parameter));
            return Ok(new ApiResponse(true, 200, token));
        }

        [HttpPost]
        public async Task<IActionResult> CreateNewUser(string email, string password)
        {
            if (email == null) return Ok(new ApiResponse(false, 400, "Email cannot be empty"));
            if (password == null) return Ok(new ApiResponse(false, 400, "Password cannot be empty"));
            var user = new ApplicationUser { UserName = email, Email = email };
            using var scope = _factory.CreateScope();

            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            if (userManager == null) return Ok(new ApiResponse(false, 500, "Could not create user."));

            var result = await userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                _queue.QueueBackgroundWorkItem(async (serviceScope, stoppingToken) =>
                {
                    var userMgr = serviceScope.GetNotNullService<UserManager<ApplicationUser>>();
                    var sender = serviceScope.GetNotNullService<IEmailSender>();
                    var configuration = serviceScope.GetNotNullService<IConfiguration>();
                    var jwtStore = serviceScope.GetNotNullService<IJwtStore>();

                    var claimResult = await userMgr.AddClaimAsync(user, new Claim("subscription", "Early access"));
                    var token = await jwtStore.CreateEmailConfirmationTokenAsync(user);
                    var id = (await userMgr.FindByEmailAsync(user.Email)).Id;

                    await sender.SendEmailAsync(await userMgr.GetEmailAsync(user), "Confirmation email",
                        $"Click <a href=\"http://{configuration["Host"]}/api/confirm/email?token={HttpUtility.UrlEncode(token)}\">here</a> to confirm your email");

                    return new ApiQueuedResponse(claimResult, id);
                });
            }
            return Ok(new ApiResponse(result));
        }
        [HttpDelete]
        [Authorize]
        public async Task<IActionResult> DeleteUser(string password)
        {
            if (password == null) return Ok(new ApiResponse(false, 400, "Password cannot be empty"));

            var scope = _factory.CreateScope();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var store = scope.ServiceProvider.GetService<IExpiredTokenStore>();
            if (userManager == null || store == null) 
                return Ok(new ApiResponse(false, 500, "Could not delete user"));

            var id =  userManager.GetUserId(User);
            if(id == null) return Ok(new ApiResponse(false, 404, "Id not found"));

            var user = await userManager.FindByIdAsync(id);
            if (user == null) return Ok(new ApiResponse(false, 404, "User not found"));

            if (!await userManager.CheckPasswordAsync(user, password)) return Ok(new ApiResponse(false, 403, "Incorrect password"));

            var result = await userManager.DeleteAsync(user);

            if (result.Succeeded)
            {
                var token = Request.Headers[HeaderNames.Authorization];
                var tryParse = AuthenticationHeaderValue.TryParse(token, out var jwt);
                if (jwt == null || !tryParse) return Ok(new ApiResponse(false, 400, "Could not retrieve token"));

                var jwtToken = new JwtSecurityToken(jwt.Parameter);

                await store.AddBlacklistedTokenAsync(jwtToken);
            }
            return Ok(new ApiResponse(result));
        }

        [HttpGet("id/{id}")]
        public async Task<IActionResult> GetUserById([FromRoute]string id)
        {
            if (id == null) return Ok(new ApiResponse(false, 400, "Id cannot be empty"));

            var scope = _factory.CreateScope();
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            if (userManager == null) throw new NullReferenceException(nameof(userManager));

            var user = await userManager.FindByIdAsync(id);
            return Ok(user == null ? new ApiResponse(false, 404, $"No user found under id '{id}'")
                : new ApiResponse(true, 200, new ApplicationUserDto(user)));
        }
        
        [HttpPost("2fa")]
        [Authorize]
        public async Task<IActionResult> EnableTwoFactorAuthentication()
        {
            using var scope = _factory.CreateScope();

            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var store = scope.ServiceProvider.GetService<ITwoFactorStore>();
            if (userManager == null || store == null) 
                return Ok(new ApiResponse(false, 500, "Could not find user"));

            var id = userManager.GetUserId(User);
            if(id == null) return Ok(new ApiResponse(false, 400, "Could not find user id"));

            var user = await userManager.FindByIdAsync(id);
            if (user == null) return Ok(new ApiResponse(false, 400, "Could not find user"));

            if (await userManager.GetTwoFactorEnabledAsync(user))
                return Ok(new ApiResponse(false, 400, "User already has 2Fa enabled"));

            var secret = await store.GetUserSecretAsync(user);

            _queue.QueueBackgroundWorkItem(async (serviceScope, token) =>
            {
                var userMgr = serviceScope.GetNotNullService<UserManager<ApplicationUser>>();

                var twoFactorUser = await userMgr.FindByIdAsync(id);
                if (twoFactorUser == null) return default;

                var result = await userMgr.SetTwoFactorEnabledAsync(twoFactorUser, true);

                if (!result.Succeeded)
                    return new ApiQueuedResponse(false, 400, id, "Could not enable 2FA");

                return new ApiQueuedResponse(true, 200, id, "Successfully enabled 2FA");
            });

            return Ok(new ApiResponse(true, 200, "Successfully sent request", Base32Encoding.ToString(secret)));
        }

        [HttpDelete("2fa")]
        public async Task<IActionResult> DisableTwoFactorAuthentication(string email)
        {
            string id;
            using(var scope = _factory.CreateScope())
            {
                var userMgr = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
                if (userMgr == null) return Ok(new ApiResponse(false, 500, "Could not find user"));

                var user = await userMgr.FindByEmailAsync(email);
                if (user == null) return Ok(new ApiResponse(false, 404, "Could not find user"));
                id = await userMgr.GetUserIdAsync(user);
            }

            _queue.QueueBackgroundWorkItem(async (scope, stoppingToken) =>
            {
                var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();
                var sender = scope.GetNotNullService<IEmailSender>();
                var store = scope.GetNotNullService<IJwtStore>();
                var config = scope.GetNotNullService<IConfiguration>();

                var user = await userManager.FindByEmailAsync(email);
                if (user == null) return new ApiQueuedResponse(false, 404, id, "User not found");

                var token = await store.CreateTwoFactorRecoveryTokenAsync(user);

                await sender.SendEmailAsync(await userManager.GetEmailAsync(user), "2FA Account Recovery",
                    $"<a href=\"http://{config["Host"]}/api/confirm/2fa?recoveryToken=${token}\">Click me</a>");

                return new ApiQueuedResponse(true, 200, id, "Successfully sent 2FA recovery email");
            });

            return Ok(new ApiResponse(true, 200, "Successfully sent recovery email"));
        }
    }
}
