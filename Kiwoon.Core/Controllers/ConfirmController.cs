using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Token;
using Kiwoon.Domain.Identity.User;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace Kiwoon.Core.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ConfirmController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserRepository _userRepo;
        private readonly IJwtRepository _jwtRepo;

        public ConfirmController(IConfiguration configuration, IUserRepository userRepo, IJwtRepository jwtRepo)
        {
            _configuration = configuration;
            _userRepo = userRepo;
            _jwtRepo = jwtRepo;
        }

        [HttpGet("email")]
        public async Task<IActionResult> ConfirmEmail([Required] string token)
        {
            var result = JsonSerializer.Serialize(await _userRepo.ConfirmEmailAsync(token));
            return RedirectPermanent($"http://{_configuration["Host"]}/result.html?response={Base64UrlEncoder.Encode(result)}");
        }

        [HttpPost("email")]
        [Authorize]
        public async Task<ApplicationIdentityResult> ResendConfirmEmail()
        {
            var email = User.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email)?.Value;
            if (email == null)
                return IdentityResultTypes.EmailNotFound;

            return await _userRepo.SendConfirmEmailAsync(email);
        }

        [HttpGet("password")]
        public async Task<IActionResult> ConfirmResetPassword([Required] string newPassword, [Required] string token)
        {
            var result = JsonSerializer.SerializeToUtf8Bytes(await _userRepo.ConfirmChangePasswordAsync(newPassword, token));

            return RedirectPermanent($"http://{_configuration["Host"]}/result?response=" +
                                     Base64UrlTextEncoder.Encode(result));
        }

        [HttpGet("2fa")]
        public async Task<IActionResult> ConfirmTwoFactorReset([Required] string recoveryToken)
        {
            if (!AuthenticationHeaderValue.TryParse(Request.Headers[HeaderNames.Authorization], out var jwt))
                return Ok(IdentityResultTypes.BadToken);

            var identity = new ClaimsIdentity(new JwtSecurityToken(jwt.Parameter).Claims);
            var user = await _userRepo.GetUserAsync(new ClaimsPrincipal(identity));
            if (user == null)
                return Ok(IdentityResultTypes.UserNotFound);

            var result = JsonSerializer.Serialize(await _jwtRepo.ValidateTwoFactorRecoveryTokenAsync(user, recoveryToken));
            return RedirectPermanent($"http://{_configuration["Host"]}/result.html?response=" + 
                                     Base64UrlEncoder.Encode(result));
        }
    }
}