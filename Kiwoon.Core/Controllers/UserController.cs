using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Logins;
using Kiwoon.Domain.Identity.Token;
using Kiwoon.Domain.Identity.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using OtpNet;

namespace Kiwoon.Core.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserRepository _userRepo;
        private readonly IJwtRepository _jwtRepo;
        private readonly ITwoFactorCodeRepository _twoFactorRepo;

        public UserController(IUserRepository userRepo, IJwtRepository jwtRepo, ITwoFactorCodeRepository twoFactorRepo)
        {
            _userRepo = userRepo;
            _jwtRepo = jwtRepo;
            _twoFactorRepo = twoFactorRepo;
        }

        [HttpGet]
        [Authorize]
        public async Task<ApplicationIdentityResult> GetUserFromToken()
        {
            var user = await _userRepo.GetUserAsync(User);
            if (user == null) return IdentityResultTypes.UserNotFound;

            return new ApplicationIdentityResult(true, JsonSerializer.Serialize((ApplicationUserDto) user));
        }

        [HttpGet("refresh")]
        [Authorize]
        public async Task<ApplicationIdentityResult> RefreshToken()
        {
            var user = await _userRepo.GetUserAsync(User);
            if (user == null) return IdentityResultTypes.UserNotFound;

            _ = AuthenticationHeaderValue.TryParse(Request.Headers[HeaderNames.Authorization], out var jwt);
            await _jwtRepo.AddBlacklistedTokenAsync(new JwtSecurityToken(jwt!.Parameter));
            var result = await _jwtRepo.CreateTokenAsync(user);
            return new ApplicationIdentityResult(!string.IsNullOrWhiteSpace(result), result);
        }

        [HttpPost]
        public async Task<ApplicationIdentityResult> CreateNewUser([Required] string email,[Required] string password)
        {
            return await _userRepo.Create(
                new ApplicationUser {Email = email, UserName = email, PasswordHash = password});
        }

        [HttpDelete]
        [Authorize]
        public async Task<ApplicationIdentityResult> DeleteUser([Required] string password)
        {
            var user = await _userRepo.GetUserAsync(User);
            if (user == null) return IdentityResultTypes.UserNotFound;

            if (!_userRepo.ValidatePassword(user, password).Succeeded)
                return IdentityResultTypes.BadPassword;

            await _userRepo.Delete(user);
            return IdentityResult.Success;
        }

        [HttpGet("id/{id}")]
        public async Task<ApplicationUserDto> GetUserById([FromRoute][Required] string id)
        {
            var user = await _userRepo.FindByIdAsync(id);
            return user == null ? null : (ApplicationUserDto) user;
        }

        [HttpPost("2fa")]
        [Authorize]
        public async Task<ApplicationIdentityResult> EnableTwoFactorAuthentication()
        {
            var user = await _userRepo.GetUserAsync(User);
            if (user == null) return IdentityResultTypes.UserNotFound;
            
            var result = await _userRepo.EnableTwoFactorAuthentication(user);
            if (!result.Succeeded) return result;

            return new ApplicationIdentityResult(true, 
                $"otpauth://totp/{user.Email}?secret={Base32Encoding.ToString(await _twoFactorRepo.GetUserSecretAsync(user))}&issuer=Kiwoon Learning");
        }

        [HttpGet("2fa")]
        public async Task<ApplicationIdentityResult> SendTwoFactorRecoveryEmail([Required] string email)
        {
            var user = await _userRepo.FindByEmailAsync(email);
            if (user == null) return IdentityResultTypes.UserNotFound;

            return await _userRepo.SendTwoFactorRecoveryEmailAsync(user);
        }

        [HttpDelete("2fa")]
        [Authorize]
        public async Task<ApplicationIdentityResult> DisableTwoFactorAuthentication()
        {
            var user = await _userRepo.GetUserAsync(User);
            if (user == null) return IdentityResultTypes.UserNotFound;

            return await _userRepo.DisableTwoFactorAuthentication(user);
        }
    }
}