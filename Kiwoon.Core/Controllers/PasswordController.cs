using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Kiwoon.Core.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasswordController : ControllerBase
    {
        private readonly IUserRepository _userRepo;

        public PasswordController(IUserRepository userRepo)
        {
            _userRepo = userRepo;
        }
        [HttpPut]
        [Authorize]
        public async Task<ApplicationIdentityResult> ChangePassword([Required] string currentPass, [Required] string newPass)
        {
            var user = await _userRepo.GetUserAsync(User);
            if (user == null) return IdentityResultTypes.UserNotFound;

            return await _userRepo.ChangeUserPasswordAsync(user, currentPass, newPass);
        }

        [HttpPost]
        [Authorize]
        public async Task<ApplicationIdentityResult> SetPassword(string password)
        {
            var user = await _userRepo.GetUserAsync(User);
            if (user == null) 
                return IdentityResultTypes.UserNotFound;

            return await _userRepo.SetPasswordAsync(user, password);
        }

        [HttpGet("forgot")]
        public async Task<ApplicationIdentityResult> ForgotPassword([Required] string email)
        {
            return await _userRepo.SendPasswordRecoveryEmailAsync(email);
        }

        public string GetUserId()
        {
            return User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
        }
    }
}