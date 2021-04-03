using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Kiwoon.Core.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmailController : ControllerBase
    {
        private readonly IUserRepository _userRepo;

        public EmailController(IUserRepository userRepo)
        {
            _userRepo = userRepo;
        }

        [HttpGet]
        public async Task<ApplicationIdentityResult> FindByEmail([Required] string email)
        {
            var user = await _userRepo.FindByEmailAsync(email);
            return new ApplicationIdentityResult(user != null, JsonSerializer.Serialize(user));
        }

        [HttpPut]
        [Authorize]
        public async Task<ApplicationIdentityResult> ChangeEmail([Required] string email,[Required] string newEmail)
        {
            return await _userRepo.ChangeEmailAsync(email, newEmail);
        }

        [HttpGet("confirm")]
        public async Task<ApplicationIdentityResult> ConfirmEmail([Required] string token)
        {
            return await _userRepo.ConfirmEmailAsync(token);
        }
    }
}