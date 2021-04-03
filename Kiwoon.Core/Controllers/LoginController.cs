using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Logins;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Kiwoon.Core.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly ILoginRepository _loginRepo;

        public LoginController(ILoginRepository loginRepo)
        {
            _loginRepo = loginRepo;
        }

        [HttpGet]
        [Authorize]
        public bool CheckAuth(string policy)
        {
            if (string.IsNullOrWhiteSpace(policy))
                return true;

            _ = AuthenticationHeaderValue.TryParse(Request.Headers[HeaderNames.Authorization], out var jwt);
            return new JwtSecurityToken(jwt!.Parameter).Claims.Any(x => x.Type == policy);
        }

        [HttpGet("password")]
        public async Task<ApplicationIdentityResult> PasswordLogin([Required] string userName, [Required] string password,
            int code = 0, bool rememberMe = false, string rememberMeToken = "")
        {
            return await _loginRepo.PasswordLogin(userName, password, rememberMe, rememberMeToken, code);
        }

        [HttpGet("google")]
        public async Task<ApplicationIdentityResult> GoogleLogin(string securityToken)
        {
            return await _loginRepo.GoogleLogin(securityToken);
        }

        public string GetUserId()
        {
            return User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
        }
    }
}