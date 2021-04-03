using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Kiwoon.Core.Authorization
{
    public class CorrectJwtPurposeRequirement : IAuthorizationRequirement
    {
    }

    public class CorrectJwtPurposeHandler : AuthorizationHandler<CorrectJwtPurposeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
            CorrectJwtPurposeRequirement requirement)
        {
            if (context.Resource is not HttpContext httpContext) return Task.CompletedTask;

            var tokenBearer = httpContext.Request.Headers[HeaderNames.Authorization].ToString();
            if (string.IsNullOrWhiteSpace(tokenBearer)) return Task.CompletedTask;
            var token = new JwtSecurityToken(tokenBearer[6..].Trim());

            if (token.Claims.Any(c => c.Type == "purpose")) return Task.CompletedTask;

            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}