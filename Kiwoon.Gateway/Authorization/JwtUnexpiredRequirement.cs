using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Kiwoon.Gateway.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Kiwoon.Gateway.Authorization
{
    public class JwtUnexpiredRequirement : IAuthorizationRequirement { }

    public class JwtUnexpiredHandler : AuthorizationHandler<JwtUnexpiredRequirement>
    {
        private readonly IExpiredTokenStore _store;

        public JwtUnexpiredHandler(IExpiredTokenStore store)
        {
            _store = store;
        }
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, JwtUnexpiredRequirement requirement)
        {
            if (context.Resource is not HttpContext httpContext || (!httpContext.User.Identity?.IsAuthenticated ?? false))
            {
                return;
            }
            var token = new JwtSecurityToken(httpContext.Request.Headers[HeaderNames.Authorization].ToString()[6..].Trim());
            if (!await _store.IsBlacklistedTokenAsync(token)) 
            {
                context.Succeed(requirement);
            }
        }
    }
}
