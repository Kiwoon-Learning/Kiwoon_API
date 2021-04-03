using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity.Token;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Kiwoon.Core.Authorization
{
    public class JwtUnexpiredRequirement : IAuthorizationRequirement
    {
    }

    public class JwtUnexpiredHandler : AuthorizationHandler<JwtUnexpiredRequirement>
    {
        private readonly IExpiredTokenRepository _store;

        public JwtUnexpiredHandler(IExpiredTokenRepository store)
        {
            _store = store;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
            JwtUnexpiredRequirement requirement)
        {
            if (context.Resource is not HttpContext httpContext ||
                (!httpContext.User.Identity?.IsAuthenticated ?? false)) return;
            var parse = AuthenticationHeaderValue.TryParse(httpContext.Request.Headers[HeaderNames.Authorization], out var jwt);
            if (!parse) return;

            if (!await _store.IsBlacklistedTokenAsync(new JwtSecurityToken(jwt.Parameter))) context.Succeed(requirement);
        }
    }
}