using System.Linq;
using System.Security.Claims;

namespace Kiwoon.Gateway.Users
{
    public static class UserManagerHelper
    {
#nullable enable
        public static string? GetUserId(ClaimsPrincipal claim)
        {
            return claim.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
        }
    }
}
