using Microsoft.AspNetCore.Identity;

namespace Kiwoon.Domain.Identity.Logins
{
    public class LoginRequest : BusRequest
    {
        public ApplicationUser User { get; set; }
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }
    }
}
