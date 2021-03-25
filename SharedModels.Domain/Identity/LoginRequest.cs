using Microsoft.AspNetCore.Identity;

namespace SharedModels.Domain.Identity
{
    public class LoginRequest : BusRequest
    {
        public ApplicationUser User { get; set; }
        public UserLoginInfo Login { get; set; }
    }
}
