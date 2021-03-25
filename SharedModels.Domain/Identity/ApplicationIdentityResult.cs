using Microsoft.AspNetCore.Identity;

namespace SharedModels.Domain.Identity
{
    public class ApplicationIdentityResult
    {
        public IdentityResult ToIdentityResult()
        {
            return Succeeded ? IdentityResult.Success : IdentityResult.Failed(Errors);
        }
        public bool Succeeded { get; set; }
        public IdentityError[] Errors { get; set; }
    }
}
