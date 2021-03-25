using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Domain.User
{
    public class ApplicationUserDto
    {
        public ApplicationUserDto()
        {
            
        }
        public ApplicationUserDto(ApplicationUser user)
        {
            Id = user.Id;
            UserName = user.UserName;
            Email = user.Email;
        }
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}
