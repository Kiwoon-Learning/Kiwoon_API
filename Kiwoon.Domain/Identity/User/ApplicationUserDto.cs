namespace Kiwoon.Domain.Identity.User
{
    public class ApplicationUserDto
    {
        public ApplicationUserDto() { }

        public ApplicationUserDto(ApplicationUser user)
        {
            Id = user.Id;
            UserName = user.UserName;
            Email = user.Email;
        }

        public static explicit operator ApplicationUserDto(ApplicationUser user) => new(user);

        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}
