namespace Kiwoon.Domain.Identity.User
{
    public class UserRequest : BusRequest
    {
        public UserRequest(ApplicationUser user)
        {
            User = user;
        }
        public ApplicationUser User { get; set; }
    }
}
