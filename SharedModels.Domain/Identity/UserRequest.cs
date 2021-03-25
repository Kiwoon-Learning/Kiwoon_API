namespace SharedModels.Domain.Identity
{
    public class UserRequest : BusRequest
    {
        public ApplicationUser User { get; set; }
    }
}
