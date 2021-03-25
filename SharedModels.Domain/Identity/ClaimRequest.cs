using System.Collections.Generic;

namespace SharedModels.Domain.Identity
{
    public class ClaimRequest : BusRequest
    {
        public ApplicationUser User { get; set; }
        public IEnumerable<ApplicationClaim> Claims { get; set; }
    }
}
