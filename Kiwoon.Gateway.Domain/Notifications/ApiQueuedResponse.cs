using Microsoft.AspNetCore.Identity;
using SharedModels.Domain.Blog;

namespace Kiwoon.Gateway.Domain.Notifications
{
    public class ApiQueuedResponse : ApiResponse
    {
        public ApiQueuedResponse(IdentityResult result, string id) : base(result)
        {
            UserId = id;
        }

        public ApiQueuedResponse(BlogResult result, string id) : base(result)
        {
            UserId = id;
        }
#nullable enable
        public ApiQueuedResponse(bool succeeded, int status, string id, params object[]? response) :
            base(succeeded, status, response)
        {
            UserId = id;
        }
        public string UserId { get; set; }
    }
}
