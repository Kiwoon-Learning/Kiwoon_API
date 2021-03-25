using System;
using System.Linq;
using Microsoft.AspNetCore.Identity;
using SharedModels.Domain.Blog;

namespace Kiwoon.Gateway.Domain
{
    public class ApiResponse
    {
        public ApiResponse()
        {
            
        }
#nullable enable
        public ApiResponse(IdentityResult result)
        {
            Response = (Response ?? Array.Empty<object>()).Union(result.Errors).ToArray();
            Succeeded = result.Succeeded;
            if (result.Succeeded) StatusCode = 200;
            else StatusCode = result.Errors.Any(x => x.Description.Contains("not found",
                StringComparison.InvariantCultureIgnoreCase)) ? 404 : 400;
        }
        public ApiResponse(BlogResult result)
        {
            Response = (Response ?? Array.Empty<object>()).Union(result.Blogs).ToArray();
            Succeeded = result.Succeeded;
            StatusCode = result.Succeeded ? 200 : 400;

        }
        public ApiResponse(bool succeeded, int statusCode, params object[]? response)
        {
            Succeeded = succeeded;
            StatusCode = statusCode;
            Response = response ?? Array.Empty<object>();
        }
        public bool Succeeded { get; set; }
        public int StatusCode { get; set; }
        public object[]? Response { get; set; }
    }
}
