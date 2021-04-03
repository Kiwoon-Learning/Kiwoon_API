using System.Linq;
using Microsoft.AspNetCore.Identity;

namespace Kiwoon.Domain.Identity
{
    public class ApplicationIdentityResult
    {
        public ApplicationIdentityResult(bool succeeded, params string[] response)
        {
            Succeeded = succeeded;
            Response = response;
        }

        public ApplicationIdentityResult(IdentityResult result)
        {
            Succeeded = result.Succeeded;
            Response = result.Errors.Select(x => $"{x.Code} - {x.Description}").ToArray();
        }

        public static implicit operator ApplicationIdentityResult(IdentityResult result) => new(result);

        public static implicit operator IdentityResult(ApplicationIdentityResult result) =>  
            result.Succeeded ? IdentityResult.Success : IdentityResult.Failed(result.Response.Select(x => new IdentityError
            {
                Code = x.Split('-')[0].Trim(),
                Description = x.Split('-')[1].TrimStart()
            }).ToArray());

        public bool Succeeded { get; set; }
        public string[] Response { get; set; }
    }
}
