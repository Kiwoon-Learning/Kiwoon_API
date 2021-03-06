using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace Kiwoon.Domain.Identity
{
    public class ApplicationUser : IdentityUser
    {
        [Key,DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public override string Id { get; set; }
    }
}
