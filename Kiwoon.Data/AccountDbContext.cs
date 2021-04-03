using Kiwoon.Domain.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Kiwoon.Data
{
    public class AccountDbContext : IdentityDbContext<ApplicationUser>
    {
        public AccountDbContext(DbContextOptions<AccountDbContext> options)
            : base(options)
        { 
        }
    }
}
