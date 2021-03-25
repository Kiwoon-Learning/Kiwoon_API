using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Kiwoon.Accounts.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SharedModels.Domain.Identity;

namespace Kiwoon.Accounts.Services
{
    public class UserStore :
        IUserLoginStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserEmailStore<ApplicationUser>,
        IUserTwoFactorStore<ApplicationUser>,
        IUserLockoutStore<ApplicationUser>,
        IUserClaimStore<ApplicationUser>
    {
        private readonly IServiceScopeFactory _factory;

        public UserStore(IServiceScopeFactory factory)
        {
            _factory = factory;
        }
        public void Dispose()
        {
        }

        public async Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken) => await Task.FromResult(user.Id);

        public async Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) => await Task.FromResult(user.UserName);

        public async Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken) => await Task.FromResult(user.UserName = userName);

        public async Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) => await Task.FromResult(user.NormalizedUserName);

        public async Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken) =>
        await Task.FromResult(user.NormalizedUserName = normalizedName);

        public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            try
            {
                await context.Users.AddAsync(user, cancellationToken);
                await context.SaveChangesAsync(cancellationToken);
            }
            catch
            {
                return IdentityResult.Failed();
            }

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            try
            {
                context.Update(user);
                await context.SaveChangesAsync(cancellationToken);
            }
            catch
            {
                return IdentityResult.Failed();
            }
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            try
            {
                context.Users.Remove(user);
                await context.SaveChangesAsync(cancellationToken);
            }
            catch
            {
                return IdentityResult.Failed();
            }
            return IdentityResult.Success;
        }

        public async Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            return await context.Users.FindAsync(userId);
        }

        public async Task<ApplicationUser> FindByNameAsync(string normalizedUserName,
            CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            return await context.Users.FirstOrDefaultAsync(x => x.NormalizedUserName == normalizedUserName,
                cancellationToken);
        }

        public async Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            return await context.UserClaims.Where(x => x.UserId == user.Id).Select(x => new Claim(x.ClaimType, x.ClaimValue))
                .ToArrayAsync(cancellationToken);
        }

        public async Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            var userClaims = Enumerable.Empty<IdentityUserClaim<string>>();
            userClaims = claims.Aggregate(userClaims, (current, claim) => current.Append(new IdentityUserClaim<string> {ClaimType = claim.Type, ClaimValue = claim.Value, UserId = user.Id}));
            await context.UserClaims.AddRangeAsync(userClaims, cancellationToken);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            var oldClaim = await context.UserClaims.FirstOrDefaultAsync(x => new Claim(x.ClaimType, x.ClaimValue) == claim, cancellationToken: cancellationToken);
            context.UserClaims.Remove(oldClaim);
            await context.UserClaims.AddAsync(new IdentityUserClaim<string>
                {ClaimType = newClaim.Type, ClaimValue = newClaim.Value, UserId = user.Id}, cancellationToken);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            context.RemoveRange(claims);
             await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            List<string> ids = new();
            var users = context.UserClaims.Where(x => new Claim(x.ClaimType, x.ClaimValue) == claim);
            await users.ForEachAsync(x => ids.Add(x.UserId), cancellationToken);
            return context.Users.Where(x => ids.Contains(x.Id)).ToArray();
        }

        public async Task AddLoginAsync(ApplicationUser user, UserLoginInfo login,
            CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            await context.UserLogins.AddAsync(new IdentityUserLogin<string>
            {
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName,
                ProviderKey = login.ProviderKey,
                UserId = user.Id
            }, cancellationToken);
            await context.SaveChangesAsync(cancellationToken);
        }


        public async Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            context.UserLogins.Remove(new IdentityUserLogin<string>
            {
                LoginProvider = loginProvider,
                ProviderDisplayName = loginProvider,
                ProviderKey = providerKey,
                UserId = user.Id
            });
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user,
            CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            return await Task.FromResult(context.UserLogins.Where(x => x.UserId == user.Id)
                .Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey, x.ProviderDisplayName)).ToList());
        }

        public async Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
           return await context.Users.FindAsync(
                (await context.UserLogins.FirstOrDefaultAsync(
                    x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey, cancellationToken)).UserId);
        }

        public async Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.PasswordHash = passwordHash;
            context.Update(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.PasswordHash);
        }

        public async Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.PasswordHash != null);
        }

        public async Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.SecurityStamp = stamp;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.SecurityStamp);
        }

        public async Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.Email = email;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<string> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.Email);
        }

        public async Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.EmailConfirmed);
        }

        public async Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.EmailConfirmed = confirmed;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<ApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            return await context.Users.FirstOrDefaultAsync(x => x.NormalizedEmail == normalizedEmail, cancellationToken);
        }

        public async Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.NormalizedEmail);
        }

        public async Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.NormalizedEmail = normalizedEmail;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.TwoFactorEnabled = enabled;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.TwoFactorEnabled);
        }

        public async Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.LockoutEnd);
        }

        public async Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.LockoutEnd = lockoutEnd;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.AccessFailedCount++;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
            return user.AccessFailedCount;
        }

        public async Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.AccessFailedCount = 0;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }

        public async Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.AccessFailedCount);
        }

        public async Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.LockoutEnabled);
        }

        public async Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            using var scope = _factory.CreateScope();
            var context = scope.ServiceProvider.GetService<AccountDbContext>();
            user.LockoutEnabled = enabled;
            context.Attach(user);
            await context.SaveChangesAsync(cancellationToken);
        }
    }
}
