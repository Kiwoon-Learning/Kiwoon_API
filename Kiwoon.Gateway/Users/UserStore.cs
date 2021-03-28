using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Messaging.ServiceBus;
using Microsoft.AspNetCore.Identity;
using SharedModels.Domain;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Users
{
    public class UserStore : IUserClaimStore<ApplicationUser>,
        IUserLoginStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserEmailStore<ApplicationUser>,
        IUserTwoFactorStore<ApplicationUser>,
        IUserLockoutStore<ApplicationUser>
    {
        private readonly ServiceBusClient _client;
        public UserStore(ServiceBusClient client)
        {
            _client = client;
        }
        private async Task<T> SendSessionRequestResponseAsync<T>(string queueName, BusRequest request, Guid guidId, CancellationToken cancellationToken = default)
        {
            var id = guidId.ToString();
            await using var sender = _client.CreateSender(queueName);
            var input = JsonSerializer.SerializeToUtf8Bytes(request, request.GetType());
            await sender.SendMessageAsync(new ServiceBusMessage(input){SessionId = id}, cancellationToken);

            await using var session = await _client.AcceptSessionAsync("Response", id, cancellationToken: cancellationToken);
            var message = await session.ReceiveMessageAsync(cancellationToken: cancellationToken);
            await session.CompleteMessageAsync(message, cancellationToken);
            return message.Body.ToObjectFromJson<T>(new JsonSerializerOptions{IncludeFields = true});
        }
        private async Task SendRequestAsync(string queueName, BusRequest request, Guid guidId, CancellationToken cancellationToken = default)
        {
            var id = guidId.ToString();
            await using var sender = _client.CreateSender(queueName);
            var input = JsonSerializer.SerializeToUtf8Bytes(request, request.GetType());
            await sender.SendMessageAsync(new ServiceBusMessage(input){SessionId = id}, cancellationToken);
        }

        public async Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.TwoFactorEnabled = enabled);
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
            await Task.FromResult(user.LockoutEnd = lockoutEnd);
        }

        public async Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.AccessFailedCount++);
        }

        public async Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.AccessFailedCount = 0);
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
            await Task.FromResult(user.LockoutEnabled = enabled);
        }
        public async Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.Id);
        }

        public async Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.UserName);
        }

        public async Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.UserName = userName);
        }

        public async Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.NormalizedUserName);
        }

        public async Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.NormalizedUserName = normalizedName);
        }

        public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return (await SendSessionRequestResponseAsync<ApplicationIdentityResult>("CreateUser",
                new UserRequest{User = user}, Guid.NewGuid(), cancellationToken)).ToIdentityResult();
        }

        public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return (await SendSessionRequestResponseAsync<ApplicationIdentityResult>("UpdateUser",
                new UserRequest{User = user}, Guid.NewGuid(), cancellationToken)).ToIdentityResult();
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return (await SendSessionRequestResponseAsync<ApplicationIdentityResult>("DeleteUser",
                new UserRequest{User = user}, Guid.NewGuid(), cancellationToken)).ToIdentityResult();
        }

        public async Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            return await SendSessionRequestResponseAsync<ApplicationUser>("FindById",
                new FindByRequest{SearchQuery = userId}, Guid.NewGuid(), cancellationToken);
        }

        public async Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            return await SendSessionRequestResponseAsync<ApplicationUser>("FindByName",
                new FindByRequest{SearchQuery = normalizedUserName}, Guid.NewGuid(), cancellationToken);
        }

        public async Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            var claims = await SendSessionRequestResponseAsync<IList<ApplicationClaim>>("GetClaims",
                new ClaimRequest { User = user }, Guid.NewGuid(), cancellationToken);
            return claims.Select(claim =>
                new Claim(claim.Type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer)).ToArray();
        }

        public async Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            await SendRequestAsync("AddClaims", new ClaimRequest{User = user, Claims = 
                from claim in claims select new ApplicationClaim(claim)}, Guid.NewGuid(), cancellationToken);
        }

        public async Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            await SendRequestAsync("ReplaceClaim", new ClaimRequest{User = user, Claims = new[]{ new ApplicationClaim(claim),
                new ApplicationClaim(newClaim) } }, Guid.NewGuid(), cancellationToken);
        }

        public async Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            await SendRequestAsync("RemoveClaim", new ClaimRequest{User = user, 
                Claims = from claim in claims select new ApplicationClaim(claim)}, Guid.NewGuid(), cancellationToken);
        }

        public async Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            return await SendSessionRequestResponseAsync<IList<ApplicationUser>>("GetUsersForClaim",
                new ClaimRequest{ Claims = new []{new ApplicationClaim(claim)}}, Guid.NewGuid(), cancellationToken);
        }

        public async Task AddLoginAsync(ApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            await SendRequestAsync("AddLogin", new LoginRequest{User = user, Login = login }, Guid.NewGuid(), cancellationToken);
        }

        public async Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            await SendRequestAsync("RemoveLogin", new LoginRequest{User = user}, Guid.NewGuid(), cancellationToken);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await SendSessionRequestResponseAsync<IList<UserLoginInfo>>("GetLogins",
                new LoginRequest { User = user }, Guid.NewGuid(), cancellationToken);
        }

        public async Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            return await SendSessionRequestResponseAsync<ApplicationUser>("FindByLogin",
                new LoginRequest{ Login = new UserLoginInfo(loginProvider,providerKey,loginProvider)}, Guid.NewGuid(), cancellationToken);
        }

        public async Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.PasswordHash = passwordHash);
        }

        public async Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.PasswordHash);
        }

        public async Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(string.IsNullOrEmpty(user.PasswordHash));
        }

        public async Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.SecurityStamp = stamp);
        }

        public async Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.SecurityStamp);
        }

        public async Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.Email = email);
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
            await Task.FromResult(user.EmailConfirmed = confirmed);
        }

        public async Task<ApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            return await SendSessionRequestResponseAsync<ApplicationUser>("FindByEmail",
                new FindByRequest { SearchQuery = normalizedEmail }, Guid.NewGuid(), cancellationToken);
        }

        public async Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return await Task.FromResult(user.NormalizedEmail);
        }

        public async Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            await Task.FromResult(user.NormalizedEmail = normalizedEmail);
        }

        public void Dispose()
        {
        }
        //TODO: Use JWT for email confirmation, we'll see about 2FA  (Use authenticator app?)
    }
}
