using System;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Azure.Messaging.ServiceBus;
using Kiwoon.Domain;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Token;
using Kiwoon.Domain.Identity.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

namespace Kiwoon.Core.Users
{
    public class UserRepository : IUserRepository
    {
        private readonly ServiceBusClient _client;
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IJwtRepository _jwtRepo;

        public UserRepository(ServiceBusClient client, IConfiguration configuration, UserManager<ApplicationUser> userManager, IJwtRepository jwtRepo)
        {
            _client = client;
            _configuration = configuration;
            _userManager = userManager;
            _jwtRepo = jwtRepo;
        }
        public async Task<ApplicationIdentityResult> Create([Required] ApplicationUser user)
        {
            var result = await _userManager.CreateAsync(user, user.PasswordHash);
            if(result.Succeeded)
                await SendConfirmEmailAsync(user.Email);
            return result;
        }

        public async Task<ApplicationUser> Read([Required] ApplicationUser user)
        {
            return await FindByIdAsync(user.Id) ?? await FindByEmailAsync(user.Email);
        }

        public async Task Update([Required] ApplicationUser user)
        {
            if(await FindByIdAsync(user.Id) == null) throw new ArgumentNullException(nameof(user));

            await SendRequestAsync("UpdateUser", new UserRequest(user));
        }

        public async Task Delete([Required] ApplicationUser user)
        {
            if (await FindByIdAsync(user.Id) == null) throw new ArgumentNullException(nameof(user));

            await SendRequestAsync("DeleteUser", new UserRequest(user));
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            await SendRequestAsync("SendEmail", new EmailRequest(email, subject, htmlMessage));
        }

        public async Task<ApplicationIdentityResult> ConfirmEmailAsync([Required] string confirmToken)
        {
            var token = HttpUtility.UrlDecode(confirmToken);

            JwtSecurityToken jwtToken;
            try
            {
                jwtToken = new JwtSecurityToken(token);
            }
            catch (ArgumentException)
            {
                return IdentityResultTypes.NotAJwtToken;
            }

            if (await _jwtRepo.IsBlacklistedTokenAsync(jwtToken))
                return IdentityResultTypes.BadToken;

            var purposeClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == "purpose");
            if (purposeClaim == null || purposeClaim.Value != "emailConfirmation")
                return IdentityResultTypes.BadTokenPurpose;

            var idClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub);
            if (idClaim?.Value == null)
                return IdentityResultTypes.IdNotFound;

            var user = await FindByIdAsync(idClaim.Value);
            if (user == null)
                return IdentityResultTypes.UserNotFound;

            if (!await _jwtRepo.ValidateTokenAsync(user, token))
                return IdentityResultTypes.BadToken;

            var emailClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email);
            if (emailClaim?.Value == null || emailClaim.Value != user.Email)
                return IdentityResultTypes.BadEmail;

            await _jwtRepo.AddBlacklistedTokenAsync(jwtToken);

            user.EmailConfirmed = true;
            await Update(user);

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> SendConfirmEmailAsync([Required]string email)
        {
            var user = await FindByEmailAsync(email);
            if (user == null)
                return IdentityResult.Failed(
                    new IdentityError{Code = "UserNotFound", Description = "User not found"});

            if (user.EmailConfirmed)
                return IdentityResult.Failed(new IdentityError{Code = "BadEmail", Description = "User's email is already confirmed"});

            var token = await _jwtRepo.CreateEmailConfirmationTokenAsync(user);
            
            await SendEmailAsync(user.Email, "Confirm your email for Kiwoon Learning",
                $"Click <a href=\"http://{_configuration["Host"]}/api/confirm/email?token={HttpUtility.UrlEncode(token)}\">here</a> to confirm your email");

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> ChangeEmailAsync([Required] string oldEmail,[Required] string newEmail)
        {
            var user = await FindByEmailAsync(oldEmail);
            if (user == null)
                return IdentityResultTypes.BadEmail;

            try
            {
                if (!Regex.IsMatch(newEmail, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase,
                    TimeSpan.FromMilliseconds(250)))
                    return IdentityResultTypes.NotAnEmail;
            }
            catch(RegexMatchTimeoutException)
            {
                return IdentityResultTypes.NotAnEmail;
            }

            if (await FindByEmailAsync(newEmail) != null)
                return IdentityResultTypes.BadNewEmail;

            return await SendConfirmEmailAsync(newEmail);
        }

        public async Task<ApplicationIdentityResult> SendPasswordRecoveryEmailAsync([Required] string email)
        {
            var user = await FindByEmailAsync(email);
            if (user == null)
                return IdentityResultTypes.UserNotFound;

            var token = await _jwtRepo.CreatePasswordRecoveryTokenAsync(user);

            var uri = $"http://{_configuration["Host"]}/api/confirm/password";

            await SendEmailAsync(user.Email, "Password recovery",
                $"<form method='get' action='{uri}'> <input type='hidden' id='token' name='token' value='{token}'/>" +
                "<label for='newPassword'>New Password:</label><br> <input id='newPassword' name='newPassword'/>" +
                "<button type='submit'>Submit</button></form>");

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> ConfirmChangePasswordAsync([Required] string newPassword,[Required] string confirmToken)
        {
            var token = HttpUtility.UrlDecode(confirmToken);

            JwtSecurityToken jwtToken;
            try
            {
                jwtToken = new JwtSecurityToken(token);
            }
            catch (ArgumentException)
            {
                return IdentityResultTypes.NotAJwtToken;
            }

            var purposeClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == "purpose");
            if (purposeClaim?.Value != "passwordRecovery")
                return IdentityResultTypes.BadTokenPurpose;

            var idClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub);
            if (idClaim?.Value == null)
                return IdentityResultTypes.IdNotFound;

            var user = await FindByIdAsync(idClaim.Value);
            if (user == null)
                return IdentityResultTypes.UserNotFound;

            if (!await _jwtRepo.ValidateTokenAsync(user, token))
                return IdentityResultTypes.BadToken;

            var emailClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email);
            if (emailClaim?.Value == null || emailClaim.Value != user.Email)
                return IdentityResultTypes.BadEmail;

            if (_userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, newPassword) !=
                PasswordVerificationResult.Failed)
                return IdentityResultTypes.SamePassword;

            var hash = jwtToken.Claims.FirstOrDefault(x => x.Type == "hash");
            if (hash?.Value == null)
                return IdentityResultTypes.NoHash;

            if (_userManager.PasswordHasher.VerifyHashedPassword(user, hash.Value, user.PasswordHash)
                != PasswordVerificationResult.Failed)
                return IdentityResultTypes.BadHash;

            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, newPassword);
            await Update(user);

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> ChangeUserPasswordAsync(ApplicationUser userToChangePass, string oldPassword, string newPassword)
        {
            var user = await FindByIdAsync(await _userManager.GetUserIdAsync(userToChangePass));
            if (user == null)
                return IdentityResultTypes.UserNotFound;

            if (user.PasswordHash != null)
                return IdentityResultTypes.BadUser;

            if (string.Equals(oldPassword, newPassword, StringComparison.InvariantCultureIgnoreCase))
                return IdentityResultTypes.SamePassword;

            var result = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, oldPassword);
            if (result == PasswordVerificationResult.Failed)
                return IdentityResultTypes.BadPassword;

            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, newPassword);
            await Update(user);

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> SetPasswordAsync(ApplicationUser userToAddPass, string password)
        {
            var user = await FindByIdAsync(await _userManager.GetUserIdAsync(userToAddPass));
            if (user == null)
                return IdentityResultTypes.UserNotFound;

            if (user.PasswordHash != null)
                return IdentityResultTypes.BadPassword;

            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, password);
            await Update(user);

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> EnableTwoFactorAuthentication(ApplicationUser twoFactorUser)
        {
            var user = await FindByIdAsync(twoFactorUser.Id);
            if (user == null) return IdentityResultTypes.UserNotFound;

            if (user.TwoFactorEnabled) return IdentityResultTypes.BadUser;
            if (user.PasswordHash == null) return IdentityResultTypes.BadPassword;

            user.TwoFactorEnabled = true;
            await Update(user);


            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> DisableTwoFactorAuthentication(ApplicationUser twoFactorUser)
        {
            var user = await FindByIdAsync(twoFactorUser.Id);
            if (user == null) return IdentityResultTypes.UserNotFound;

            if (!user.TwoFactorEnabled) return IdentityResultTypes.BadUser;

            user.TwoFactorEnabled = false;
            await Update(user);

            return IdentityResult.Success;
        }

        public async Task<ApplicationIdentityResult> SendTwoFactorRecoveryEmailAsync([Required] ApplicationUser user)
        {
            var token = await _jwtRepo.CreateTwoFactorRecoveryTokenAsync(user);
            await SendEmailAsync(user.Email, "Two factor recovery", $"Click this <a href=\"http://{_configuration["Host"]}/confirm/2fa?recoveryToken=${token}\">link</a> to disable 2FA on your account");
            return IdentityResult.Success;
        }

        public ApplicationIdentityResult ValidatePassword(ApplicationUser user, string password)
        {
            var result = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
            return result == PasswordVerificationResult.Failed ? IdentityResultTypes.BadPassword : IdentityResult.Success;
        }

        public async Task<ApplicationUser> FindByEmailAsync([Required] string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }

        public async Task<ApplicationUser> FindByIdAsync([Required] string id)
        {
            return await _userManager.FindByIdAsync(id);
        }

        public async Task<ApplicationUser> GetUserAsync(ClaimsPrincipal principal)
        {
            var sub = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            if (sub?.Value == null) return null;

            return await FindByIdAsync(sub.Value);
        }

        public async Task<ApplicationUser> GetUserFromTokenAsync([Required] string userToken)
        {
            var token = HttpUtility.UrlDecode(userToken);

            JwtSecurityToken jwtToken;
            try
            {
                jwtToken = new JwtSecurityToken(token);
            }
            catch (ArgumentException)
            {
                return null;
            }

            var idClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub);
            if (idClaim?.Value == null)
                return null;

            var user = await FindByIdAsync(idClaim.Value);

            if (!await _jwtRepo.ValidateTokenAsync(user, userToken))
                return null;

            return user;
        }

        private async Task SendRequestAsync(string queueName, BusRequest request,
            CancellationToken cancellationToken = default)
        {
            await using var sender = _client.CreateSender(queueName);
            var input = JsonSerializer.SerializeToUtf8Bytes(request, request.GetType());
            await sender.SendMessageAsync(new ServiceBusMessage(input), cancellationToken);
        }
    }
}
