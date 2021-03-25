using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Kiwoon.Gateway.Domain.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SharedModels.Domain;
using SharedModels.Domain.Identity;

namespace Kiwoon.Gateway.Authorization
{
    public class JwtStore : IJwtStore
    {
        private readonly IServiceScopeFactory _factory;

        public JwtStore(IServiceScopeFactory factory)
        {
            _factory = factory;
        }
        public async Task<string> CreateTokenAsync(ApplicationUser user)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();
            var config = scope.GetNotNullService<IConfiguration>();

            var userClaims = await userManager.GetClaimsAsync(user);
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Email, user.Email)
            };
            claims.AddRange(userClaims);

            if (await userManager.GetTwoFactorEnabledAsync(user))
                claims.Add(new Claim(JwtRegisteredClaimNames.Amr, "otp"));

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Audience"],
                claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: signingCredentials);
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        public async Task<string> CreateEmailConfirmationTokenAsync(ApplicationUser user)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();
            var config = scope.GetNotNullService<IConfiguration>();

            var userClaims = await userManager.GetClaimsAsync(user);
            IList<Claim> claims = new []
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("purpose", "emailConfirmation")
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Audience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: signingCredentials);
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        public async Task<bool> ValidateEmailConfirmationTokenAsync(ApplicationUser user, string token)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();

            if (userManager.FindByIdAsync(await userManager.GetUserIdAsync(user)) == null) return false;

            var handler = new JwtSecurityTokenHandler();
            var tokenParams = GetValidationParameters();

            var principal = handler.ValidateToken(token, tokenParams, out var jwtToken);
            if (!principal.Identity?.IsAuthenticated ?? true)
                return false;
            var jwt = (JwtSecurityToken)jwtToken;

            var email = await userManager.GetEmailAsync(user);
            var tokenEmail = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
            if (email != tokenEmail)
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == "purpose")?.Value != "emailConfirmation")
                return false;

            return true;
        }

        public Task<string> CreatePasswordRecoveryTokenAsync(ApplicationUser user)
        {
            using var scope = _factory.CreateScope();
            var config = scope.GetNotNullService<IConfiguration>();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("hash", Encoding.UTF8.GetString(SHA256.HashData(Encoding.UTF8.GetBytes(user.PasswordHash)))),
                new Claim("purpose", "passwordRecovery")
            };
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Audience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: signingCredentials);
            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
        }

        public async Task<bool> ValidatePasswordRecoveryTokenAsync(ApplicationUser user, string token)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();

            var recoveryUser = await userManager.FindByIdAsync(await userManager.GetUserIdAsync(user));
            if (recoveryUser == null) return false;

            var handler = new JwtSecurityTokenHandler();
            var tokenParams = GetValidationParameters();

            IPrincipal principal;
            SecurityToken jwtToken;
            try
            {
                principal = handler.ValidateToken(token, tokenParams, out jwtToken);
            }
            catch (SecurityTokenException)
            {
                return false;
            }

            if (!principal.Identity?.IsAuthenticated ?? true)
                return false;
            var jwt = (JwtSecurityToken)jwtToken;
            var oldPwd = Encoding.UTF8.GetString(SHA256.HashData(Encoding.UTF8.GetBytes(user.PasswordHash)));

            if (oldPwd !=
                jwt.Claims.FirstOrDefault(c => c.Type == "hash")?.Value)
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == "purpose")?.Value != "passwordRecovery")
                return false;

            return true;
        }

        public TokenValidationParameters GetValidationParameters()
        {
            using var scope = _factory.CreateScope();
            var config = scope.GetNotNullService<IConfiguration>();

            return new()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = config["Jwt:Issuer"],
                ValidAudience = config["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"])),
            };
        }

        public Task<string> CreateTwoFactorRecoveryTokenAsync(ApplicationUser user)
        {
            using var scope = _factory.CreateScope();
            var config = scope.GetNotNullService<IConfiguration>();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Amr, "otp"),
                new Claim("purpose", "twoFactorRecovery")
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Audience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: signingCredentials);

            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
        }
        public async Task<bool> ValidateTwoFactorRecoveryTokenAsync(ApplicationUser user, string token)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();

            var recoveryUser = await userManager.FindByIdAsync(await userManager.GetUserIdAsync(user));
            if (recoveryUser == null) return false;

            var handler = new JwtSecurityTokenHandler();
            var tokenParams = GetValidationParameters();

            IPrincipal principal;
            SecurityToken jwtToken;
            try
            {
                principal = handler.ValidateToken(token, tokenParams, out jwtToken);
            }
            catch (SecurityTokenException)
            {
                return false;
            }

            if ((!principal.Identity?.IsAuthenticated ?? true) || jwtToken is not JwtSecurityToken jwt)
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == "purpose")?.Value != "twoFactorRecovery")
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Amr)?.Value != "otp")
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value != user.Id)
                return false;

            return true;
        }

        public Task<string> CreateTwoFactorRememberMeTokenAsync(ApplicationUser user)
        {
            using var scope = _factory.CreateScope();
            var config = scope.GetNotNullService<IConfiguration>();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Amr, "otp"),
                new Claim("purpose", "twoFactorRememberMe")
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Audience"],
                claims,
                expires: DateTime.UtcNow.AddDays(30),
                signingCredentials: signingCredentials);

            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
        }

        public async Task<bool> ValidateTwoFactorRememberMeTokenAsync(ApplicationUser user, string token)
        {
            using var scope = _factory.CreateScope();
            var userManager = scope.GetNotNullService<UserManager<ApplicationUser>>();

            var recoveryUser = await userManager.FindByIdAsync(await userManager.GetUserIdAsync(user));
            if (recoveryUser == null) return false;

            var handler = new JwtSecurityTokenHandler();
            var tokenParams = GetValidationParameters();

            IPrincipal principal;
            SecurityToken jwtToken;
            try
            {
                principal = handler.ValidateToken(token, tokenParams, out jwtToken);
            }
            catch (SecurityTokenException)
            {
                return false;
            }

            if ((!principal.Identity?.IsAuthenticated ?? true) || jwtToken is not JwtSecurityToken jwt)
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == "purpose")?.Value != "twoFactorRememberMe")
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Amr)?.Value != "otp")
                return false;

            if (jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value != user.Id)
                return false;

            return true;
        }
    }
}
