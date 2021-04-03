using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Kiwoon.Domain.Identity;
using Kiwoon.Domain.Identity.Token;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Kiwoon.Core.Authorization
{
    public class JwtRepository : IJwtRepository
    {
        private readonly IConfiguration _config;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDistributedCache _cache;

        public JwtRepository(IConfiguration config, UserManager<ApplicationUser> userManager, IDistributedCache cache)
        {
            _config = config;
            _userManager = userManager;
            _cache = cache;
        }

        public async Task<string> CreateTokenAsync(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Email, user.Email)
            };
            claims.AddRange(userClaims);

            if (await _userManager.GetTwoFactorEnabledAsync(user))
                claims.Add(new Claim(JwtRegisteredClaimNames.Amr, "otp"));

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                _config["JwtIssuer"],
                _config["JwtAudience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: signingCredentials);
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        public Task<string> CreateEmailConfirmationTokenAsync(ApplicationUser user)
        {
            IList<Claim> claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("purpose", "emailConfirmation")
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                _config["JwtIssuer"],
                _config["JwtAudience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: signingCredentials);
            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
        }

        public Task<bool> ValidateTokenAsync(ApplicationUser user, string token)
        {

            var handler = new JwtSecurityTokenHandler();
            var tokenParams = GetValidationParameters();

            var principal = handler.ValidateToken(token, tokenParams, out _);
            if (!principal.Identity?.IsAuthenticated ?? true)
                return Task.FromResult(false);

            return Task.FromResult(true);
        }

        public Task<string> CreatePasswordRecoveryTokenAsync(ApplicationUser user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("hash", Encoding.UTF8.GetString(SHA256.HashData(Encoding.UTF8.GetBytes(user.PasswordHash)))),
                new Claim("purpose", "passwordRecovery")
            };
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                _config["JwtIssuer"],
                _config["JwtAudience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: signingCredentials);
            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
        }

        private TokenValidationParameters GetValidationParameters()
        {
            return new()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _config["JwtIssuer"],
                ValidAudience = _config["JwtAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]))
            };
        }

        public Task<string> CreateTwoFactorRecoveryTokenAsync(ApplicationUser user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Amr, "otp"),
                new Claim("purpose", "twoFactorRecovery")
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                _config["JwtIssuer"],
                _config["JwtAudience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: signingCredentials);

            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
        }

        public Task<string> CreateTwoFactorRememberMeTokenAsync(ApplicationUser user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Amr, "otp"),
                new Claim("purpose", "twoFactorRememberMe")
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                _config["JwtIssuer"],
                _config["JwtAudience"],
                claims,
                expires: DateTime.UtcNow.AddDays(30),
                signingCredentials: signingCredentials);

            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));
        }

        public async Task<bool> ValidateTwoFactorRecoveryTokenAsync(ApplicationUser user, string token)
        {
            ClaimsPrincipal principal;
            SecurityToken jwtToken;
            try
            {
                principal = new JwtSecurityTokenHandler().ValidateToken(token, GetValidationParameters(), out jwtToken);
            }
            catch(Exception e)
            {
                if (e is SecurityTokenException || e is ArgumentException)
                    return false;
                throw;
            }

            if (jwtToken is not JwtSecurityToken)
                throw new SecurityTokenException(nameof(jwtToken));

            if (principal.FindFirst(JwtRegisteredClaimNames.Amr)?.Value != "otp")
                return false;

            if (principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value != user.Id)
                return false;

            if (principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value != user.Email)
                return false;

            if (principal.FindFirst("purpose")?.Value != "twoFactorRecovery")
                return false;

            return true;
        }

        public async Task<bool> ValidateTwoFactorRememberMeTokenAsync(ApplicationUser user, string token)
        {
            ClaimsPrincipal principal;
            SecurityToken jwtToken;
            try
            {
                principal = new JwtSecurityTokenHandler().ValidateToken(token, GetValidationParameters(), out jwtToken);
            }
            catch (Exception e)
            {
                if (e is SecurityTokenException || e is ArgumentException)
                    return false;
                throw;
            }

            if (jwtToken is not JwtSecurityToken)
                throw new SecurityTokenException(nameof(jwtToken));

            if (principal.FindFirst(JwtRegisteredClaimNames.Amr)?.Value != "otp")
                return false;

            if (principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value != user.Id)
                return false;

            if (principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value != user.Email)
                return false;

            if (principal.FindFirst("purpose")?.Value != "twoFactorRememberMe")
                return false;

            return true;
        }

        public async Task<bool> IsBlacklistedTokenAsync(JwtSecurityToken token)
        {
            return await _cache.GetAsync(token.RawSignature) != null;
        }

        public async Task AddBlacklistedTokenAsync(JwtSecurityToken token)
        {
            await _cache.SetStringAsync(token.RawSignature, "Blacklist",
                new DistributedCacheEntryOptions { AbsoluteExpiration = token.ValidTo });
        }

        public async Task<string> GetBlacklistedSecurityTokenAsync(string tokenSignature)
        {
            return Encoding.UTF8.GetString(await _cache.GetAsync(tokenSignature));
        }
    }
}