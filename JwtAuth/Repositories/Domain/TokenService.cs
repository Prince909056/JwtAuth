using JwtAuth.Models.Dto;
using JwtAuth.Repositories.Abstract;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuth.Repositories.Domain
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT: Secret"])),
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSercurityToken = securityToken as JwtSecurityToken;
            if (jwtSercurityToken != null || !jwtSercurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid Token");
            return principal;
        }

        public string GetRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public TokenResponse GetToken(IEnumerable<Claim> claim)
        {
            var authSigningkey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT: Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration[""],
                audience: _configuration[""],
                expires: DateTime.Now.AddDays(7),
                claims: claim,
                signingCredentials: new SigningCredentials(authSigningkey, SecurityAlgorithms.HmacSha256)
                );
            string tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return new TokenResponse
            {
                TokenString = tokenString,
                ValidTo = token.ValidTo,
            };
        }
    }
}
