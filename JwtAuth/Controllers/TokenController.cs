using JwtAuth.Models.Domain;
using JwtAuth.Models.Dto;
using JwtAuth.Repositories.Abstract;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]/{action}")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly DatabaseContext _databaseContext;
        private readonly ITokenService _tokenService;

        public TokenController(DatabaseContext databaseContext, ITokenService tokenService)
        {
            _databaseContext = databaseContext;
            _tokenService = tokenService;
        }
        [HttpPost]
        public IActionResult Refresh(RefreshTokenRequest refreshTokenRequest)
        {
            if (refreshTokenRequest == null)
                return BadRequest("Invalid Client Request");
            string accessToken = refreshTokenRequest.AccessToken;
            string refreshToken = refreshTokenRequest.RefreshToken;
            var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);
            var userName = principal.Identity.Name;
            var user = _databaseContext.TokenInfo.SingleOrDefault(x => x.UserName == userName);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiry <= DateTime.Now)
                return BadRequest("Invalid Client Request");
            var newAccessToken = _tokenService.GetToken(principal.Claims);
            var newRefreshToken = _tokenService.GetRefreshToken();
            user.RefreshToken = newRefreshToken;
            _databaseContext.SaveChanges();
            return Ok(new RefreshTokenRequest()
            {
                AccessToken = newAccessToken.TokenString,
                RefreshToken = newRefreshToken
            });
        }

        //Revoken is user for removing token entry
        [HttpPost, Authorize]
        public IActionResult Revoke()
        {
            try
            {
                var username = User.Identity.Name;
                var user = _databaseContext.TokenInfo.SingleOrDefault(x => x.UserName == username);
                if (user is null) return BadRequest();
                user.RefreshToken = null;
                _databaseContext.SaveChanges();
                return Ok();
            }
            catch (Exception ex)
            {

                throw ex;
            }

        }
    }
}
