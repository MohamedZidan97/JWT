using JWTApi.Models;
using JWTApi.Models.Account;
using JWTApi.Models.AuthServiceVM;
using JWTApi.Models.Identities;
using JWTApi.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NuGet.Common;

namespace JWTApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        public readonly IAuthService auth;
        private readonly UserManager<ApplicationUser> userManager;

        public AccountController(IAuthService auth, UserManager<ApplicationUser> userManager)
        {
            this.auth = auth;
            this.userManager = userManager;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterM registerVM)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await auth.RegisterAsync(registerVM);

            if (!result.IsAuthenticed)
            {
                return BadRequest(result);
            }


            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);

        }

        [HttpPost("GetToken")]
        public async Task<IActionResult> GetTokens([FromBody] GetTokenM model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var authModel = await auth.GetTokenAsync(model);

            if (!authModel.IsAuthenticed)
                return BadRequest(authModel.Message);

            if (!string.IsNullOrEmpty(authModel.RefreshToken))
                SetRefreshTokenInCookie(authModel.RefreshToken, authModel.RefreshTokenExpiration);


            return Ok(authModel);
        }

        [HttpPost("AddRole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleM model)
        {
            var Message = await auth.AddRoleAsync(model);

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (!string.IsNullOrEmpty(Message))
                return BadRequest(Message);

            return Ok(model);

        }

        [Authorize]
        [HttpGet("GetUsers")]
        public async Task<IActionResult> GetUser()
        {
            var Users = await userManager.Users.Select(x => new { FirstName = x.FirstName, Email = x.Email }).ToListAsync();


            return Ok(Users);
        }

        [HttpPost("revokedtoken")]
        public async Task<IActionResult> RevokedToken([FromBody] RequestTokenM model)
        {
            // if model.RefreshToken is null, use  Request.Cookies["refreshToken"]
            var refreshToken = model.RefreshToken ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest("Token is required!");


            var result = await auth.RevokedTokenAsync(refreshToken);

            if (!result)
                return BadRequest("Token is Invalid!");

            return Ok("Done");

        }

        [HttpGet("RefreshToken")]
        public async Task<IActionResult> RefreshTokens()
        {
            // it back with Cookie, we will use in search on his user 
            var refresToken = Request.Cookies["refreshToken"];

            var result = await auth.CheckOrCreateRefreshTokenAsync(refresToken);

            if (!result.IsAuthenticed)
                return BadRequest(result);

            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);

        }

        private void SetRefreshTokenInCookie(string refreshToken,DateTime expire)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expire.ToLocalTime()
            };
            Response.Cookies.Append("refreshToken", refreshToken,cookieOptions);

        }

    }
}
