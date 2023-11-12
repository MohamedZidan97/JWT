using JWTApi.Helper.appsettingsSections;
using JWTApi.Models;
using JWTApi.Models.Account;
using JWTApi.Models.AuthServiceVM;
using JWTApi.Models.Identities;
using JWTApi.Models.RefreshTokenM;
using JWTApi.Services.Interfaces;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Composition;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using NuGet.Common;

namespace JWTApi.Services.Repositories
{
    public class AuthService : IAuthService
    {
        public readonly UserManager<ApplicationUser> userManager;
        public readonly RoleManager<IdentityRole> roleManager;
        public readonly JWT jwt;


        public AuthService(IOptions<JWT> jwt, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.jwt = jwt.Value;
        }

        public async Task<AuthModel> RegisterAsync(RegisterM registerVM)
        {
            if (await userManager.FindByEmailAsync(registerVM.Email) is not null)
                return new AuthModel { Message = "Email Is already Recoerd", IsAuthenticed = false };
            if (await userManager.FindByNameAsync(registerVM.UserName) is not null)
                return new AuthModel { Message = "UserName Is already Recoerd", IsAuthenticed = false };

            var user = new ApplicationUser()
            {
                FirstName = registerVM.FirstName,
                LastName = registerVM.LastName,
                Email = registerVM.Email,
                UserName = registerVM.UserName,
            };


            var result = await userManager.CreateAsync(user, registerVM.Password);

            if (!result.Succeeded)
            {
                var errors = String.Empty;

                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description},";
                }
                return new AuthModel { Message = errors, IsAuthenticed = false };
            }

            await userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);
            var generateRefreshToken = await GenerateRefreshToken();
            user.RefreshTokens.Add(generateRefreshToken);
            await userManager.UpdateAsync(user);


           

            return new AuthModel
            {
                IsAuthenticed = true,
                Email = registerVM.Email,
                Username = registerVM.UserName,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                RefreshToken= generateRefreshToken.Token,
                RefreshTokenExpiration= generateRefreshToken.ExpiresOn
            };
        }

        public async Task<AuthModel> GetTokenAsync(GetTokenM login)
        {
            AuthModel model = new AuthModel();
            
            var user = await userManager.FindByEmailAsync(login.Email); 

            if(user is null||! await userManager.CheckPasswordAsync(user, login.Password))
            {
                model.Message = "Email Or Password is incorect!";
                return model;
            }
            var jwtSecurityToken = await CreateJwtToken(user);
            var GetRoles = await userManager.GetRolesAsync(user);
            model.IsAuthenticed= true;
            model.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            model.Email = user.Email;
            model.Username = user.UserName;
            model.ExpiresOn = jwtSecurityToken.ValidTo;
            model.Roles = GetRoles.ToList();

            if(user.RefreshTokens.Any(act => act.IsActive))
            {
                var ActiveToken = user.RefreshTokens.FirstOrDefault(act=> act.IsActive);
                model.RefreshToken = ActiveToken.Token;
                model.RefreshTokenExpiration = ActiveToken.ExpiresOn;

            }
            else
            {
                var newRefreshToken = await GenerateRefreshToken();
               
                model.RefreshToken = newRefreshToken.Token;
                model.RefreshTokenExpiration = newRefreshToken.ExpiresOn;

                user.RefreshTokens.Add(newRefreshToken);
                await userManager.UpdateAsync(user);

            }

            return model;

        }

        public async Task<string> AddRoleAsync(AddRoleM roleM)
        {
            var user = await userManager.FindByIdAsync(roleM.UserId);
         
            if (user is null || !await roleManager.RoleExistsAsync(roleM.RoleName))
                return "User Or Role isn't exist";

            if (await userManager.IsInRoleAsync(user, roleM.RoleName))
                return "user already  assigned to this Role";

            var res = await userManager.AddToRoleAsync(user, roleM.RoleName);


            return res.Succeeded ? string.Empty : "Something is Wrong";

        }



        #region Token


        public async Task<bool> RevokedTokenAsync(string refreshToken)
        {
            var user = await userManager.Users.SingleOrDefaultAsync(tok => tok.RefreshTokens.Any(rt => rt.Token == refreshToken));

            if(user == null)
            {
                return false;
            }
            var existingToken = user.RefreshTokens.Single(t => t.Token == refreshToken);

            if(!existingToken.IsActive)
                return false;

            existingToken.RevokedOn = DateTime.UtcNow;
            await userManager.UpdateAsync(user);

            return true;


        }
        public async Task<AuthModel> CheckOrCreateRefreshTokenAsync(string refreshToken)
        {

            var user = await userManager.Users.SingleOrDefaultAsync(tok => tok.RefreshTokens.Any(rt => rt.Token == refreshToken));

            var authModel = new AuthModel();
            if (user == null)
            {
                authModel.Message = "Invalid token";
                return authModel;
            }

            var existingToken = user.RefreshTokens.Single(t => t.Token == refreshToken);

            if (!existingToken.IsActive)
            {
                authModel.Message = "Inactive token";
                return authModel;
            }

            // make old refresh token Revoked
            existingToken.RevokedOn = DateTime.UtcNow;

            // Add the new Token 
            var newRefreshToken = await GenerateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            await userManager.UpdateAsync(user);

            // Generate Token Authorization
            var jwtToken = await CreateJwtToken(user);
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            // complete attributes of AuthModel
            authModel.IsAuthenticed = true;
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            var roles = await userManager.GetRolesAsync(user);
            authModel.Roles = roles.ToList();
            authModel.RefreshToken = newRefreshToken.Token;
            authModel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;


            return authModel;

        }

        private async Task<RefreshToken> GenerateRefreshToken()
        {
            var randomNumber = new byte[32];

            using var Generator = new RNGCryptoServiceProvider();
            Generator.GetBytes(randomNumber);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddMinutes(jwt.DurationInMinutes),
                CreatedOn = DateTime.UtcNow
            };
        }
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await userManager.GetClaimsAsync(user);
            var roles = await userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: jwt.Issure,
                audience: jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(jwt.DurationInMinutes),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
        #endregion
    }
}
