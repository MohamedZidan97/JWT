using Microsoft.AspNetCore.Identity;

using System.ComponentModel.DataAnnotations;
using JWTApi.Models.RefreshTokenM;

namespace JWTApi.Models.Identities
{
    public class ApplicationUser :IdentityUser
    {
        [Required, MaxLength(15)]
        public string FirstName { get; set; }
        [Required, MaxLength(15)]
        public string LastName { get; set; }
        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}
