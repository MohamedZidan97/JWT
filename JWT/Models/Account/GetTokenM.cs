using System.ComponentModel.DataAnnotations;

namespace JWTApi.Models.Account
{
    public class GetTokenM
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
