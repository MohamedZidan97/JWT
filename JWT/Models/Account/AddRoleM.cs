using System.ComponentModel.DataAnnotations;

namespace JWTApi.Models.Account
{
    public class AddRoleM
    {
        [Required]
        public string UserId { get; set; }
        [Required]
        public string RoleName { get; set; }
    }
}
