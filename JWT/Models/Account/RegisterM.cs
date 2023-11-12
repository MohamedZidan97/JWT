using System.ComponentModel.DataAnnotations;

namespace JWTApi.Models.AuthServiceVM
{
    public class RegisterM
    {
        [Required,StringLength(50)]
        public string FirstName { get; set; }
        [Required, StringLength(50)]
        public string LastName { get; set; }
        [Required, StringLength(50)]
        public string UserName { get; set; }
        [Required, StringLength(50)]
        public string Email { get; set; }
        [Required,MaxLength(20)]
        public string Password { get; set; }
      

    }
}
