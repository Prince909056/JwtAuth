using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Models.Dto
{
    public class RegistrationModel
    {
        [Required]
        public string? Username { get; set; }
        [Required]
        public string? Email { get; set; }
        [Required]
        public string? Password { get; set; }
    }
}
