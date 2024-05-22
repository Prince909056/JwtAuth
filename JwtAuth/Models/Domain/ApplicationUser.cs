using Microsoft.AspNetCore.Identity;

namespace JwtAuth.Models.Domain
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }
    }
}
