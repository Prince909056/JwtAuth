﻿namespace JwtAuth.Models.Dto
{
    public class LoginResponse : Status
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime? Expiration { get; set; }
        public string Name { get; set; }
        public string UserName { get; set; }
    }
}
