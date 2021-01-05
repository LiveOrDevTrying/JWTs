using System;

namespace JWTs.Models
{
    public interface IRefreshToken
    {
        DateTime Created { get; set; }
        string CreatedByIp { get; set; }
        DateTime Expires { get; set; }
        bool IsActive { get; }
        bool IsExpired { get; }
        DateTime? Revoked { get; set; }
        string RevokedByIp { get; set; }
        string Scopes { get; set; }
        string Token { get; set; }
    }
}