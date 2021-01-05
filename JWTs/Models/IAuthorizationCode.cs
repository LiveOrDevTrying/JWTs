using System;

namespace JWTs.Models
{
    public interface IAuthorizationCode
    {
        string Code { get; set; }
        DateTime Created { get; set; }
        string CreatedByIp { get; set; }
        DateTime Expires { get; set; }
        bool IsExpired { get; }
        string RedirectURI { get; set; }
        string Scope { get; set; }
    }
}