using JWTs.Models;
using JWTs.Models.Interfaces;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace JWTs.Services
{
    public interface IDAL
    {
        Task<IAuthorizationCode> GetAuthorizationCodeAsync(string code, string redirect_uri, bool markInactive);
        Task<IAuthorizationCode> CreateAuthorizationCodeAsync(string subject, string code, string redirect_uri, string scope, int lifespanMin, string createdByIP, Dictionary<string, object> additionalJWTClaims = null);

        Task<IRefreshToken> GetRefreshTokenAsync(string refreshToken);
        Task<IRefreshToken> AddRefreshTokenAsync(string subject, string refreshToken, int refreshTokenExpirationDays, string createdByIP, Dictionary<string, object> additionalJWTClaims = null);
        Task<bool> RevokeRefreshTokenAsync(IRefreshToken refreshToken, DateTime revokedTime, string revokedByIp, IRefreshToken replacedByToken);
    }
}
