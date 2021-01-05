using JWTs.Models;
using JWTs.Services;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace JWTs
{
    public interface IJWTService
    {
        Task<IAuthorizationCode> GenerateAuthorizationCodeAsync(string subject, string redirect_uri, string scope, int lifespanMin, string createdByIP, IDAL dal, Dictionary<string, object> additionalClaims = null);
        Task<IAuthorizationCode> GetAuthorizationCodeAsync(string code, string redirect_uri, bool markInactive, IDAL dal);

        Task<bool> RevokeRefreshTokenAsync(string refreshToken, string ipaddress, IRefreshToken replacedByToken, IDAL dal);
        
        Task<IToken> GenerateTokenAsync(string subject, string audience, string issuerURI, string state, int tokenExpirationMin, string symmetricSigningKey, Dictionary<string, object> additionalJWTClaims = null);
        Task<(IToken, IRefreshToken)> GenerateTokenWithRefreshTokenAsync(string subject, string audience, string issuerURI, string state, int tokenExpirationMin, string symmetricSigningKey, string ipAddressIssuingToken, int refreshTokenExpirationDays, IDAL dal, Dictionary<string, object> additionalJWTClaims = null);
        JwtSecurityToken DecodeToken(string token);
        Task<bool> ValidateTokenAsync(string token, string audience, string issuerURI, string signingKey, bool validateSigningKey, bool valdateIssuer, bool validateAudience);
    }
}