using JWTs.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JWTs.Services;

namespace JWTs
{
    public class JWTService : IJWTService
    {
        // Audience must be specified because one client could have multiple audiences
        public virtual Task<IToken> GenerateTokenAsync(
            string subject,
            string audience,
            string issuerURI,
            string state,
            int tokenExpirationMin,
            string symmetricSigningKey,
            Dictionary<string, object> additionalJWTClaims = null)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(symmetricSigningKey);

            var claims = new Dictionary<string, object>();

            if (additionalJWTClaims != null)
            {
                foreach (var item in additionalJWTClaims)
                {
                    claims.Add(item.Key, item.Value);
                }
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = subject != null ? new ClaimsIdentity(new[] { new Claim("sub", subject.ToString()) }) : new ClaimsIdentity(),
                Expires = DateTime.UtcNow.AddMinutes(tokenExpirationMin),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = audience,
                Issuer = issuerURI,
                IssuedAt = DateTime.UtcNow,
                Claims = claims
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            // What are potential token_type? Bearer, jwt, id token,? what else
            return Task.FromResult(new Token
            {
                access_token = tokenHandler.WriteToken(token),
                expires_in = (int)TimeSpan.FromMinutes(tokenExpirationMin).TotalSeconds,
                refresh_token = null,
                state = state,
                token_type = "Bearer"
            } as IToken);
        }
        public virtual async Task<(IToken, IRefreshToken)> GenerateTokenWithRefreshTokenAsync(
          string subject,
          string audience,
          string issuerURI,
          string state,
          int tokenExpirationMin,
          string symmetricSigningKey,
          string ipAddressIssuingToken,
          int refreshTokenExpirationDays,
          IDAL dal,
          Dictionary<string, object> additionalJWTClaims = null)
        {
            var token = await GenerateTokenAsync(subject, audience, issuerURI, state, tokenExpirationMin, symmetricSigningKey, additionalJWTClaims);
            
            var refreshToken = await dal.AddRefreshTokenAsync(subject, GenerateRandomTokenString(), refreshTokenExpirationDays, ipAddressIssuingToken, additionalJWTClaims);
            token.refresh_token = refreshToken.Token;
            
            return (token, refreshToken);
        }
        public virtual Task<bool> ValidateTokenAsync(string token, string audience, string issuerURI, string signingKey, bool validateSigningKey, bool valdateIssuer, bool validateAudience)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                // Random Guid is for Implicit clients that do not verify signing key
                var key = !string.IsNullOrWhiteSpace(signingKey) ? Encoding.UTF8.GetBytes(signingKey) : Encoding.UTF8.GetBytes(Guid.NewGuid().ToString());

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = validateSigningKey,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = valdateIssuer,
                    ValidateAudience = validateAudience,
                    ValidAudience = audience,
                    ValidIssuer = issuerURI,
                    // Set clockskew to 0 so tokens expire exactly at token expiration instead of 5 minutes later
                    ClockSkew = TimeSpan.Zero
                }, out var validatedToken);

                return Task.FromResult(true);
            }
            catch
            { }

            return Task.FromResult(false);
        }
        public virtual JwtSecurityToken DecodeToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.ReadJwtToken(token);
        }
        public virtual async Task<bool> RevokeRefreshTokenAsync(string refreshToken, string ipaddress, IRefreshToken replacedByToken, IDAL dal)
        {
            var refreshTokenEntity = await dal.GetRefreshTokenAsync(refreshToken);

            refreshTokenEntity.Revoked = DateTime.UtcNow;
            refreshTokenEntity.RevokedByIp = ipaddress;

            return await dal.RevokeRefreshTokenAsync(refreshTokenEntity, DateTime.UtcNow, ipaddress, replacedByToken);
        }

        public virtual async Task<IAuthorizationCode> GenerateAuthorizationCodeAsync(string subject, string redirect_uri, string scope, int lifespanMin, string createdByIP, IDAL dal, Dictionary<string, object> additionalClaims = null)
        {
            return await dal.CreateAuthorizationCodeAsync(subject, GenerateRandomTokenString(), redirect_uri, scope, lifespanMin, createdByIP, additionalClaims);
        }
        public virtual async Task<IAuthorizationCode> GetAuthorizationCodeAsync(string code, string redirect_uri, bool markInactive, IDAL dal)
        {
            return await dal.GetAuthorizationCodeAsync(code, redirect_uri, true);
        }

        protected virtual string GenerateRandomTokenString()
        {
            using var cryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            cryptoServiceProvider.GetBytes(randomBytes);

            // Convert random bytes to a hex string
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }
    }
}
