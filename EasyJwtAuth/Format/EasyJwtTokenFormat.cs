namespace EasyJwtAuth.Format
{
    using Microsoft.IdentityModel.Tokens;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler.Encoder;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;

    /// <summary>
    /// Signs and validates JWT tokens.
    /// </summary>
    public class EasyJwtTokenFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private const string IssuedAtClaimName = "iat";
        private const string ExpiryClaimName = "exp";
        private const string JwtIdClaimName = "jti";
        private static DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private readonly List<string> _allowedAudiences = new List<string>();

        private readonly string audienceId;
        private readonly string issuer;
        private readonly byte[] secret;

        public EasyJwtTokenFormat(EasyJwtTokenOptions jwtTokenOptions)
        {
            this.audienceId = jwtTokenOptions.AudienceId;
            this.issuer = jwtTokenOptions.Issuer;
            this.secret = TextEncodings.Base64Url.Decode(jwtTokenOptions.Secret);
        }

        /// <summary>
        /// Sign the JWT token
        /// </summary>
        /// <param name="data">The data the JWT token will contain</param>
        /// <returns>The JWT token</returns>
        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var signingKey = new SymmetricSecurityKey(this.secret);
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;

            if (!issued.HasValue || !expires.HasValue)
            {
                return null;
            }

            var jwtSecurityToken = new JwtSecurityToken(this.issuer, this.audienceId, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingCredentials);
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            return jwtSecurityTokenHandler;
        }

        /// <summary>
        /// Validate the JWT token
        /// </summary>
        /// <param name="protectedText">The JWT Token</param>
        /// <returns>The user identity information</returns>
        public AuthenticationTicket Unprotect(string protectedText)
        {
            if (string.IsNullOrWhiteSpace(protectedText))
            {
                throw new ArgumentNullException("protectedText");
            }

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadToken(protectedText) as JwtSecurityToken;

            if (token == null)
            {
                throw new ArgumentOutOfRangeException("protectedText", "Invalid JWT Token");
            }

            var validationParameters = new TokenValidationParameters { IssuerSigningKey = new SymmetricSecurityKey(this.secret), ValidAudiences = new[] { audienceId }, ValidateIssuer = true, ValidIssuer = this.issuer, ValidateLifetime = true, ValidateAudience = true, ValidateIssuerSigningKey = true };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken = null;

            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(protectedText, validationParameters, out validatedToken);
            var claimsIdentity = (ClaimsIdentity)claimsPrincipal.Identity;

            var authenticationExtra = new AuthenticationProperties(new Dictionary<string, string>());
            if (claimsIdentity.Claims.Any(c => c.Type == ExpiryClaimName))
            {
                string expiryClaim = (from c in claimsIdentity.Claims where c.Type == ExpiryClaimName select c.Value).Single();
                authenticationExtra.ExpiresUtc = _epoch.AddSeconds(Convert.ToInt64(expiryClaim, CultureInfo.InvariantCulture));
            }

            if (claimsIdentity.Claims.Any(c => c.Type == IssuedAtClaimName))
            {
                string issued = (from c in claimsIdentity.Claims where c.Type == IssuedAtClaimName select c.Value).Single();
                authenticationExtra.IssuedUtc = _epoch.AddSeconds(Convert.ToInt64(issued, CultureInfo.InvariantCulture));
            }

            var returnedIdentity = new ClaimsIdentity(claimsIdentity.Claims, "JWT");

            return new AuthenticationTicket(returnedIdentity, authenticationExtra);
        }
    }
}