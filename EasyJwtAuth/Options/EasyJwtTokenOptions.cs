namespace EasyJwtAuth
{
    /// <summary>
    /// The Jwt token options
    /// </summary>
    public class EasyJwtTokenOptions
    {
        public string AudienceId { set; get; }
        public string Issuer { set; get; }
        public string Secret { set; get; }
        public EasyJwtTokenOptions(string audienceId, string issuer, string secret)
        {
            AudienceId = audienceId;
            Issuer = issuer;
            Secret = secret;
        }
    }
}
