namespace EasyJwtAuth
{
    using System;
    /// <summary>
    /// The EasyJwt token server config options
    /// </summary>
    public class EasyJwtAuthorizationServerOptions
    {
        public bool AllowInsecureHttp { set; get; } = true;
        public string TokenEndpointPath { set; get; } = "/oauth2/token";
        public TimeSpan AccessTokenExpireTimeSpan { set; get; } = TimeSpan.FromMinutes(30);
    }
}
