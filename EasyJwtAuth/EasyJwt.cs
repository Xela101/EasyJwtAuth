namespace EasyJwtAuth
{
    using Format;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.OAuth;
    using Owin;

    public static class EasyJwt
    {
        public static void UseEasyJwtAuthorizationServer(this IAppBuilder app, IOAuthAuthorizationServerProvider oAuthProvider, EasyJwtTokenOptions jwtTokenOptions)
        {
            app.UseEasyJwtAuthorizationServer(new EasyJwtAuthorizationServerOptions(), oAuthProvider, jwtTokenOptions);
        }
        public static void UseEasyJwtAuthorizationServer(this IAppBuilder app, EasyJwtAuthorizationServerOptions easyJwtAuthorizationServerOptions, IOAuthAuthorizationServerProvider oAuthProvider, EasyJwtTokenOptions jwtTokenOptions)
        {
            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = easyJwtAuthorizationServerOptions.AllowInsecureHttp,
                TokenEndpointPath = new PathString(easyJwtAuthorizationServerOptions.TokenEndpointPath),
                AccessTokenExpireTimeSpan = easyJwtAuthorizationServerOptions.AccessTokenExpireTimeSpan,
                Provider = oAuthProvider,
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "Bearer",
                AccessTokenFormat = new EasyJwtTokenFormat(jwtTokenOptions)
            });
        }
        public static void UseEasyJwtAuthentication(this IAppBuilder app, EasyJwtTokenOptions jwtTokenOptions)
        {
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AccessTokenFormat = new EasyJwtTokenFormat(jwtTokenOptions),
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "Bearer",
                Description = new AuthenticationDescription()
            });
        }
    }
}
