# EasyJwtAuth
Provides easy JWT Authentication into your MVC and WebAPI projects.

Setup Jwt Authentication into your MVC and WebAPI projects in a few lines of code.

## Code Example
```c#
//The JWT options the that will be used by the Token server and Authenticator.
var easyJwtTokenOptions = new EasyJwtTokenOptions(audienceId, issuer, secret);

//This will setup a JWT token server endpoint at "/oauth2/token", validate the user and setup user claims.
app.UseEasyJwtAuthorizationServer(new CustomOAuthProvider(), easyJwtTokenOptions);

//This will setup the JWT token authentication within your application.
app.UseEasyJwtAuthentication(easyJwtTokenOptions);
```
## Motivation
Setting up JWT bearer authentication wihtin your web projects doesn't need to be difficult :)

## Installation
Create a new or use an existing ASP web project and target .NET 4.6.1

Install EasyJwtAuth via Nuget: 
```c#
Install-Package EasyJwtAuth
```

Add some appSettings in your Web.config
```c#
  <appSettings>
    <add key="audienceId" value="414e1927a3884f68abc79f7283837fd1" />
    <add key="issuer" value="http://localhost/" />
    <add key="secret" value="IxrAjDoa2FqElO7IhrSrUJELhUckePEPVpaePlS_Xaw" />
  </appSettings>
```

Create a OAuthProvider or find an existing one that implments OAuthAuthorizationServerProvider to validate your logins eg:
```c#
      public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            if (context.UserName != context.Password)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect");
                context.Rejected();
                return Task.FromResult<object>(null);
            }

            var identity = new ClaimsIdentity("JWT");
            identity.AddClaim(new Claim(ClaimTypes.Role, "User"));
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));

            var ticket = new AuthenticationTicket(identity, null);
            context.Validated(ticket);
            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            return Task.FromResult<object>(null);
        }
    }
```

Open your App_Start folder and edit the Startup.Auth.cs file:

```c#
  <appSettings>
    <add key="audienceId" value="414e1927a3884f68abc79f7283837fd1" />
    <add key="issuer" value="http://localhost/" />
    <add key="secret" value="IxrAjDoa2FqElO7IhrSrUJELhUckePEPVpaePlS_Xaw" />
  </appSettings>
```

Create a OAuthProvider or find an existing one that implments OAuthAuthorizationServerProvider to validate your logins eg:
```c#
    public partial class Startup
    {
        public static string PublicClientId { get; private set; }

        private readonly string audienceId = ConfigurationManager.AppSettings["audienceId"];
        private readonly string issuer = ConfigurationManager.AppSettings["issuer"];
        private readonly string secret = ConfigurationManager.AppSettings["secret"];

        public void ConfigureAuth(IAppBuilder app)
        {
            var easyJwtTokenOptions = new EasyJwtTokenOptions(audienceId, issuer, secret);
            app.UseEasyJwtAuthorizationServer(new CustomOAuthProvider(), easyJwtTokenOptions);
            app.UseEasyJwtAuthentication(easyJwtTokenOptions);
        }
    }
```

Test your authentication:

## API Reference
```c#
//The JWT token server has option that can be changed.
var easyJwtAuthorizationServerOptions = new EasyJwtAuthorizationServerOptions();
easyJwtAuthorizationServerOptions.AllowInsecureHttp = true;
easyJwtAuthorizationServerOptions.TokenEndpointPath = "/oauth2/token";
easyJwtAuthorizationServerOptions.AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30);
app.UseEasyJwtAuthorizationServer(easyJwtAuthorizationServerOptions, new CustomOAuthProvider(), easyJwtTokenOptions);
```

## License
The current license is MIT.
