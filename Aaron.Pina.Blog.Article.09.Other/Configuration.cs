using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._09.Shared;
using Microsoft.IdentityModel.Tokens;

namespace Aaron.Pina.Blog.Article._09.Other;

public static class Configuration
{
    public static class JwtBearer
    {
        public static readonly Action<JwtBearerOptions> Options = options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ClockSkew = TimeSpan.Zero,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuer = true
            };
            options.MapInboundClaims = false;
            options.RequireHttpsMetadata = false;
            options.Audience = Api.Audience.Other.Name;
            options.Authority = Api.UrlFor(Api.Audience.Server.Name);
        };
    }
}
