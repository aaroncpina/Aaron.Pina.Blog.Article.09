using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Distributed;
using Aaron.Pina.Blog.Article._09.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Aaron.Pina.Blog.Article._09.Server;

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
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    var jti = context.Principal?.FindFirstValue("jti");
                    if (string.IsNullOrEmpty(jti)) return;
                    var services = context.HttpContext.RequestServices;
                    var blacklist = services.GetRequiredService<IDistributedCache>();
                    var val = await blacklist.GetStringAsync(RedisKeys.Blacklist(jti));
                    if (val != "revoked") return;
                    context.Fail("Token has been invalidated");
                    var logger = services.GetRequiredService<ILogger<Program>>();
                    logger.LogWarning("Token {Jti} has been invalidated", jti);
                }
            };
            options.MapInboundClaims = false;
            options.RequireHttpsMetadata = false;
            options.Audience = Api.Audience.Server.Name;
            options.Authority = Api.UrlFor(Api.Audience.Server.Name);
        };
    }

    public static class Authorisation
    {
        public static void Options(AuthorizationOptions options)
        {
            options.AddPolicy("admin", policy =>
                policy.RequireAuthenticatedUser()
                      .RequireClaim("role", "admin"));
        }
    }
    
    public static class DbContext
    {
        public static void Options(DbContextOptionsBuilder builder) =>
            builder.UseSqlite("Data Source=server.db");
    }

    public static class RedisCache
    {
        public static void Options(RedisCacheOptions options)
        {
            options.Configuration = "localhost:6379";
        }
    }
}
