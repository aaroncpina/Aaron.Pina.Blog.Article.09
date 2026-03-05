using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._09.Shared.Responses;
using Aaron.Pina.Blog.Article._09.Shared.Requests;
using Microsoft.Extensions.Caching.Distributed;
using Aaron.Pina.Blog.Article._09.Shared;
using Aaron.Pina.Blog.Article._09.Server;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStackExchangeRedisCache(Configuration.RedisCache.Options);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(Configuration.JwtBearer.Options);
builder.Services.AddAuthorization(Configuration.Authorisation.Options);
builder.Services.AddScoped<TokenRepository>();
builder.Services.AddScoped<UserRepository>();
builder.Services.AddScoped<JwksKeyManager>();
builder.Services.AddDbContext<ServerDbContext>(Configuration.DbContext.Options);
builder.Services.Configure<JwksConfig>(builder.Configuration.GetSection(nameof(JwksConfig)));
builder.Services.Configure<TokenConfig>(builder.Configuration.GetSection(nameof(TokenConfig)));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<ServerDbContext>().Database.EnsureCreated();

app.MapGet("/.well-known/openid-configuration", () => Results.Json(
        new
        {
            Issuer  = "https://localhost:5001",
            JwksUri = "https://localhost:5001/.well-known/jwks.json"
        },
        new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower }))
   .AllowAnonymous();

app.MapGet("/.well-known/jwks.json", async (JwksKeyManager keyManager) =>
    {
        var jwks = await keyManager.GetAllPublicKeysAsync();
        return Results.Json(jwks);
    })
   .WithName("JWKS")
   .AllowAnonymous();

app.MapGet("/{role}/register", (UserRepository repo, string role) =>
    {
        if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            Role = role
        };
        repo.AddUser(user);
        return Results.Ok(user.Id);
    })
   .AllowAnonymous();

app.MapGet("/token", async
    (IOptionsSnapshot<TokenConfig> config,
     JwksKeyManager keyManager,
     TokenRepository tokenRepo,
     UserRepository userRepo,
     string audience,
     Guid userId) =>
    {
        if (!Api.IsValidTarget(audience)) return Results.BadRequest("Invalid audience");
        var token = tokenRepo.TryGetTokenByUserIdAndAudience(userId, audience);
        if (token is not null)
        {
            return Results.BadRequest(new
            {
                Error = "User already has an active token for this audience",
                Message = "Use the /refresh endpoint with your refresh token to get a new token"
            });
        }
        var user = userRepo.TryGetUserById(userId);
        if (user is null) return Results.BadRequest("Invalid user id");
        var jti = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var signingKey = await keyManager.GetOrCreateSigningKeyAsync();
        var refreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(
            signingKey, jti, userId, user.Role, audience, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(
            jti, accessToken, refreshToken, config.Value.AccessTokenLifetime.TotalMinutes);
        tokenRepo.SaveToken(new TokenEntity
        {
            RefreshTokenExpiresAt = now.Add(config.Value.RefreshTokenLifetime),
            RefreshToken = refreshToken,
            Audience = audience,
            UserId = userId,
            CreatedAt = now
        });
        return Results.Ok(response);
    })
   .AllowAnonymous();

app.MapPost("/refresh", async
    (IOptionsSnapshot<TokenConfig> config,
     JwksKeyManager keyManager,
     TokenRepository tokenRepo,
     UserRepository userRepo,
     HttpContext context) =>
    {
        var refreshToken = context.Request.Form["refresh_token"].FirstOrDefault();
        if (string.IsNullOrEmpty(refreshToken)) return Results.BadRequest();
        var audience = context.Request.Form["audience"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(audience) || !Api.IsValidTarget(audience))
            return Results.BadRequest("Invalid audience");
        var token = tokenRepo.TryGetTokenByRefreshTokenAndAudience(refreshToken, audience);
        if (token is null) return Results.BadRequest();
        if (token.RefreshTokenExpiresAt < DateTime.UtcNow)
        {
            return Results.BadRequest(new
            {
                Error = "Refresh token has expired",
                Message = "Please login again to get a new token"
            });
        }
        var user = userRepo.TryGetUserById(token.UserId);
        if (user is null) return Results.BadRequest("Invalid user id");
        var jti = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var signingKey = await keyManager.GetOrCreateSigningKeyAsync();
        var newRefreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(
            signingKey, jti, token.UserId, user.Role, audience, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(
            jti, accessToken, newRefreshToken, config.Value.AccessTokenLifetime.TotalMinutes);
        token.RefreshTokenExpiresAt = now.Add(config.Value.RefreshTokenLifetime);
        token.RefreshToken = newRefreshToken;
        tokenRepo.UpdateToken(token);
        return Results.Ok(response);
    })
   .AllowAnonymous();

app.MapPost("/rotate-key", async (JwksKeyManager keyManager) =>
    {
        var key = await keyManager.RotateSigningKeyAsync();
        return Results.Ok(new { Kid = key.KeyId, Message = "Key rotated successfully" });
    })
   .RequireAuthorization("admin");

app.MapPost("/revoke-key/{kid}", async (JwksKeyManager keyManager, string kid) =>
    {
        await keyManager.RevokeKeyAsync(kid);
        return Results.Ok(new { Message = $"Key {kid} has been revoked" });
    })
   .RequireAuthorization("admin");

app.MapPost("/blacklist", async (IDistributedCache blacklist, BlacklistRequest request) =>
    {
        var expires = DateTimeOffset.UtcNow.AddSeconds(request.AccessTokenExpiresIn);
        if (expires < DateTimeOffset.UtcNow) return Results.BadRequest("Token already expired");
        await blacklist.SetStringAsync(RedisKeys.Blacklist(request.Jti.ToString()), "revoked",
            new DistributedCacheEntryOptions { AbsoluteExpiration = expires });
        return Results.Ok();
    })
   .RequireAuthorization("admin");

app.Run();
