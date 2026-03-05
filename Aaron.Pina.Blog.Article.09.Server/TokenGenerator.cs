using Aaron.Pina.Blog.Article._09.Shared;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Buffers.Text;

namespace Aaron.Pina.Blog.Article._09.Server;

public static class TokenGenerator
{
    public static string GenerateToken(
        RsaSecurityKey rsaKey,
        Guid jti,
        Guid userId,
        string role,
        string audience,
        DateTime now,
        TimeSpan expiresIn)
    {
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            IssuedAt = now,
            Audience = audience,
            Expires = now.Add(expiresIn),
            Issuer = Api.UrlFor(Api.Audience.Server.Name),
            Subject = new ClaimsIdentity([
                new Claim("role", role),
                new Claim("jti", jti.ToString()),
                new Claim("sub", userId.ToString())
            ]),
            SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
        };
        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }

    public static string GenerateRefreshToken(int length = 32) =>
        Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(length));
}
