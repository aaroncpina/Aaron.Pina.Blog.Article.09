namespace Aaron.Pina.Blog.Article._09.Server;

public class TokenRepository(ServerDbContext dbContext)
{
    public void SaveToken(TokenEntity token)
    {
        dbContext.Tokens.Add(token);
        dbContext.SaveChanges();
    }

    public void UpdateToken(TokenEntity token)
    {
        dbContext.Tokens.Update(token);
        dbContext.SaveChanges();
    }

    public TokenEntity? TryGetTokenByUserIdAndAudience(Guid userId, string audience) =>
        dbContext.Tokens.FirstOrDefault(t => t.UserId == userId && t.Audience == audience);

    public TokenEntity? TryGetTokenByRefreshTokenAndAudience(string refreshToken, string audience) =>
        dbContext.Tokens.FirstOrDefault(t => t.RefreshToken == refreshToken && t.Audience == audience);
}
