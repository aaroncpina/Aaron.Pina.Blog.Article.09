namespace Aaron.Pina.Blog.Article._09.Server;

public class TokenConfig
{
    public TimeSpan AccessTokenLifetime  { get; init; }
    public TimeSpan RefreshTokenLifetime { get; init; }
}
