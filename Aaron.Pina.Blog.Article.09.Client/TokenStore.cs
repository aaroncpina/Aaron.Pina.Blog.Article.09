namespace Aaron.Pina.Blog.Article._09.Client;

public class TokenStore
{
    public string    Audience             { get; set; } = string.Empty;
    public string    AccessToken          { get; set; } = string.Empty;
    public string    RefreshToken         { get; set; } = string.Empty;
    public DateTime? AccessTokenExpiresAt { get; set; }

    public bool IsInitialised => AccessTokenExpiresAt.HasValue
                              && !string.IsNullOrEmpty(Audience)
                              && !string.IsNullOrEmpty(AccessToken)
                              && !string.IsNullOrEmpty(RefreshToken);
}
