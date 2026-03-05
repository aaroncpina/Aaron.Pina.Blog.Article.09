using Aaron.Pina.Blog.Article._09.Shared;

namespace Aaron.Pina.Blog.Article._09.Client;

public class TokenRepository
{
    public Dictionary<string, Dictionary<string, TokenStore>> TokenStores { get; } =
        Roles.ValidRoles.ToDictionary(r => r, _ => Api.Targets.Keys.ToDictionary(a => a, _ => new TokenStore()));

    public TokenStore GetStore(string role, string audience) => TokenStores[role][audience];
}
