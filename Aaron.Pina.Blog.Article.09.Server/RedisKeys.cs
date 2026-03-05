namespace Aaron.Pina.Blog.Article._09.Server;

public static class RedisKeys
{
    private const string Root = "jwt-server";
    
    public static string Blacklist(string jti)  => $"{Root}:blacklist:{jti}";
    public static string CurrentKid()           => $"{Root}:jwks:current-kid";   // points to the active signing key
    public static string PrivateKey(string kid) => $"{Root}:jwks:private:{kid}"; // full private material (short life)
    public static string PublicKey(string kid)  => $"{Root}:jwks:public:{kid}";  // public material only (long life)
    public static string KeyHistory()           => $"{Root}:jwks:key-history";   // simple list of every KID we have ever used
}
