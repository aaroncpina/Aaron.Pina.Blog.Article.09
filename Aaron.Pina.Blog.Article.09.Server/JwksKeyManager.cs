using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text.Json;

namespace Aaron.Pina.Blog.Article._09.Server;

public class JwksKeyManager(IDistributedCache cache, IOptionsSnapshot<JwksConfig> options)
{
    private readonly DistributedCacheEntryOptions _privateKeyOptions = new()
        { AbsoluteExpirationRelativeToNow = options.Value.PrivateKeyLifetime };

    private readonly DistributedCacheEntryOptions _publicKeyOptions = new()
        { AbsoluteExpirationRelativeToNow = options.Value.PublicKeyLifetime };
    
    public async Task<RsaSecurityKey> GetOrCreateSigningKeyAsync()
    {
        var currentKid = await cache.GetStringAsync(RedisKeys.CurrentKid());
        if (string.IsNullOrEmpty(currentKid)) return await RotateSigningKeyAsync();
        var signingKey = await LoadKeyAsync(currentKid, true);
        if (signingKey is not null) return signingKey;
        return await RotateSigningKeyAsync();
    }

    public async Task<RsaSecurityKey> RotateSigningKeyAsync()
    {
        using var rsa = RSA.Create(2048);
        var kid = Guid.CreateVersion7().ToString();
        var (publicJson, _) = SerialiseKey(rsa, kid, false);
        var (privateJson, privateParameters) = SerialiseKey(rsa, kid, true);
        await cache.SetStringAsync(RedisKeys.PrivateKey(kid), privateJson, _privateKeyOptions);
        await cache.SetStringAsync(RedisKeys.PublicKey(kid), publicJson, _publicKeyOptions);
        await cache.SetStringAsync(RedisKeys.CurrentKid(), kid, _publicKeyOptions);
        await AddKidToHistoryAsync(kid);
        return new RsaSecurityKey(privateParameters) { KeyId = kid };
    }

    public async Task<JsonWebKeySet> GetAllPublicKeysAsync()
    {
        var kids = await GetKeyHistoryAsync();
        var jwks = new JsonWebKeySet();
        var dead = new List<string>();
        foreach (var kid in kids)
        {
            var key = await LoadKeyAsync(kid, false);
            if (key is null)
            {
                dead.Add(kid);
                continue;
            }
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            jwk.Alg = SecurityAlgorithms.RsaSha256;
            jwk.Use = "sig";
            jwk.Kid = kid;
            jwks.Keys.Add(jwk);
        }
        if (dead.Count > 0) await PruneDeadKidsAsync(kids, dead);
        return jwks;
    }
    
    public async Task RevokeKeyAsync(string kid)
    {
        await cache.RemoveAsync(RedisKeys.PrivateKey(kid));
        await cache.RemoveAsync(RedisKeys.PublicKey(kid));
        var history = await GetKeyHistoryAsync();
        history.Remove(kid);
        var json = JsonSerializer.Serialize(history);
        await cache.SetStringAsync(RedisKeys.KeyHistory(), json, _publicKeyOptions);
        var currentKid = await cache.GetStringAsync(RedisKeys.CurrentKid());
        if (currentKid == kid) await cache.RemoveAsync(RedisKeys.CurrentKid());
    }

    private static (string, RSAParameters) SerialiseKey(RSA rsa, string kid, bool includePrivate)
    {
        var parameters = rsa.ExportParameters(includePrivate);
        var key = new RsaKey(parameters, kid);
        var json = JsonSerializer.Serialize(key);
        return (json, parameters);
    }
    
    private async Task<RsaSecurityKey?> LoadKeyAsync(string kid, bool includePrivate)
    {
        var keyName = includePrivate ? RedisKeys.PrivateKey(kid) : RedisKeys.PublicKey(kid);
        var json = await cache.GetStringAsync(keyName);
        if (json is null) return null;
        var rsaKey = JsonSerializer.Deserialize<RsaKey>(json);
        if (rsaKey is null) return null;
        var parameters = includePrivate ? rsaKey.ToRsaParameters() : rsaKey.ToPublicRsaParameters();
        return new RsaSecurityKey(parameters) { KeyId = kid };
    }
    
    private async Task<List<string>> GetKeyHistoryAsync()
    {
        var json = await cache.GetStringAsync(RedisKeys.KeyHistory());
        return json is null ? [] : JsonSerializer.Deserialize<List<string>>(json) ?? [];
    }

    private async Task AddKidToHistoryAsync(string kid)
    {
        var history = await GetKeyHistoryAsync();
        if (history.Contains(kid)) return;
        history.Add(kid);
        var json = JsonSerializer.Serialize(history);
        await cache.SetStringAsync(RedisKeys.KeyHistory(), json, _publicKeyOptions);
    }

    private async Task PruneDeadKidsAsync(List<string> kids, List<string> dead)
    {
        var history = kids.Except(dead).ToList();
        var json = JsonSerializer.Serialize(history);
        await cache.SetStringAsync(RedisKeys.KeyHistory(), json, _publicKeyOptions);
    }
}
