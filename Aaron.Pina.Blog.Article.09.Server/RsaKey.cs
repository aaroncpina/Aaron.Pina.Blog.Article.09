using System.Security.Cryptography;

namespace Aaron.Pina.Blog.Article._09.Server;

public class RsaKey
{
    public string Kid      { get; init; } = string.Empty;
    public byte[] Modulus  { get; init; } = [];
    public byte[] Exponent { get; init; } = [];
    public byte[] D        { get; init; } = [];
    public byte[] P        { get; init; } = [];
    public byte[] Q        { get; init; } = [];
    public byte[] Dp       { get; init; } = [];
    public byte[] Dq       { get; init; } = [];
    public byte[] InverseQ { get; init; } = [];

    public RsaKey(RSAParameters p, string kid)
    {
        Kid      = kid;
        Modulus  = p.Modulus  ?? [];
        Exponent = p.Exponent ?? [];
        D        = p.D        ?? [];
        P        = p.P        ?? [];
        Q        = p.Q        ?? [];
        Dp       = p.DP       ?? [];
        Dq       = p.DQ       ?? [];
        InverseQ = p.InverseQ ?? [];
    }

    public RsaKey() { }

    public RSAParameters ToRsaParameters() => new()
    {
        Modulus = Modulus, Exponent = Exponent, D = D, P = P, Q = Q,
        DP = Dp, DQ = Dq, InverseQ = InverseQ
    };

    public RSAParameters ToPublicRsaParameters() => new()
    {
        Exponent = Exponent,
        Modulus = Modulus
    };
}
