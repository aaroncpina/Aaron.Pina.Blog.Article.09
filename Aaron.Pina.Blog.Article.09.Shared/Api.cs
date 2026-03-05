namespace Aaron.Pina.Blog.Article._09.Shared;

public static class Api
{
    public static class Audience
    {
        public static class Server
        {
            public const string Name = "server";
        }

        public static class Other
        {
            public const string Name = "other";
        }
    }
    
    public static Dictionary<string, int> Targets { get; } = new()
    {
        [Audience.Server.Name] = 5001,
        [Audience.Other.Name]  = 5003
    };

    public static bool IsValidTarget(string target) => Targets.ContainsKey(target);

    public static string UrlFor(string target) =>
        Targets.TryGetValue(target, out var port)
            ? $"https://localhost:{port}"
            : throw new ArgumentException($"Unknown API target '{target}'", nameof(target));
}
