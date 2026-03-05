namespace Aaron.Pina.Blog.Article._09.Client;

public static class Configuration
{
    public static class TokenServer
    {
        public static Action<HttpClient> HttpClientSettings(int port) =>
            client =>
            {
                client.BaseAddress = new Uri($"https://localhost:{port}");
                client.Timeout = TimeSpan.FromSeconds(10);
            };

        public static HttpMessageHandler HttpMessageHandlerSettings() =>
            new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

        public static Func<IServiceProvider, DelegatingHandler> HttpMessageHandlerFor(string role, string audience) =>
            provider =>
            {
                var factory = provider.GetRequiredService<Func<string, string, TokenRefreshHandler>>();
                return factory(role, audience);
            };

        public static Func<string, string, TokenRefreshHandler> TokenRefreshHandlerFactory(IServiceProvider provider) =>
            (role, audience) =>
            {
                var repository = provider.GetRequiredService<TokenRepository>();
                return new TokenRefreshHandler(repository.GetStore(role, audience));
            };
    }
}
