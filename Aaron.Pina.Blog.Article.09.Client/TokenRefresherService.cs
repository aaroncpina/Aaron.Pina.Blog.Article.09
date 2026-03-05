using Aaron.Pina.Blog.Article._09.Shared.Responses;
using Aaron.Pina.Blog.Article._09.Shared;

namespace Aaron.Pina.Blog.Article._09.Client;

public class TokenRefresherService(
    IHttpClientFactory factory,
    IServiceProvider serviceProvider,
    ILogger<TokenRefresherService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            try
            {
                logger.LogInformation("Proactively checking expiry of tokens");
                using var scope = serviceProvider.CreateScope();
                var repository = scope.ServiceProvider.GetRequiredService<TokenRepository>();
                foreach (var (_, audiences) in repository.TokenStores)
                foreach (var (_, store) in audiences)
                {
                    if (!store.IsInitialised)
                    {
                        logger.LogInformation("TokenStores still uninitialised");
                        continue;
                    }
                    var expiresIn = store.AccessTokenExpiresAt!.Value.Subtract(DateTime.UtcNow);
                    if (expiresIn > TimeSpan.FromMinutes(5))
                    {
                        logger.LogInformation("Access token expires in {ExpiresIn} minutes", expiresIn.TotalMinutes);
                        continue;
                    }
                    var client = factory.CreateClient("server-api");
                    var url = $"{Api.UrlFor(Api.Audience.Server.Name)}/refresh";
                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    request.Content = new FormUrlEncodedContent([
                        new KeyValuePair<string, string>("refresh_token", store.RefreshToken),
                        new KeyValuePair<string, string>("audience", store.Audience)
                    ]);
                    logger.LogInformation("Calling server to refresh tokens");
                    using var response = await client.SendAsync(request, stoppingToken);
                    if (!response.IsSuccessStatusCode)
                    {
                        logger.LogWarning("Server refresh token response failed");
                        continue;
                    }
                    var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>(stoppingToken);
                    if (tokens is null)
                    {
                        logger.LogWarning("Refresh token response content was invalid");
                        continue;
                    }
                    store.AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(tokens.AccessTokenExpiresIn);
                    store.RefreshToken = tokens.RefreshToken;
                    store.AccessToken = tokens.AccessToken;
                }
                logger.LogInformation("Refreshed tokens");
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Unexpected error in proactive token refresh loop");
            }
        }
    }
}
