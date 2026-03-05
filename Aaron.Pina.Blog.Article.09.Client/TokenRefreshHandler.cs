using Aaron.Pina.Blog.Article._09.Shared.Responses;
using System.Net.Http.Headers;
using System.Net;

namespace Aaron.Pina.Blog.Article._09.Client;

public class TokenRefreshHandler(TokenStore store) : DelegatingHandler
{
    private readonly SemaphoreSlim _refreshLock = new(1, 1); 
    
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var response = await base.SendAsync(request, ct);
        if (response.StatusCode != HttpStatusCode.Unauthorized) return response;
        await _refreshLock.WaitAsync(ct);
        try
        {
            if (!store.IsInitialised) return response;
            if (store.AccessTokenExpiresAt!.Value < DateTime.UtcNow)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", store.AccessToken);
                return await base.SendAsync(request, ct);
            }
            var refreshRequest = new HttpRequestMessage(HttpMethod.Post, "https://localhost:5001/refresh");
            refreshRequest.Content = new FormUrlEncodedContent([
                new KeyValuePair<string, string>("refresh_token", store.RefreshToken),
                new KeyValuePair<string, string>("audience", store.Audience)
            ]);
            using var refreshResponse = await base.SendAsync(refreshRequest, ct);
            if (!refreshResponse.IsSuccessStatusCode) return response;
            var tokenResponse = await refreshResponse.Content.ReadFromJsonAsync<TokenResponse>(ct);
            if (tokenResponse is null) return response;
            store.AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(tokenResponse.AccessTokenExpiresIn);
            store.RefreshToken = tokenResponse.RefreshToken;
            store.AccessToken = tokenResponse.AccessToken;
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
            return await base.SendAsync(request, ct);
        }
        finally
        {
            _refreshLock.Release();
        }
    }
}
