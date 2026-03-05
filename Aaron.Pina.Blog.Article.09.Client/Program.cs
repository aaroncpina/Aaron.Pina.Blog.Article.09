using Aaron.Pina.Blog.Article._09.Shared.Responses;
using Aaron.Pina.Blog.Article._09.Shared.Requests;
using static System.Net.Mime.MediaTypeNames;
using Aaron.Pina.Blog.Article._09.Client;
using Aaron.Pina.Blog.Article._09.Shared;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<TokenRepository>();
builder.Services.AddHostedService<TokenRefresherService>();
builder.Services.AddTransient(Configuration.TokenServer.TokenRefreshHandlerFactory);

foreach (var role in Roles.ValidRoles)
foreach (var (audience, port) in Api.Targets)
{
    builder.Services.AddHttpClient($"{role}-{audience}-api", Configuration.TokenServer.HttpClientSettings(port))
                    .ConfigurePrimaryHttpMessageHandler(Configuration.TokenServer.HttpMessageHandlerSettings)
                    .AddHttpMessageHandler(Configuration.TokenServer.HttpMessageHandlerFor(role, audience));
}

var app = builder.Build();

app.MapGet("/{role}/login", async (IHttpClientFactory factory, TokenRepository repository, string role) =>
{
    if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
    using var client = factory.CreateClient($"{role}-server-api");
    using var registerResponse = await client.GetAsync($"{role}/register");
    if (!registerResponse.IsSuccessStatusCode) return Results.BadRequest("Unable to register");
    var userId = await registerResponse.Content.ReadFromJsonAsync<Guid>();
    if (userId == Guid.Empty) return Results.BadRequest("Unable to parse user id");
    foreach (var audience in Api.Targets.Keys)
    {
        using var tokenResponse = await client.GetAsync($"/token?userId={userId}&audience={audience}");
        if (!tokenResponse.IsSuccessStatusCode) return Results.BadRequest($"Unable to get token for API '{audience}'");
        var token = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        if (token is null) return Results.BadRequest($"Unable to parse token for API {audience}");
        var store = repository.GetStore(role, audience);
        store.AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(token.AccessTokenExpiresIn);
        store.RefreshToken = token.RefreshToken;
        store.AccessToken = token.AccessToken;
        store.Audience = audience;
    }
    return Results.Ok("Logged in");
});

app.MapGet("/{role}/info", async (IHttpClientFactory factory, TokenRepository repository, string role) =>
{
    if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
    using var client = factory.CreateClient($"{role}-other-api");
    if (client.BaseAddress is null) return Results.BadRequest("Unable to get base address");
    var uriBuilder = new UriBuilder(client.BaseAddress) { Path = "user" };
    using var request = new HttpRequestMessage(HttpMethod.Get, uriBuilder.Uri);
    var store = repository.GetStore(role, Api.Audience.Other.Name);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", store.AccessToken);
    using var response = await client.SendAsync(request);
    if (!response.IsSuccessStatusCode) return Results.BadRequest("Unable to get user info");
    var user = await response.Content.ReadFromJsonAsync<UserResponse>();
    if (user is null) return Results.BadRequest("Unable to parse user info");
    return Results.Ok($"User Id: {user.UserId} | Role: {user.Role}");
});

app.MapGet("/admin/blacklist", async (IHttpClientFactory factory, TokenRepository repository) =>
{
    var userStore = repository.GetStore("user", Api.Audience.Other.Name);
    if (userStore.AccessTokenExpiresAt is null) return Results.BadRequest("User token not yet initialised");
    var handler = new JwtSecurityTokenHandler();
    if (!handler.CanReadToken(userStore.AccessToken)) return Results.BadRequest("Invalid access token");
    var token = handler.ReadJwtToken(userStore.AccessToken);
    var claim = token.Claims.FirstOrDefault(c => c.Type == "jti");
    if (claim is null || !Guid.TryParse(claim.Value, out var jti)) return Results.BadRequest("No jti claim found");
    var expiresIn = userStore.AccessTokenExpiresAt.Value.Subtract(DateTime.UtcNow);
    using var client = factory.CreateClient("admin-server-api");
    if (client.BaseAddress is null) return Results.BadRequest("Unable to get base address");
    var uriBuilder = new UriBuilder(client.BaseAddress) { Path = "blacklist" };
    var adminStore = repository.GetStore("admin", Api.Audience.Server.Name);
    using var request = new HttpRequestMessage(HttpMethod.Post, uriBuilder.Uri);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminStore.AccessToken);
    var json = JsonSerializer.Serialize(new BlacklistRequest(jti, expiresIn.TotalSeconds));
    request.Content = new StringContent(json, Encoding.UTF8, Application.Json);
    var response = await client.SendAsync(request);
    if (!response.IsSuccessStatusCode) return Results.BadRequest("Unable to blacklist token");
    return Results.Ok("Token blacklisted");
});

app.Run();
