using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._09.Shared.Responses;
using Aaron.Pina.Blog.Article._09.Other;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(Configuration.JwtBearer.Options);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/user", (HttpContext context) =>
    {
        var role = context.User.FindFirstValue("role");
        if (role is null) return Results.Unauthorized();
        var sub = context.User.FindFirstValue("sub");
        var parsed = Guid.TryParse(sub, out var userId); 
        if (!parsed) return Results.Unauthorized();
        return Results.Ok(new UserResponse(userId, role));
    })
   .RequireAuthorization();

app.Run();
