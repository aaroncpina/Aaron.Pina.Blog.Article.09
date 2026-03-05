namespace Aaron.Pina.Blog.Article._09.Server;

public class UserEntity
{
    public Guid   Id   { get; init; } = Guid.NewGuid();
    public string Role { get; init; } = string.Empty;
}
