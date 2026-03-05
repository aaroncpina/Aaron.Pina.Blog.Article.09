namespace Aaron.Pina.Blog.Article._09.Server;

public class UserRepository(ServerDbContext dbContext)
{
    public void AddUser(UserEntity user)
    {
        dbContext.Users.Add(user);
        dbContext.SaveChanges();
    }

    public UserEntity? TryGetUserById(Guid userId) =>
        dbContext.Users.FirstOrDefault(u => u.Id == userId);
}
