using Microsoft.EntityFrameworkCore;

namespace Aaron.Pina.Blog.Article._09.Server;

public class ServerDbContext(DbContextOptions<ServerDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TokenEntity>()
                    .Property(t => t.RefreshToken)
                    .HasMaxLength(512);

        modelBuilder.Entity<TokenEntity>()
                    .Property(t => t.Audience)
                    .HasMaxLength(128);

        modelBuilder.Entity<TokenEntity>()
                    .HasIndex(t => new { t.UserId, t.Audience })
                    .IsUnique();

        modelBuilder.Entity<UserEntity>()
                    .Property(t => t.Role)
                    .HasMaxLength(512);
    }
    
    public DbSet<TokenEntity> Tokens => Set<TokenEntity>();
    public DbSet<UserEntity>  Users =>  Set<UserEntity>();
}
