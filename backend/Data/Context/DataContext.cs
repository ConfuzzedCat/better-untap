using backend.Data.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
//using backend.Data.Entities;

namespace backend.Data.Context;

public class DataContext : IdentityDbContext<User>
{
    public DbSet<InviteCode> InviteCodesDb { get; set; }
    public DataContext()
    {
    }

    public DataContext(DbContextOptions<DataContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }
}
