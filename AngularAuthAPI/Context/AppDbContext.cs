using AngularAuthAPI.Models;
using AngularAuthAPI.Models.Dto;
using Microsoft.EntityFrameworkCore;

namespace AngularAuthAPI.Context
{
    public class AppDbContext:DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options):base(options)
        {
            
        }
        public  DbSet<User> Users { get; set; }
        public  DbSet<Roles> Roles { get; set; }
    

        protected  void onModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.Entity<User>().ToTable("users");
            modelBuilder.Entity<User>()
          .HasOne(u => u.Roles)
          .WithMany(r => r.users)
          .HasForeignKey(u => u.IdRoles);
            modelBuilder.Entity<Roles>().ToTable("Roles");
          

        }
    }
}
