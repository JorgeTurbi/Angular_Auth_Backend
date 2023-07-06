namespace AngularAuthAPI.Models
{
    public class Roles
    {
        public int Id { get; set; }
        public  string Name { get; set; }       
      
        public ICollection<User> users { get; set; }
    }
}
