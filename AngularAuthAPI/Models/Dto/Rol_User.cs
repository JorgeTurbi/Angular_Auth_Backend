namespace AngularAuthAPI.Models.Dto
{
    public class Rol_User
    {
        public int Id { get; set; }
        public Roles rol { get; set; }
        public User user { get; set; }
    }
}
