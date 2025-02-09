using System.ComponentModel.DataAnnotations;

namespace backend.Data.Entities;

public class InviteCode
{
    [Key]
    public Guid Code { get; set; }
    public bool IsUsed { get; set; }
    public Guid? IssuerId { get; set; }

    public InviteCode(string userId) : this(Guid.Parse(userId)) { }
    public InviteCode(User user) : this(user.Id) { }
    public InviteCode(Guid userid) : this()
    {
        IssuerId = userid;
    }
    public InviteCode()
    {
        Code = Guid.NewGuid();
        IsUsed = false;
    }

}