using Microsoft.AspNetCore.Identity;

namespace backend.Data.Entities;

public class User : IdentityUser
{
    public int GameWins { get; set; }
    public int GameLosses { get; set; }
    public int GameTies { get; set; }
    public int GameTotal { get; set; }
    public TimeSpan GameTime { get; set; }
    public DateTime CreationDate { get; set; }
    public Guid? InviteCode { get; set; }
    public bool isDeleted { get; set; }

    public User()
    {
        GameWins = 0;
        GameLosses = 0;
        GameTies = 0;
        GameTotal = 0;
        GameTime = TimeSpan.Zero;
        CreationDate = DateTime.UtcNow;
        isDeleted = false;
    }

    public User(string username) : base(username)
    {
        GameWins = 0;
        GameLosses = 0;
        GameTies = 0;
        GameTotal = 0;
        GameTime = TimeSpan.Zero;
        CreationDate = DateTime.UtcNow;
        isDeleted = false;
    }

    public User(Guid _InviteCode) : this()
    {
        InviteCode = _InviteCode;
    } 
    public User(InviteCode code) : this(code.Code) {}
}