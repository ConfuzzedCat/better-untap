using backend.Data.Entities;

namespace backend.Data.Services.Interfaces;

public interface IInviteCodeService
{
    Task<InviteCode> GenerateNewCode(User? user);
    Task<InviteCode?> FindCode(Guid code);
    Task<List<InviteCode>> GetAllCodesByUser(User user);
    Task<List<InviteCode>> GetAllCodes();
    Task<List<InviteCode>> GetAllCodesByStatus(bool isUsed = false);
    Task<bool> SetCodeStatus(Guid code, bool isUsed = true);
    Task<bool> DeleteCode(Guid code);
    Task DeleteCodesByUser(User user);
    Task<bool> ValidateCode(Guid inviteCode);
}