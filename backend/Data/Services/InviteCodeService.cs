using backend.Data.Context;
using backend.Data.Entities;
using backend.Data.Services.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace backend.Data.Services;

public class InviteCodeService : IInviteCodeService
{
    
    private readonly DataContext _context;
    private readonly ILogger<InviteCodeService> _logger;

    public InviteCodeService(DataContext context, ILogger<InviteCodeService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<InviteCode> GenerateNewCode(User? user)
    {
        InviteCode code;
        if (user is not null)
        {
            code = new InviteCode(user);
        }
        else
        {
            code = new InviteCode();
        }

        await _context.InviteCodesDb.AddAsync(code);
        await _context.SaveChangesAsync();
        return code;
    }

    public async Task<InviteCode?> FindCode(Guid code)
    {
        try
        {
            return await _context.InviteCodesDb.FirstAsync(c => c.Code == code);
        }
        catch (InvalidOperationException e)
        {
            _logger.LogError(e, "Couldn't find invite code: {code}", code);
            return null;
        }
    }

    public async Task<List<InviteCode>> GetAllCodesByUser(User user)
    {
        return await _context.InviteCodesDb.Where(c => c.IssuerId != null && c.IssuerId.ToString() == user.Id).ToListAsync();
    }

    public async Task<List<InviteCode>> GetAllCodes()
    {
        return await _context.InviteCodesDb.ToListAsync();
    }

    public async Task<List<InviteCode>> GetAllCodesByStatus(bool isUsed = false)
    {
        return await _context.InviteCodesDb.Where(c => c.IsUsed == isUsed).ToListAsync();
    }

    public async Task<bool> SetCodeStatus(Guid code, bool isUsed = true)
    {
        try
        {
            var inviteCode = await _context.InviteCodesDb.FirstAsync(c => c.Code == code);
            inviteCode.IsUsed = isUsed;
            _context.Update(inviteCode);
            await _context.SaveChangesAsync();
            return true;
        }
        catch (InvalidOperationException e)
        {
            _logger.LogError(e, "Couldn't find invite code: {code}", code);
            return false;
        }
    }

    public async Task<bool> DeleteCode(Guid code)
    {
        try
        {
            var inviteCode = await _context.InviteCodesDb.FirstAsync(c => c.Code == code);
            _context.Remove(inviteCode);
            return true;
        }
        catch (InvalidOperationException e)
        {
            _logger.LogError(e, "Couldn't find invite code: {code}", code);
            return false;
        }
    }

    public async Task DeleteCodesByUser(User user)
    {
        var inviteCodes = await _context.InviteCodesDb.Where(c => c.IssuerId != null && c.IssuerId.ToString() == user.Id).ToListAsync();
        _context.RemoveRange(inviteCodes);
    }

    public async Task<bool> ValidateCode(Guid inviteCode)
    {
        try
        {
            var code = await _context.InviteCodesDb.FirstAsync(c => c.Code == inviteCode && c.IsUsed == false);
            return true;
        }
        catch (InvalidOperationException e)
        {
            _logger.LogError(e, "Couldn't validate invite code: {code}", inviteCode);
            return false;
        }
    }
}