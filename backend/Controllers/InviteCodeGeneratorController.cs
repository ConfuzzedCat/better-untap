using System.Security.Claims;
using backend.Data.Entities;
using backend.Data.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize(Roles = "admin,trusted")]
public class InviteCodeGeneratorController : ControllerBase
{
    private readonly ILogger<InviteCodeGeneratorController> _logger;
    private readonly IInviteCodeService _codeService;
    private readonly UserManager<User> _userManager;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public InviteCodeGeneratorController(ILogger<InviteCodeGeneratorController> logger, IInviteCodeService codeService, UserManager<User> userManager, IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _codeService = codeService;
        _userManager = userManager;
        _httpContextAccessor = httpContextAccessor;
    }

    [HttpGet(Name = "GetNewCode")]
    public async Task<InviteCode> Get()
    {
        var claims = _httpContextAccessor.HttpContext?.User;
        if (claims is null)
        {
            return await _codeService.GenerateNewCode(null);
        }
        var user = await _userManager.GetUserAsync(claims);
        return await _codeService.GenerateNewCode(user);
    }
}