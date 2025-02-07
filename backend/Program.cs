using backend.Data.Context;
using backend.Data.Entities;
using backend.Data.Services;
using backend.Data.Services.Interfaces;
using backend.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Configuration;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;

namespace backend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddScoped<IInviteCodeService, InviteCodeService>();

        builder.Services.AddControllers();
        // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
        //builder.Services.AddOpenApi();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(options =>
        {
            options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header,
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey
            });
            
            options.OperationFilter<SecurityRequirementsOperationFilter>();
        });

        builder.Services.AddDbContext<DataContext>(opt =>
            opt.UseNpgsql(builder.Configuration.GetConnectionString("Dev")));

        builder.Services.AddAuthorization();
        builder.Services.AddIdentityApiEndpoints<User>()
            .AddEntityFrameworkStores<DataContext>();
        
        builder.Services.Configure<IdentityOptions>(options =>
        {
            // Default User settings.
            options.User.AllowedUserNameCharacters =
                "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ0123456789-._@+";
        });
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = "NordtapCookie";
            options.ExpireTimeSpan = TimeSpan.FromDays(365);
        });
        
        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            //app.MapOpenApi();
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.MapIdentityApiCustom();

        app.UseHttpsRedirection();

        app.UseAuthorization();


        app.MapControllers();

        app.Run();
    }
}