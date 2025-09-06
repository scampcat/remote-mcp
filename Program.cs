using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Text.Json;
using System.Reflection;
using Authentication.Configuration;
using Authentication.Interfaces;
using Authentication.Services;
using Authentication.Middleware;
using Authentication.OAuth;
using Authentication.WebAuthn;
using Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Authentication.Models;
using Services;
using Authentication.Services;
using Configuration;

// Handle CLI commands for service management
if (args.Length > 0)
{
    var command = args[0].ToLowerInvariant();
    var serviceManager = new ServiceManager();
    
    switch (command)
    {
        case "--daemon":
        case "daemon":
            Console.WriteLine("Starting Remote MCP Server as daemon...");
            break;
            
        case "--status":
        case "status":
            await serviceManager.ShowStatusAsync();
            return;
            
        case "--stop":
        case "stop":
            await serviceManager.StopServiceAsync();
            return;
            
        case "--install-service":
        case "install-service":
            await serviceManager.InstallServiceAsync();
            return;
            
        case "--uninstall-service":
        case "uninstall-service":
            await serviceManager.UninstallServiceAsync();
            return;
            
        case "--help":
        case "help":
        case "-h":
            ShowHelp();
            return;
            
        default:
            if (!command.StartsWith("--"))
            {
                Console.WriteLine($"Unknown command: {command}");
                ShowHelp();
                return;
            }
            break;
    }
}

static void ShowHelp()
{
    Console.WriteLine("Remote MCP Server - Cross-platform service hosting");
    Console.WriteLine();
    Console.WriteLine("Usage: remote-mcp [command]");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  daemon             Run as background daemon/service");
    Console.WriteLine("  status             Show service status");
    Console.WriteLine("  stop               Stop running service");
    Console.WriteLine("  install-service    Install as system service");
    Console.WriteLine("  uninstall-service  Remove system service");
    Console.WriteLine("  help               Show this help");
    Console.WriteLine();
    Console.WriteLine("Default (no command): Run as interactive server");
}

var builder = WebApplication.CreateBuilder(args);

// Configure cross-platform service hosting
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Remote MCP Server";
});

builder.Services.AddSystemd();

// Add background service for lifecycle management
builder.Services.AddHostedService<McpServerLifecycleService>();

// Configure logging to stderr (MCP convention) with UTC timestamps
builder.Logging.AddConsole(consoleLogOptions =>
{
    consoleLogOptions.LogToStandardErrorThreshold = LogLevel.Trace;
    consoleLogOptions.TimestampFormat = "[yyyy-MM-dd HH:mm:ss UTC] ";
    consoleLogOptions.UseUtcTimestamp = true;
});

// Register MCP server with HTTP transport (Streamable HTTP)
builder.Services.AddMcpServer()
    .WithHttpTransport()
    .WithToolsFromAssembly();

// Configure enterprise authentication services
builder.Services.Configure<AuthenticationConfiguration>(
    builder.Configuration.GetSection(AuthenticationConfiguration.SectionName));

// Configure server settings
builder.Services.Configure<ServerConfiguration>(
    builder.Configuration.GetSection(ServerConfiguration.SectionName));

// Register authentication services following Microsoft DI patterns
// Use consistent lifetimes to avoid DI violations

// Application Services (per-request scope for proper lifecycle)
builder.Services.AddScoped<IAuthenticationModeProvider, AuthenticationModeProvider>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IMultiTenantTokenService, MultiTenantTokenService>();

// Domain Layer (scoped to maintain consistency boundary)
builder.Services.AddScoped<Authentication.Domain.Services.IAuthenticationDomainService, Authentication.Domain.Services.AuthenticationDomainService>();

// Infrastructure Layer (scoped for database connection lifetime)
builder.Services.AddScoped<Authentication.Domain.Repositories.IUserRepository, Authentication.Infrastructure.Repositories.InMemoryUserRepository>();

// Enterprise Services (scoped for dependency consistency)
builder.Services.AddScoped<IEnterpriseOAuthPolicyService, EnterpriseOAuthPolicyService>();
builder.Services.AddScoped<IClientCertificateService, ClientCertificateService>();
builder.Services.AddScoped<IEnterpriseWebAuthnService, EnterpriseWebAuthnService>();
builder.Services.AddScoped<IPasswordlessAIAuthFlow, PasswordlessAIAuthFlow>();

// OAuth endpoint providers removed for clean state

// Register rate limiting service
builder.Services.AddSingleton<IRateLimitingService, RateLimitingService>();

// Register SOLID key management service
builder.Services.AddSingleton<ICryptographicUtilityService, Authentication.Domain.Services.CryptographicUtilityService>();
builder.Services.AddSingleton<ISigningKeyService, SigningKeyService>();

// Register OAuth endpoint provider services
builder.Services.AddScoped<SimpleOAuthEndpointProvider>();
builder.Services.AddScoped<LocalOAuthEndpointProvider>();
builder.Services.AddScoped<IOAuthEndpointProviderFactory, OAuthEndpointProviderFactory>();

// Add standard ASP.NET Core JWT Bearer authentication using SigningKeyService
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        // Configuration will be completed by ConfigureJwtBearerOptions below
    });

// Configure JWT Bearer options using proper IConfigureNamedOptions pattern
builder.Services.ConfigureOptions<ConfigureJwtBearerOptions>();

builder.Services.AddAuthorization();

// Add session support for OAuth and WebAuthn  
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(8); // Extend for OAuth sessions
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Lax; // Fix: Use Lax for localhost OAuth flow
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

// Configure authentication database (in-memory for development)
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseInMemoryDatabase("AuthDatabase");
});

// Add CORS for browser-based MCP clients
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// Initialize AuthenticationTools with service provider for remote MCP service
Tools.AuthenticationTools.Initialize(app.Services);

// Enable CORS middleware
app.UseCors();

// CRITICAL DEBUG: Log ALL HTTP requests to understand mcp-remote behavior
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogCritical("🌐 HTTP REQUEST: {Method} {Path} {QueryString}", 
        context.Request.Method, context.Request.Path, context.Request.QueryString);
    await next();
});

// Add session support for WebAuthn challenges
app.UseSession();

// Add enterprise security middleware (before MCP mapping)  
app.UseMiddleware<RateLimitingMiddleware>();

// Add OAuth 2.1 bearer token security middleware
app.UseMiddleware<OAuth21BearerTokenSecurityMiddleware>();

// Enable OAuth discovery and implementation endpoints (BEFORE authentication middleware)
app.MapOAuthEndpoints();
app.MapOAuthImplementationEndpoints();
app.MapWebAuthnEndpoints();

// Use standard ASP.NET Core authentication/authorization
app.UseAuthentication();
app.UseAuthorization();

// Map MCP endpoints with authentication required for enterprise security
app.MapMcp().RequireAuthorization();

// Optional: Add a health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

// Optional: Add server info endpoint for debugging
app.MapGet("/info", () => Results.Json(new 
{ 
    name = "Remote MCP Server",
    version = "1.0.0",
    transport = "streamable-http",
    endpoints = new 
    {
        mcp = "/mcp",
        health = "/health",
        protected_demo = "/protected",
        oauth_auth = "/authorize"
    },
    description = "A remote MCP server built with C# and ASP.NET Core"
}));

// Add protected test endpoint for OAuth 2.1 testing
app.MapGet("/protected", () => Results.Json(new 
{
    message = "Success! You have accessed a protected endpoint.",
    timestamp = DateTime.UtcNow,
    user = "authenticated_user",
    scope = "mcp:tools"
})).RequireAuthorization();

// Start server - use configuration from appsettings.json
var serverConfig = app.Configuration.GetSection(ServerConfiguration.SectionName).Get<ServerConfiguration>() ?? new ServerConfiguration();
var serverUrl = serverConfig.GetUrl();
app.Run(serverUrl);

// Make Program class accessible for testing  
public partial class Program { }

/// <summary>
/// MCP Tools - All classes marked with [McpServerToolType] are automatically registered
/// Tool implementations are located in the Tools/ directory for better organization
/// </summary>