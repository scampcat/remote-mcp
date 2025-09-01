using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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

var builder = WebApplication.CreateBuilder(args);

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

// Register authentication services following SOLID principles
builder.Services.AddSingleton<IAuthenticationModeProvider, AuthenticationModeProvider>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IMultiTenantTokenService, MultiTenantTokenService>();
builder.Services.AddSingleton<IEnterpriseOAuthPolicyService, EnterpriseOAuthPolicyService>();
builder.Services.AddSingleton<IClientCertificateService, ClientCertificateService>();
builder.Services.AddSingleton<IEnterpriseWebAuthnService, EnterpriseWebAuthnService>();
builder.Services.AddSingleton<IPasswordlessAIAuthFlow, PasswordlessAIAuthFlow>();

// Register external identity provider services
builder.Services.AddHttpClient<IAzureADTokenValidator, AzureADTokenValidator>();

// Register OAuth endpoint providers following SOLID principles
builder.Services.AddSingleton<IOAuthEndpointProvider, LocalOAuthEndpointProvider>();
builder.Services.AddSingleton<IOAuthEndpointProvider, AzureADOAuthEndpointProvider>();
builder.Services.AddSingleton<IOAuthEndpointProviderFactory, OAuthEndpointProviderFactory>();

// Register rate limiting service
builder.Services.AddSingleton<IRateLimitingService, RateLimitingService>();

// Add session support for WebAuthn challenges  
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(8); // Extend for OAuth sessions
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.None;
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

// Enable CORS middleware
app.UseCors();

// Add session support for WebAuthn challenges
app.UseSession();

// Add enterprise security middleware (before MCP mapping)  
app.UseMiddleware<RateLimitingMiddleware>();
app.UseMiddleware<AuthenticationMiddleware>();

// Map OAuth 2.1 discovery endpoints (before MCP endpoints)
app.MapOAuthEndpoints();

// Map OAuth 2.1 implementation endpoints
app.MapOAuthImplementationEndpoints();

// Map WebAuthn enterprise endpoints
app.MapWebAuthnEndpoints();

// Map MCP endpoints (creates /mcp endpoint for Streamable HTTP transport)
app.MapMcp();

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
        health = "/health"
    },
    description = "A remote MCP server built with C# and ASP.NET Core"
}));

// Start server - listen on all interfaces for network access
app.Run("http://0.0.0.0:3001");

/// <summary>
/// MCP Tools - All classes marked with [McpServerToolType] are automatically registered
/// Tool implementations are located in the Tools/ directory for better organization
/// </summary>