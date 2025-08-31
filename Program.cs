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
using Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Configure logging to stderr (MCP convention)
builder.Logging.AddConsole(consoleLogOptions =>
{
    consoleLogOptions.LogToStandardErrorThreshold = LogLevel.Trace;
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
// WebAuthn service registration - implementation in progress

// Add session support for WebAuthn challenges
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(10);
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

// Add enterprise authentication middleware (before MCP mapping)
app.UseMiddleware<AuthenticationMiddleware>();

// Map OAuth 2.1 discovery endpoints (before MCP endpoints)
app.MapOAuthEndpoints();

// Map OAuth 2.1 implementation endpoints
app.MapOAuthImplementationEndpoints();

// WebAuthn endpoints - implementation in progress for Sprint 5

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