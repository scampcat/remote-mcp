using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Net.Http;
using Authentication.Configuration;
using Authentication.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;

namespace Tools;

/// <summary>
/// MCP tools for enterprise authentication flows with automatic browser launching.
/// Uses proper service resolution for remote MCP service architecture.
/// </summary>
[McpServerToolType]
public static class AuthenticationTools
{
    private static IServiceProvider? _serviceProvider;
    
    /// <summary>
    /// Initialize service provider for remote MCP service (called during startup)
    /// </summary>
    internal static void Initialize(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    /// <summary>
    /// Get service from DI container (following enterprise patterns for remote services)
    /// </summary>
    private static T GetService<T>() where T : notnull
    {
        if (_serviceProvider == null)
            throw new InvalidOperationException("AuthenticationTools not initialized with service provider");
        return _serviceProvider.GetRequiredService<T>();
    }
    /// <summary>
    /// Triggers OAuth 2.1 authentication flow by automatically opening browser.
    /// Uses session-based authentication for MCP integration.
    /// </summary>
    [McpServerTool]
    [Description("Start OAuth authentication flow - automatically opens browser for user authentication")]
    public static async Task<string> StartOAuthAuthentication(
        [Description("Force interactive authentication: login=force credentials, select_account=show picker, consent=force consent, none=silent")] string prompt = "select_account")
    {
        try
        {
            // Use proper DI service resolution (CLAUDE.md compliant)
            var authConfigMonitor = GetService<IOptionsMonitor<AuthenticationConfiguration>>();
            
            var authConfig = authConfigMonitor.CurrentValue;
            
            // Build the local authentication endpoint URL for session-based flow
            var authUrl = $"http://localhost:3001/auth/login?prompt={prompt}";

            // Automatically open browser for session-based authentication
            OpenBrowser(authUrl);

            return $@"✅ Authentication flow started!

🌐 Browser opened automatically for session-based authentication

📋 Session Authentication Flow:
   • Browser will handle OAuth flow
   • Session cookie will be created upon successful authentication
   • MCP clients can use the session for API access
   • Session duration: 8 hours with sliding expiration

🔄 Next steps:
   1. Complete authentication in the opened browser
   2. Browser will show: {GetPromptDescription(prompt)}
   3. Session will be established automatically
   4. Use CheckAuthenticationStatus() to verify session";
        }
        catch (Exception ex)
        {
            return $"❌ Failed to start OAuth flow: {ex.Message}";
        }
    }

    /// <summary>
    /// Opens WebAuthn registration flow in browser.
    /// </summary>
    [McpServerTool]
    [Description("Start WebAuthn biometric registration - automatically opens browser for security key/fingerprint setup")]
    public static async Task<string> StartWebAuthnRegistration()
    {
        try
        {
            var webAuthnUrl = "http://localhost:3001/webauthn/register";
            
            // Automatically open browser
            OpenBrowser(webAuthnUrl);

            return $@"✅ WebAuthn registration started!

🌐 Browser opened automatically: {webAuthnUrl}

🔐 Available methods:
   • Fingerprint authentication
   • Face recognition (Windows Hello, Touch ID)  
   • Hardware security keys (YubiKey, etc.)
   • Platform authenticators

📱 Instructions:
   1. Follow the browser prompts
   2. Choose your preferred authentication method
   3. Complete biometric/security key setup
   4. Use this credential for future OAuth flows";
        }
        catch (Exception ex)
        {
            return $"❌ Failed to start WebAuthn registration: {ex.Message}";
        }
    }

    /// <summary>
    /// Check authentication status and get current tokens.
    /// </summary>
    [McpServerTool]
    [Description("Check current authentication status and available tokens")]
    public static async Task<string> CheckAuthenticationStatus()
    {
        try
        {
            // Check authentication status via dedicated endpoint
            using var client = new HttpClient();
            
            // Include cookies for session-based authentication
            var cookieContainer = new System.Net.CookieContainer();
            var handler = new HttpClientHandler { CookieContainer = cookieContainer };
            using var sessionClient = new HttpClient(handler);
            
            var response = await sessionClient.GetAsync("http://localhost:3001/auth/status");
            
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                return $@"❌ Not authenticated

🔓 Status: No valid session or authentication token
🔑 To authenticate, run: StartOAuthAuthentication() or StartWebAuthnRegistration()

Available endpoints:
• OAuth Login: http://localhost:3001/auth/login
• OAuth 2.1: http://localhost:3001/authorize
• WebAuthn: http://localhost:3001/webauthn/register
• Protected resource: http://localhost:3001/protected";
            }
            else if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                return $@"✅ Authenticated successfully!

🔐 Status: Valid session or authentication token active
📄 Authentication info: {content}";
            }
            else
            {
                return $"⚠️ Authentication status unclear: {response.StatusCode}";
            }
        }
        catch (Exception ex)
        {
            return $"❌ Failed to check auth status: {ex.Message}";
        }
    }

    // Duplicate PKCE methods removed - now using centralized ICryptographicUtilityService

    /// <summary>
    /// Describes what the user will see based on the prompt parameter (Microsoft documentation).
    /// </summary>
    private static string GetPromptDescription(string prompt)
    {
        return prompt.ToLower() switch
        {
            "login" => "Credential entry screen (ignores existing login)",
            "select_account" => "Account picker (recommended for SSO scenarios)",
            "consent" => "Permission consent dialog",
            "none" => "Silent authentication (no user interaction)",
            _ => "Default authentication flow"
        };
    }

    /// <summary>
    /// Cross-platform browser opening.
    /// </summary>
    private static void OpenBrowser(string url)
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url);
            }
            else
            {
                throw new PlatformNotSupportedException("Cannot open browser on this platform");
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to open browser: {ex.Message}", ex);
        }
    }
}