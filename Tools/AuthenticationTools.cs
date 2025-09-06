using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
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
    /// </summary>
    [McpServerTool]
    [Description("Start OAuth authentication flow - automatically opens browser for user authentication")]
    public static async Task<string> StartOAuthAuthentication(
        [Description("The redirect URI where the auth code will be sent")] string redirectUri = "",
        [Description("Random state parameter for CSRF protection")] string state = "",
        [Description("Force interactive authentication: login=force credentials, select_account=show picker, consent=force consent, none=silent")] string prompt = "select_account")
    {
        try
        {
            // Use proper DI service resolution (CLAUDE.md compliant)
            var authConfigMonitor = GetService<IOptionsMonitor<AuthenticationConfiguration>>();
            var cryptographicService = GetService<ICryptographicUtilityService>();
            
            var authConfig = authConfigMonitor.CurrentValue;
            var azureConfig = authConfig.ExternalIdP?.AzureAD;
            
            if (azureConfig == null || string.IsNullOrEmpty(azureConfig.Authority) || string.IsNullOrEmpty(azureConfig.ClientId))
            {
                return "❌ Azure AD configuration missing in appsettings.json Authentication:ExternalIdP:AzureAD section";
            }

            // Use first configured redirect URI if not provided - following enterprise configuration patterns
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = azureConfig.RedirectUris?.FirstOrDefault();
                if (string.IsNullOrEmpty(redirectUri))
                {
                    return "❌ No redirect URIs configured in appsettings.json Authentication:ExternalIdP:AzureAD:RedirectUris";
                }
            }

            // Generate secure state if not provided using cryptographic service
            if (string.IsNullOrEmpty(state))
            {
                var stateBytes = cryptographicService.GenerateSecureRandomBytes(16);
                state = cryptographicService.ToBase64Url(stateBytes);
            }

            // Generate PKCE challenge using centralized cryptographic service (OAuth 2.1 requirement)
            var codeVerifier = cryptographicService.GenerateCodeVerifier();
            var codeChallenge = cryptographicService.GenerateCodeChallenge(codeVerifier);

            // Build Microsoft OAuth 2.0 authorization URL using explicit variables (CLAUDE.md compliance)
            var clientId = azureConfig.ClientId;
            var authority = azureConfig.Authority;
            var scope = Uri.EscapeDataString("User.Read openid profile");
            var redirectUriEncoded = Uri.EscapeDataString(redirectUri);
            
            var authUrl = $"{authority}/oauth2/v2.0/authorize?" +
                         $"client_id={clientId}" +
                         $"&response_type=code" +
                         $"&redirect_uri={redirectUriEncoded}" +
                         $"&scope={scope}" +
                         $"&state={state}" +
                         $"&code_challenge={codeChallenge}" +
                         $"&code_challenge_method=S256" +
                         $"&prompt={prompt}";

            // Automatically open browser
            OpenBrowser(authUrl);

            return $@"✅ Authentication flow started!

🌐 Browser opened automatically: {authUrl}

📋 Details:
   • State: {state}
   • Code Verifier: {codeVerifier}
   • Redirect URI: {redirectUri}
   • Scope: mcp:tools User.Read

🔄 Next steps:
   1. Complete authentication in the opened browser
   2. Azure AD will show: {GetPromptDescription(prompt)}
   3. You'll be redirected to: {redirectUri}
   4. Use the authorization code to get access tokens";
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
            // Test protected endpoint to check auth status
            using var client = new HttpClient();
            var response = await client.GetAsync("http://localhost:3001/protected");
            
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                return $@"❌ Not authenticated

🔓 Status: No valid authentication token
🔑 To authenticate, run: StartOAuthAuthentication() or StartWebAuthnRegistration()

Available endpoints:
• OAuth 2.1: http://localhost:3001/authorize
• WebAuthn: http://localhost:3001/webauthn/register
• Protected resource: http://localhost:3001/protected";
            }
            else if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                return $@"✅ Authenticated successfully!

🔐 Status: Valid authentication token active
📄 Protected resource response: {content}";
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