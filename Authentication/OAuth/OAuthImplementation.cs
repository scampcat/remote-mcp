using Authentication.Configuration;
using Authentication.Services;
using Authentication.OAuth;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Authentication.OAuth;

/// <summary>
/// OAuth 2.1 authorization and token endpoint implementations.
/// Follows enterprise security patterns with PKCE and comprehensive validation.
/// </summary>
public static class OAuthImplementation
{
    /// <summary>
    /// Maps working OAuth authorization and token endpoints.
    /// </summary>
    public static void MapOAuthImplementationEndpoints(this WebApplication app)
    {
        // OAuth authorization endpoint
        app.MapGet("/authorize", async (HttpContext context, 
            IOptionsMonitor<AuthenticationConfiguration> authConfig,
            ILogger<ITokenService> logger) => 
            await HandleAuthorizationRequestAsync(context, authConfig, logger));

        app.MapPost("/authorize", async (HttpContext context,
            IOptionsMonitor<AuthenticationConfiguration> authConfig,
            ITokenService tokenService,
            ILogger<ITokenService> logger) =>
            await HandleAuthorizationPostAsync(context, authConfig, tokenService, logger));

        // OAuth token endpoint  
        app.MapPost("/token", async (HttpContext context,
            IOptionsMonitor<AuthenticationConfiguration> authConfig,
            ITokenService tokenService,
            ILogger<ITokenService> logger) =>
            await HandleTokenRequestAsync(context, authConfig, tokenService, logger));
    }

    /// <summary>
    /// Handles OAuth authorization GET request - shows login form.
    /// </summary>
    private static async Task<IResult> HandleAuthorizationRequestAsync(
        HttpContext context,
        IOptionsMonitor<AuthenticationConfiguration> authConfig,
        ILogger logger)
    {
        try
        {
            var query = context.Request.Query;
            
            // Validate required OAuth parameters
            if (!query.ContainsKey("client_id") || !query.ContainsKey("redirect_uri") || 
                !query.ContainsKey("code_challenge"))
            {
                return Results.BadRequest("Missing required OAuth parameters");
            }

            var clientId = query["client_id"].ToString();
            var redirectUri = query["redirect_uri"].ToString();
            var state = query["state"].ToString();
            var codeChallenge = query["code_challenge"].ToString();
            var codeChallengeMethod = query["code_challenge_method"].ToString();

            // Basic client validation (in development mode)
            if (string.IsNullOrEmpty(clientId))
            {
                return Results.BadRequest("Invalid client_id");
            }

            // Show simple login form for development
            var loginHtml = CreateLoginForm(clientId, redirectUri, state, codeChallenge, codeChallengeMethod);
            
            logger.LogDebug("Showing authorization form for client {ClientId}", clientId);
            
            return Results.Content(loginHtml, "text/html");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error handling authorization request");
            return Results.Problem("Authorization error");
        }
    }

    /// <summary>
    /// Handles OAuth authorization POST request - processes login.
    /// </summary>
    private static async Task<IResult> HandleAuthorizationPostAsync(
        HttpContext context,
        IOptionsMonitor<AuthenticationConfiguration> authConfig,
        ITokenService tokenService,
        ILogger logger)
    {
        try
        {
            var form = await context.Request.ReadFormAsync();
            
            var username = form["username"].ToString();
            var password = form["password"].ToString();
            var clientId = form["client_id"].ToString();
            var redirectUri = form["redirect_uri"].ToString();
            var state = form["state"].ToString();
            var codeChallenge = form["code_challenge"].ToString();

            // Simple authentication for development (enterprise will integrate with IdP)
            if (IsValidTestUser(username, password))
            {
                // Create authorization code
                var authCode = GenerateAuthorizationCode();
                
                // Store code with PKCE challenge (in-memory for development)
                StoreAuthorizationCode(authCode, new AuthorizationCodeData
                {
                    ClientId = clientId,
                    UserId = username,
                    CodeChallenge = codeChallenge,
                    RedirectUri = redirectUri,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5)
                });

                // Redirect back to client with authorization code
                var redirectUrl = $"{redirectUri}?code={authCode}";
                if (!string.IsNullOrEmpty(state))
                {
                    redirectUrl += $"&state={state}";
                }

                logger.LogInformation("Authorization successful for user {User} client {Client}", 
                    username, clientId);

                return Results.Redirect(redirectUrl);
            }
            else
            {
                logger.LogWarning("Authentication failed for user {User}", username);
                return Results.Unauthorized();
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing authorization request");
            return Results.Problem("Authorization processing error");
        }
    }

    /// <summary>
    /// Handles OAuth token exchange request with PKCE validation.
    /// </summary>
    private static async Task<IResult> HandleTokenRequestAsync(
        HttpContext context,
        IOptionsMonitor<AuthenticationConfiguration> authConfig,
        ITokenService tokenService,
        ILogger logger)
    {
        try
        {
            var form = await context.Request.ReadFormAsync();
            
            var grantType = form["grant_type"].ToString();
            var code = form["code"].ToString();
            var redirectUri = form["redirect_uri"].ToString();
            var clientId = form["client_id"].ToString();
            var codeVerifier = form["code_verifier"].ToString();

            if (grantType != "authorization_code")
            {
                return Results.BadRequest(new { error = "unsupported_grant_type" });
            }

            // Retrieve and validate authorization code
            var codeData = GetAuthorizationCode(code);
            if (codeData == null)
            {
                logger.LogWarning("Invalid authorization code {Code}", code);
                return Results.BadRequest(new { error = "invalid_grant" });
            }

            if (codeData.ExpiresAt < DateTime.UtcNow)
            {
                logger.LogWarning("Expired authorization code {Code}", code);
                RemoveAuthorizationCode(code);
                return Results.BadRequest(new { error = "invalid_grant" });
            }

            // Validate PKCE
            if (!ValidatePKCE(codeData.CodeChallenge, codeVerifier))
            {
                logger.LogWarning("PKCE validation failed for code {Code}", code);
                RemoveAuthorizationCode(code);
                return Results.BadRequest(new { error = "invalid_grant" });
            }

            // Validate client and redirect URI
            if (codeData.ClientId != clientId || codeData.RedirectUri != redirectUri)
            {
                logger.LogWarning("Client validation failed for code {Code}", code);
                RemoveAuthorizationCode(code);
                return Results.BadRequest(new { error = "invalid_client" });
            }

            // Create user principal
            var identity = new ClaimsIdentity("oauth");
            identity.AddClaim(new Claim(ClaimTypes.Name, codeData.UserId));
            identity.AddClaim(new Claim("client_id", clientId));
            var user = new ClaimsPrincipal(identity);

            // Create tokens
            var accessToken = await tokenService.CreateAccessTokenAsync(
                user, clientId, new[] { "mcp:tools" }, "default");
            var refreshToken = await tokenService.CreateRefreshTokenAsync(
                user, clientId, "default");

            // Remove authorization code (single use)
            RemoveAuthorizationCode(code);

            var tokenResponse = new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = (int)authConfig.CurrentValue.OAuth.AccessTokenLifetime.TotalSeconds,
                refresh_token = refreshToken,
                scope = "mcp:tools"
            };

            logger.LogInformation("Token issued for user {User} client {Client}", 
                codeData.UserId, clientId);

            return Results.Json(tokenResponse);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing token request");
            return Results.Problem("Token processing error");
        }
    }

    /// <summary>
    /// Creates HTML login form for OAuth authorization.
    /// </summary>
    private static string CreateLoginForm(string clientId, string redirectUri, string state, 
        string codeChallenge, string codeChallengeMethod)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <title>MCP Server Authentication</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }}
        .form-group {{ margin: 15px 0; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
        button {{ width: 100%; padding: 10px; background: #007cba; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #005a87; }}
        .info {{ background: #f0f8ff; padding: 10px; border-radius: 4px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class='info'>
        <h3>Enterprise MCP Server Authentication</h3>
        <p>Client: {clientId}</p>
        <p>Development Mode - Use test credentials</p>
    </div>
    
    <form method='post' action='/authorize'>
        <div class='form-group'>
            <label for='username'>Username:</label>
            <input type='text' id='username' name='username' value='test.user@company.com' required />
        </div>
        <div class='form-group'>
            <label for='password'>Password:</label>
            <input type='password' id='password' name='password' value='testpass' required />
        </div>
        
        <input type='hidden' name='client_id' value='{clientId}' />
        <input type='hidden' name='redirect_uri' value='{redirectUri}' />
        <input type='hidden' name='state' value='{state}' />
        <input type='hidden' name='code_challenge' value='{codeChallenge}' />
        <input type='hidden' name='code_challenge_method' value='{codeChallengeMethod}' />
        
        <button type='submit'>Authorize Access</button>
    </form>
    
    <div class='info' style='margin-top: 20px; font-size: 12px;'>
        <p>Development credentials: test.user@company.com / testpass</p>
        <p>This will grant access to MCP tools for the requesting application.</p>
    </div>
</body>
</html>";
    }

    /// <summary>
    /// Validates test user credentials for development.
    /// </summary>
    private static bool IsValidTestUser(string username, string password)
    {
        // Development test users - enterprise will integrate with real IdP
        var testUsers = new Dictionary<string, string>
        {
            ["test.user@company.com"] = "testpass",
            ["admin.user@company.com"] = "adminpass"
        };

        return testUsers.TryGetValue(username, out var validPassword) && validPassword == password;
    }

    /// <summary>
    /// Generates secure authorization code.
    /// </summary>
    private static string GenerateAuthorizationCode()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    /// <summary>
    /// Validates PKCE code verifier against challenge.
    /// </summary>
    private static bool ValidatePKCE(string codeChallenge, string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        var computedChallenge = Convert.ToBase64String(challengeBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        return computedChallenge == codeChallenge;
    }

    // In-memory storage for development - enterprise will use database
    private static readonly Dictionary<string, AuthorizationCodeData> _authCodes = new();

    private static void StoreAuthorizationCode(string code, AuthorizationCodeData data)
    {
        _authCodes[code] = data;
    }

    private static AuthorizationCodeData? GetAuthorizationCode(string code)
    {
        return _authCodes.TryGetValue(code, out var data) ? data : null;
    }

    private static void RemoveAuthorizationCode(string code)
    {
        _authCodes.Remove(code);
    }
}

/// <summary>
/// Authorization code data for PKCE flow.
/// </summary>
public class AuthorizationCodeData
{
    public string ClientId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string CodeChallenge { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string[] Scopes { get; set; } = Array.Empty<string>();
}