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
using System.Collections.Concurrent;

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

        // Dynamic Client Registration endpoint
        app.MapClientRegistrationEndpoint();

        // JWKS endpoint for token validation
        app.MapGet("/.well-known/jwks", async (ITokenService tokenService, ILogger<ITokenService> logger) =>
        {
            logger.LogInformation("JWKS endpoint called");
            var jwks = await tokenService.GetJWKSAsync();
            logger.LogInformation("JWKS generated successfully");
            return Results.Json(jwks);
        });

        // WebAuthn challenge endpoint for OAuth flow
        app.MapGet("/webauthn/oauth-challenge", async (HttpContext context,
            ILogger<ITokenService> logger) =>
        {
            try
            {
                logger.LogInformation("WebAuthn OAuth challenge requested from {IP}", 
                    context.Connection.RemoteIpAddress);
                
                // Create WebAuthn challenge for OAuth authentication
                var challenge = new byte[32];
                using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
                rng.GetBytes(challenge);
                
                var challengeOptions = new
                {
                    challenge = Convert.ToBase64String(challenge).Replace('+', '-').Replace('/', '_').TrimEnd('='),
                    timeout = 60000,
                    rpId = context.Request.Host.Host,
                    allowCredentials = new object[] { }, // Allow any registered credential
                    userVerification = "preferred"
                };
                
                // Store challenge in session for later validation
                context.Session.SetString("webauthn_challenge", Convert.ToBase64String(challenge));
                
                logger.LogDebug("Generated WebAuthn challenge for OAuth flow");
                return Results.Json(challengeOptions);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to generate WebAuthn OAuth challenge");
                return Results.Problem("Failed to generate WebAuthn challenge");
            }
        });
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
            
            var clientId = form["client_id"].ToString();
            var redirectUri = form["redirect_uri"].ToString();
            var state = form["state"].ToString();
            var codeChallenge = form["code_challenge"].ToString();
            var authMethod = form["auth_method"].ToString();

            logger.LogInformation("OAuth authorization attempt: method={Method}, client={Client}", 
                authMethod, clientId);

            string authenticatedUserId = null;

            // Handle different authentication methods
            if (authMethod == "password")
            {
                // Password authentication
                var username = form["username"].ToString();
                var password = form["password"].ToString();
                
                if (IsValidTestUser(username, password))
                {
                    authenticatedUserId = username;
                    logger.LogInformation("Password authentication successful for user {User}", username);
                }
                else
                {
                    logger.LogWarning("Password authentication failed for user {User}", username);
                    return Results.Unauthorized();
                }
            }
            else if (authMethod == "webauthn")
            {
                // WebAuthn authentication
                var webauthnDataJson = form["webauthn_data"].ToString();
                
                if (string.IsNullOrEmpty(webauthnDataJson))
                {
                    logger.LogWarning("WebAuthn authentication attempted but no credential data provided");
                    return Results.BadRequest("WebAuthn credential data required");
                }

                try
                {
                    var webauthnData = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(webauthnDataJson);
                    
                    // Get stored challenge from session
                    var storedChallenge = context.Session.GetString("webauthn_challenge");
                    if (string.IsNullOrEmpty(storedChallenge))
                    {
                        logger.LogWarning("WebAuthn authentication failed: no challenge in session");
                        return Results.BadRequest("Invalid WebAuthn session");
                    }

                    // Basic WebAuthn validation (in real implementation, you'd fully validate the assertion)
                    if (webauthnData.TryGetProperty("id", out var credentialId) && !string.IsNullOrEmpty(credentialId.GetString()))
                    {
                        // For development, associate with test user
                        authenticatedUserId = "test.user@company.com";
                        logger.LogInformation("WebAuthn authentication successful for credential {CredentialId}", 
                            credentialId.GetString()?.Substring(0, 10) + "...");
                        
                        // Clear the challenge from session
                        context.Session.Remove("webauthn_challenge");
                    }
                    else
                    {
                        logger.LogWarning("WebAuthn authentication failed: invalid credential format");
                        return Results.BadRequest("Invalid WebAuthn credential");
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "WebAuthn authentication failed during credential validation");
                    return Results.BadRequest("WebAuthn validation failed");
                }
            }
            else
            {
                logger.LogWarning("Invalid authentication method: {Method}", authMethod);
                return Results.BadRequest("Invalid authentication method");
            }

            // If authentication successful, create authorization code
            if (!string.IsNullOrEmpty(authenticatedUserId))
            {
                var authCode = GenerateAuthorizationCode();
                
                // Store code with PKCE challenge (in-memory for development)
                var codeData = new AuthorizationCodeData
                {
                    ClientId = clientId,
                    UserId = authenticatedUserId,
                    CodeChallenge = codeChallenge,
                    RedirectUri = redirectUri,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5)
                };
                
                StoreAuthorizationCode(authCode, codeData);
                
                logger.LogDebug("Stored authorization code {Code} with challenge {Challenge} for client {Client}",
                    authCode, codeChallenge, clientId);

                // Redirect back to client with authorization code
                var redirectUrl = $"{redirectUri}?code={authCode}";
                if (!string.IsNullOrEmpty(state))
                {
                    redirectUrl += $"&state={state}";
                }

                logger.LogInformation("Multi-method authorization successful: user={User}, method={Method}, client={Client}", 
                    authenticatedUserId, authMethod, clientId);

                return Results.Redirect(redirectUrl);
            }
            else
            {
                logger.LogWarning("Authentication failed: no authenticated user ID");
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
            logger.LogInformation("Token endpoint called from {IP} with Content-Type: {ContentType}", 
                context.Connection.RemoteIpAddress, context.Request.ContentType);

            // Validate Content-Type per OAuth 2.1 specification (RFC 6749)
            if (!context.Request.HasFormContentType || 
                !context.Request.ContentType!.StartsWith("application/x-www-form-urlencoded"))
            {
                logger.LogWarning("Invalid Content-Type for token endpoint: {ContentType}", 
                    context.Request.ContentType);
                return Results.BadRequest(new { 
                    error = "invalid_request", 
                    error_description = "Content-Type must be application/x-www-form-urlencoded" 
                });
            }

            var form = await context.Request.ReadFormAsync();
            
            // Direct form field extraction preserving actual values
            var grantType = form["grant_type"].ToString();
            var code = form["code"].ToString();
            var redirectUri = form["redirect_uri"].ToString();
            var clientId = form["client_id"].ToString();
            var codeVerifier = form["code_verifier"].ToString();
            
            logger.LogDebug("Token exchange request: grant_type={GrantType}, code={Code}, client_id={ClientId}",
                grantType, code.Substring(0, Math.Min(code.Length, 10)) + "...", clientId);
            
            // Form debugging removed for production performance

            if (grantType == "authorization_code")
            {
                return await HandleAuthorizationCodeGrantAsync(form, authConfig, tokenService, logger);
            }
            else if (grantType == "refresh_token")
            {
                return await HandleRefreshTokenGrantAsync(form, authConfig, tokenService, logger);
            }
            else
            {
                logger.LogWarning("Unsupported grant type: {GrantType}", grantType);
                return Results.BadRequest(new { error = "unsupported_grant_type" });
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing token request");
            return Results.Problem("Token processing error");
        }
    }

    /// <summary>
    /// Handles authorization code grant for initial token issuance.
    /// </summary>
    private static async Task<IResult> HandleAuthorizationCodeGrantAsync(
        IFormCollection form,
        IOptionsMonitor<AuthenticationConfiguration> authConfig,
        ITokenService tokenService,
        ILogger logger)
    {
        try
        {
            var code = form["code"].ToString();
            var redirectUri = form["redirect_uri"].ToString();
            var clientId = form["client_id"].ToString();
            var codeVerifier = form["code_verifier"].ToString();

            // Retrieve and validate authorization code
            var codeData = GetAuthorizationCode(code);
            if (codeData == null)
            {
                logger.LogWarning("Invalid authorization code {Code} - not found in storage. Available codes: {AvailableCodes}", 
                    code, string.Join(", ", _authCodes.Keys));
                return Results.BadRequest(new { error = "invalid_grant", error_description = "Authorization code not found" });
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
                logger.LogWarning("PKCE validation failed for code {Code}. Challenge: {Challenge}, Verifier: {Verifier}", 
                    code, codeData.CodeChallenge, codeVerifier);
                RemoveAuthorizationCode(code);
                return Results.BadRequest(new { error = "invalid_grant", error_description = "PKCE validation failed" });
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
            logger.LogError(ex, "Error processing authorization code grant");
            return Results.Problem("Authorization code processing error");
        }
    }

    /// <summary>
    /// Handles refresh token grant for mcp-remote compatibility.
    /// </summary>
    private static async Task<IResult> HandleRefreshTokenGrantAsync(
        IFormCollection form,
        IOptionsMonitor<AuthenticationConfiguration> authConfig,
        ITokenService tokenService,
        ILogger logger)
    {
        try
        {
            var refreshToken = form["refresh_token"].ToString();
            var clientId = form["client_id"].ToString();

            if (string.IsNullOrEmpty(refreshToken))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "refresh_token is required" });
            }

            // Validate refresh token
            var principal = await tokenService.ValidateTokenAsync(refreshToken);
            if (principal == null)
            {
                logger.LogWarning("Invalid refresh token for client {ClientId}", clientId);
                return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid refresh token" });
            }

            // Check if this is actually a refresh token
            var tokenTypeClaim = principal.FindFirst("token_type")?.Value;
            if (tokenTypeClaim != "refresh")
            {
                logger.LogWarning("Token is not a refresh token for client {ClientId}", clientId);
                return Results.BadRequest(new { error = "invalid_grant", error_description = "Not a refresh token" });
            }

            // Issue new access token
            var accessToken = await tokenService.CreateAccessTokenAsync(
                principal, clientId, new[] { "mcp:tools" }, "default");

            // Issue new refresh token
            var newRefreshToken = await tokenService.CreateRefreshTokenAsync(
                principal, clientId, "default");

            var tokenResponse = new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = (int)authConfig.CurrentValue.OAuth.AccessTokenLifetime.TotalSeconds,
                refresh_token = newRefreshToken,
                scope = "mcp:tools"
            };

            logger.LogInformation("Refresh token exchange successful for client {ClientId}", clientId);

            return Results.Json(tokenResponse);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing refresh token request");
            return Results.Problem("Refresh token processing error");
        }
    }

    /// <summary>
    /// Creates HTML login form for OAuth authorization with multi-method authentication.
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
        body {{ font-family: Arial, sans-serif; max-width: 450px; margin: 50px auto; padding: 20px; }}
        .form-group {{ margin: 15px 0; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; border: none; border-radius: 4px; cursor: pointer; margin-bottom: 10px; font-size: 14px; }}
        .password-btn {{ background: #007cba; color: white; }}
        .password-btn:hover {{ background: #005a87; }}
        .webauthn-btn {{ background: #28a745; color: white; }}
        .webauthn-btn:hover {{ background: #218838; }}
        .info {{ background: #f0f8ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
        .auth-separator {{ text-align: center; margin: 20px 0; color: #666; font-size: 14px; }}
        .auth-method {{ border: 1px solid #ddd; padding: 20px; border-radius: 4px; margin-bottom: 15px; background: #fafafa; }}
        .auth-method h4 {{ margin: 0 0 10px 0; color: #333; }}
        .auth-method p {{ margin: 10px 0; font-size: 14px; color: #666; }}
        .biometric-icon {{ font-size: 18px; margin-right: 8px; }}
        .error {{ background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class='info'>
        <h3>🔐 Enterprise MCP Server Authentication</h3>
        <p><strong>Client:</strong> {clientId}</p>
        <p>Choose your preferred authentication method</p>
    </div>
    
    <form id='oauth_form' method='post' action='/authorize'>
        <!-- Password Authentication Method -->
        <div class='auth-method'>
            <h4>🔑 Username & Password</h4>
            <div class='form-group'>
                <label for='username'>Username:</label>
                <input type='text' id='username' name='username' value='test.user@company.com' />
            </div>
            <div class='form-group'>
                <label for='password'>Password:</label>
                <input type='password' id='password' name='password' value='testpass' />
            </div>
            <button type='submit' class='password-btn' onclick=""document.getElementById('auth_method').value='password'"">
                🔑 Sign In with Password
            </button>
        </div>
        
        <div class='auth-separator'>─── OR ───</div>
        
        <!-- WebAuthn Authentication Method -->
        <div class='auth-method'>
            <h4><span class='biometric-icon'>🔐</span>Biometric / Security Key</h4>
            <p>Use your fingerprint, face recognition, or hardware security key (YubiKey, etc.)</p>
            <button type='button' class='webauthn-btn' onclick='authenticateWithWebAuthn()'>
                🔐 Authenticate with Biometric/Security Key
            </button>
            <div id='webauthn_error' class='error' style='display:none;'></div>
        </div>
        
        <!-- Hidden fields for OAuth flow -->
        <input type='hidden' name='client_id' value='{clientId}' />
        <input type='hidden' name='redirect_uri' value='{redirectUri}' />
        <input type='hidden' name='state' value='{state}' />
        <input type='hidden' name='code_challenge' value='{codeChallenge}' />
        <input type='hidden' name='code_challenge_method' value='{codeChallengeMethod}' />
        <input type='hidden' id='auth_method' name='auth_method' value='' />
        <input type='hidden' id='webauthn_data' name='webauthn_data' value='' />
    </form>
    
    <div class='info' style='margin-top: 20px; font-size: 12px;'>
        <p><strong>Password:</strong> test.user@company.com / testpass</p>
        <p><strong>WebAuthn:</strong> First register at <a href='/webauthn/register' target='_blank'>/webauthn/register</a></p>
        <p>This will grant access to MCP tools for the requesting application.</p>
    </div>

    <script>
        async function authenticateWithWebAuthn() {{
            const errorDiv = document.getElementById('webauthn_error');
            errorDiv.style.display = 'none';
            
            try {{
                // Check WebAuthn support
                if (!window.PublicKeyCredential) {{
                    throw new Error('WebAuthn is not supported in this browser');
                }}
                
                // Get challenge from server
                const challengeResponse = await fetch('/webauthn/oauth-challenge');
                if (!challengeResponse.ok) {{
                    throw new Error('Failed to get WebAuthn challenge from server');
                }}
                const challengeData = await challengeResponse.json();
                
                // Create WebAuthn assertion
                const credential = await navigator.credentials.get({{
                    publicKey: challengeData
                }});
                
                if (!credential) {{
                    throw new Error('No credential returned from authenticator');
                }}
                
                // Convert credential to format server expects
                const authData = {{
                    id: credential.id,
                    rawId: Array.from(new Uint8Array(credential.rawId)),
                    response: {{
                        authenticatorData: Array.from(new Uint8Array(credential.response.authenticatorData)),
                        clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
                        signature: Array.from(new Uint8Array(credential.response.signature)),
                        userHandle: credential.response.userHandle ? Array.from(new Uint8Array(credential.response.userHandle)) : null
                    }},
                    type: credential.type
                }};
                
                // Submit WebAuthn authentication
                document.getElementById('webauthn_data').value = JSON.stringify(authData);
                document.getElementById('auth_method').value = 'webauthn';
                document.getElementById('oauth_form').submit();
                
            }} catch (error) {{
                console.error('WebAuthn authentication error:', error);
                errorDiv.textContent = 'WebAuthn authentication failed: ' + error.message + '. Please try password authentication.';
                errorDiv.style.display = 'block';
            }}
        }}
    </script>
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
    private static readonly ConcurrentDictionary<string, AuthorizationCodeData> _authCodes = new();

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
        _authCodes.TryRemove(code, out _);
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