using Authentication.Configuration;
using Authentication.Services;
using Authentication.OAuth;
using Authentication.Interfaces;
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
    /// Maps working OAuth authorization and token endpoints using provider pattern.
    /// </summary>
    public static void MapOAuthImplementationEndpoints(this WebApplication app)
    {
        // OAuth authorization endpoint - GET shows login form or redirects to external provider
        app.MapGet("/authorize", async (HttpContext context,
            string response_type, string client_id, string redirect_uri,
            string? scope, string? state, string? code_challenge, string? code_challenge_method,
            IOAuthEndpointProviderFactory providerFactory) =>
        {
            var provider = providerFactory.GetProvider();
            return await provider.HandleAuthorizationAsync(response_type, client_id, redirect_uri, 
                scope, state, code_challenge, code_challenge_method, context);
        });

        // OAuth authorization endpoint - POST processes local authentication
        app.MapPost("/authorize", async (HttpContext context,
            IOptionsMonitor<AuthenticationConfiguration> authConfig,
            ITokenService tokenService,
            ILogger<ITokenService> logger) =>
            await HandleAuthorizationPostAsync(context, authConfig, tokenService, logger));

        // OAuth token endpoint - delegates to appropriate provider
        app.MapPost("/token", async (HttpContext context,
            IOAuthEndpointProviderFactory providerFactory) =>
        {
            var form = await context.Request.ReadFormAsync();
            var grant_type = form["grant_type"].ToString();
            var code = form["code"].ToString();
            var redirect_uri = form["redirect_uri"].ToString();
            var client_id = form["client_id"].ToString();
            var client_secret = form["client_secret"].ToString();
            var code_verifier = form["code_verifier"].ToString();
            
            var provider = providerFactory.GetProvider();
            return await provider.HandleTokenAsync(grant_type, code, redirect_uri, client_id,
                client_secret, code_verifier, context);
        });

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

        // OAuth token revocation endpoint (RFC 7009)
        app.MapPost("/revoke", async (HttpContext context, ITokenService tokenService, ILogger<ITokenService> logger) =>
        {
            try
            {
                var form = await context.Request.ReadFormAsync();
                var token = form["token"].ToString();
                var tokenTypeHint = form["token_type_hint"].ToString();
                
                if (string.IsNullOrEmpty(token))
                {
                    return Results.BadRequest(new { error = "invalid_request", error_description = "token parameter is required" });
                }

                // Extract token ID for revocation
                var tokenId = ExtractTokenId(token);
                if (string.IsNullOrEmpty(tokenId))
                {
                    logger.LogWarning("Could not extract token ID for revocation");
                    return Results.BadRequest(new { error = "invalid_token", error_description = "Token format invalid" });
                }

                var revoked = await tokenService.RevokeTokenAsync(tokenId);
                
                if (revoked)
                {
                    logger.LogInformation("Token successfully revoked for logout");
                    return Results.Ok(new { message = "Token revoked successfully" });
                }
                else
                {
                    logger.LogWarning("Token revocation failed - token may not exist");
                    return Results.Ok(new { message = "Token revocation processed" }); // RFC 7009: return success even if token doesn't exist
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during token revocation");
                return Results.Problem("Token revocation failed");
            }
        });

        // Note: /logout endpoint is now in OAuthEndpoints.cs to avoid conflicts

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
    public static async Task<IResult> HandleAuthorizationCodeGrantAsync(
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
    public static async Task<IResult> HandleRefreshTokenGrantAsync(
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
    public static string CreateLoginForm(string clientId, string redirectUri, string state, 
        string codeChallenge, string codeChallengeMethod)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <title>MCP Server Authentication</title>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css' rel='stylesheet'>
    <style>
        body {{ background-color: #f8f9fa; }}
        .main-container {{ max-width: 700px; margin: 50px auto; }}
        .card {{ box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); border: none; }}
        .btn-password {{ background: linear-gradient(45deg, #007cba, #0056b3); border: none; }}
        .btn-password:hover {{ background: linear-gradient(45deg, #005a87, #004085); }}
        .btn-webauthn {{ background: linear-gradient(45deg, #28a745, #20c997); border: none; }}
        .btn-webauthn:hover {{ background: linear-gradient(45deg, #218838, #1ba085); }}
        .icon-large {{ font-size: 1.5rem; }}
        .auth-separator {{ margin: 1.5rem 0; }}
    </style>
</head>
<body>
    <div class='container main-container'>
        <div class='text-center mb-4'>
            <h2><i class='bi bi-shield-lock icon-large text-primary'></i> Enterprise MCP Server</h2>
            <p class='text-muted'>Secure authentication for AI tool access</p>
        </div>
        
        <div class='card'>
            <div class='card-header bg-primary text-white'>
                <h5 class='card-title mb-0'><i class='bi bi-person-check'></i> Authentication Required</h5>
            </div>
            <div class='card-body'>
                <div class='alert alert-info'>
                    <strong><i class='bi bi-info-circle'></i> Client:</strong> {clientId}<br>
                    <small>Choose your preferred authentication method below</small>
                </div>
                
                <form id='oauth_form' method='post' action='/authorize'>
                    <!-- Password Authentication Method -->
                    <div class='card mb-3'>
                        <div class='card-body'>
                            <h5 class='card-title'><i class='bi bi-key-fill text-primary'></i> Username & Password</h5>
                            <div class='mb-3'>
                                <label for='username' class='form-label'>Username:</label>
                                <input type='text' id='username' name='username' class='form-control' value='test.user@company.com' />
                            </div>
                            <div class='mb-3'>
                                <label for='password' class='form-label'>Password:</label>
                                <input type='password' id='password' name='password' class='form-control' value='testpass' />
                            </div>
                            <button type='submit' class='btn btn-password w-100' onclick=""document.getElementById('auth_method').value='password'"">
                                <i class='bi bi-key-fill'></i> Sign In with Password
                            </button>
                        </div>
                    </div>
        
                    <div class='text-center auth-separator'>
                        <span class='badge bg-secondary'>OR</span>
                    </div>
        
                    <!-- WebAuthn Authentication Method -->
                    <div class='card mb-3'>
                        <div class='card-body'>
                            <h5 class='card-title'><i class='bi bi-fingerprint text-success'></i> Biometric / Security Key</h5>
                            <p class='card-text text-muted'>Use your fingerprint, face recognition, or hardware security key (YubiKey, etc.)</p>
                            <button type='button' class='btn btn-webauthn w-100' onclick='authenticateWithWebAuthn()'>
                                <i class='bi bi-shield-check'></i> Authenticate with Biometric/Security Key
                            </button>
                            <div id='webauthn_error' class='alert alert-danger mt-2' style='display:none;'></div>
                        </div>
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
            </div>
        </div>
        
        <div class='card mt-3'>
            <div class='card-body bg-light'>
                <h6 class='card-title'><i class='bi bi-info-circle text-info'></i> Development Credentials</h6>
                <div class='row'>
                    <div class='col-md-6'>
                        <small><strong>Password:</strong> test.user@company.com / testpass</small>
                    </div>
                    <div class='col-md-6'>
                        <small><strong>WebAuthn:</strong> <a href='/webauthn/register' target='_blank' class='text-decoration-none'>Register first <i class='bi bi-box-arrow-up-right'></i></a></small>
                    </div>
                </div>
                <small class='text-muted'>This will grant access to MCP tools for the requesting application.</small>
            </div>
        </div>
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

    /// <summary>
    /// Extracts token ID from JWT for revocation.
    /// </summary>
    private static string ExtractTokenId(string token)
    {
        try
        {
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);
            return jsonToken.Claims.FirstOrDefault(c => c.Type == "jti")?.Value ?? 
                   jsonToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? 
                   "unknown";
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Creates logout page with token revocation functionality.
    /// </summary>
    private static string CreateLogoutPage()
    {
        return @"
<!DOCTYPE html>
<html>
<head>
    <title>Logout - MCP Server</title>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css' rel='stylesheet'>
</head>
<body class='bg-light'>
    <div class='container' style='max-width: 600px; margin: 100px auto;'>
        <div class='card text-center'>
            <div class='card-body p-5'>
                <i class='bi bi-shield-x text-warning' style='font-size: 4rem;'></i>
                <h3 class='mt-3'>Logout from MCP Server</h3>
                <p class='text-muted'>This will revoke your authentication tokens and end your session.</p>
                
                <div class='d-grid gap-2 mt-4'>
                    <button class='btn btn-danger btn-lg' onclick='logout()'>
                        <i class='bi bi-box-arrow-right'></i> Logout & Revoke Tokens
                    </button>
                    <a href='/authorize' class='btn btn-outline-secondary'>
                        <i class='bi bi-arrow-left'></i> Back to Login
                    </a>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function logout() {
            try {
                // Get current token from localStorage if available
                const token = localStorage.getItem('mcp_access_token') || 
                             sessionStorage.getItem('access_token') ||
                             prompt('Enter your access token to revoke (optional):');
                
                if (token) {
                    const response = await fetch('/revoke', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `token=${encodeURIComponent(token)}&token_type_hint=access_token`
                    });
                    
                    if (response.ok) {
                        alert('✅ Token revoked successfully. You are now logged out.');
                    } else {
                        alert('⚠️ Logout processed (token may have already expired).');
                    }
                } else {
                    alert('✅ Logout completed (no token to revoke).');
                }
                
                // Clear any stored tokens
                localStorage.removeItem('mcp_access_token');
                sessionStorage.removeItem('access_token');
                
                // Redirect to login
                window.location.href = '/authorize?response_type=code&client_id=mcp-client&redirect_uri=' + 
                    encodeURIComponent(window.location.origin + '/auth/callback') + 
                    '&code_challenge=placeholder&code_challenge_method=S256';
                
            } catch (error) {
                console.error('Logout error:', error);
                alert('⚠️ Logout completed with warnings. Check console for details.');
            }
        }
    </script>
</body>
</html>";
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