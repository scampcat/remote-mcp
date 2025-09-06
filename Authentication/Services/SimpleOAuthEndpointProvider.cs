using Authentication.Configuration;
using Authentication.Interfaces;
using Microsoft.Extensions.Options;

namespace Authentication.Services;

/// <summary>
/// Simple OAuth endpoint provider for Azure AD integration.
/// Implements basic authorization flow with Microsoft redirect.
/// </summary>
public class SimpleOAuthEndpointProvider : IOAuthEndpointProvider
{
    private readonly IOptionsMonitor<AuthenticationConfiguration> _authConfig;

    public SimpleOAuthEndpointProvider(IOptionsMonitor<AuthenticationConfiguration> authConfig)
    {
        _authConfig = authConfig;
    }

    /// <summary>
    /// Handles OAuth authorization by redirecting to Microsoft Azure AD with proper prompt handling.
    /// </summary>
    public Task<IResult> HandleAuthorizationAsync(
        string responseType, string clientId, string redirectUri,
        string? scope, string? state, string? codeChallenge, string? codeChallengeMethod,
        HttpContext context)
    {
        // CRITICAL DEBUG: Log that authorization endpoint is being hit
        var logger = context.RequestServices.GetRequiredService<ILogger<SimpleOAuthEndpointProvider>>();
        logger.LogCritical("🔑 AUTHORIZATION ENDPOINT HIT: ClientId={ClientId}, State={State}, RedirectUri={RedirectUri}", 
            clientId, state, redirectUri);

        var config = _authConfig.CurrentValue;

        // Build Microsoft OAuth authorization URL using AzureAD configuration
        // Use proper hexagonal pattern - only handle if this is the configured provider
        if (config.ExternalIdP.Provider != "AzureAD")
        {
            return Task.FromResult(Results.BadRequest(new { error = "azure_ad_not_configured" }));
        }

        var authority = config.ExternalIdP.AzureAD.Authority;
        var azureClientId = config.ExternalIdP.AzureAD.ClientId;
        
        // OAuth 2.1 Loopback Redirect URI Flexibility Implementation
        // Accept any localhost port but use registered URI for Azure AD
        var registeredRedirectUri = DetermineRegisteredRedirectUri(redirectUri, config);
        
        // Store original redirect_uri in session for callback forwarding
        context.Session.SetString($"original_redirect_uri_{state}", redirectUri);
        
        // Extract prompt parameter from query string or use default
        var prompt = context.Request.Query["prompt"].FirstOrDefault() ?? "select_account";
        
        var microsoftAuthUrl = $"{authority}/oauth2/v2.0/authorize" +
            $"?client_id={azureClientId}" +
            $"&response_type={responseType}" +
            $"&redirect_uri={Uri.EscapeDataString(registeredRedirectUri)}" +
            $"&scope={Uri.EscapeDataString(scope ?? "User.Read openid profile")}" +
            $"&state={state}" +
            $"&code_challenge={codeChallenge}" +
            $"&code_challenge_method={codeChallengeMethod}" +
            $"&prompt={prompt}";

        return Task.FromResult(Results.Redirect(microsoftAuthUrl));
    }

    /// <summary>
    /// OAuth 2.1 compliant redirect URI handling for loopback addresses.
    /// Implements OAuth 2.1 Section 8.4.2 - Loopback Interface Redirection.
    /// </summary>
    private string DetermineRegisteredRedirectUri(string clientRedirectUri, AuthenticationConfiguration config)
    {
        // Get the first registered redirect URI as our canonical one
        var registeredUris = config.ExternalIdP.AzureAD.RedirectUris;
        if (registeredUris == null || !registeredUris.Any())
        {
            throw new InvalidOperationException("No redirect URIs configured in Azure AD settings");
        }

        var canonicalUri = registeredUris.First();
        
        try
        {
            var clientUri = new Uri(clientRedirectUri);
            var registeredUri = new Uri(canonicalUri);
            
            // OAuth 2.1 Section 8.4.2: For loopback interfaces (localhost/127.0.0.1),
            // the authorization server MUST allow any port number.
            // Everything else must match exactly: scheme, host, path, query, fragment
            
            bool isLoopback = IsLoopbackAddress(clientUri.Host) && IsLoopbackAddress(registeredUri.Host);
            
            if (isLoopback)
            {
                // For loopback, verify everything except port matches
                bool schemeMatches = clientUri.Scheme.Equals(registeredUri.Scheme, StringComparison.OrdinalIgnoreCase);
                bool hostMatches = clientUri.Host.Equals(registeredUri.Host, StringComparison.OrdinalIgnoreCase);
                bool pathMatches = clientUri.AbsolutePath.Equals(registeredUri.AbsolutePath, StringComparison.Ordinal);
                bool queryMatches = clientUri.Query.Equals(registeredUri.Query, StringComparison.Ordinal);
                bool fragmentMatches = clientUri.Fragment.Equals(registeredUri.Fragment, StringComparison.Ordinal);
                
                if (schemeMatches && hostMatches && pathMatches && queryMatches && fragmentMatches)
                {
                    // OAuth 2.1 compliant: Accept loopback with different port
                    // But use registered URI for Azure AD to satisfy Microsoft's exact matching
                    return canonicalUri;
                }
            }
            else
            {
                // Non-loopback addresses require exact string matching per OAuth 2.1
                if (clientRedirectUri.Equals(canonicalUri, StringComparison.Ordinal))
                {
                    return canonicalUri;
                }
            }
        }
        catch (UriFormatException)
        {
            // Invalid URI format - reject
        }
        
        throw new UnauthorizedAccessException($"Redirect URI '{clientRedirectUri}' does not match registered URI '{canonicalUri}' per OAuth 2.1 requirements");
    }

    /// <summary>
    /// Determines if a host is a loopback address per OAuth 2.1 specification.
    /// </summary>
    private static bool IsLoopbackAddress(string host)
    {
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("127.0.0.1", StringComparison.Ordinal) ||
               host.Equals("::1", StringComparison.Ordinal);
    }

    /// <summary>
    /// Handles OAuth token exchange with Microsoft Azure AD.
    /// </summary>
    public async Task<IResult> HandleTokenAsync(string grantType, string? code, string? redirectUri,
        string? clientId, string? clientSecret, string? codeVerifier, HttpContext context)
    {
        if (grantType != "authorization_code" || string.IsNullOrEmpty(code))
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        var config = _authConfig.CurrentValue;
        var authority = config.ExternalIdP.AzureAD.Authority;
        var azureClientId = config.ExternalIdP.AzureAD.ClientId;

        // Exchange authorization code for tokens with Microsoft
        using var httpClient = new HttpClient();
        var tokenEndpoint = $"{authority}/oauth2/v2.0/token";

        var formData = new List<KeyValuePair<string, string>>
        {
            new("client_id", azureClientId),
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", redirectUri ?? ""),
            new("code_verifier", codeVerifier ?? ""),
            new("scope", "User.Read openid profile")
        };

        var formContent = new FormUrlEncodedContent(formData);
        
        try
        {
            var response = await httpClient.PostAsync(tokenEndpoint, formContent);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                // Return the Microsoft token response directly
                return Results.Content(responseContent, "application/json");
            }
            else
            {
                return Results.BadRequest(new { error = "token_exchange_failed", details = responseContent });
            }
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { error = "token_exchange_error", message = ex.Message });
        }
    }

    /// <summary>
    /// Handles user info endpoint.
    /// </summary>
    public Task<IResult> HandleUserInfoAsync(HttpContext context)
    {
        return Task.FromResult(Results.BadRequest(new { error = "userinfo_not_implemented" }));
    }

    /// <summary>
    /// Indicates this provider handles Azure AD authentication based on configuration.
    /// </summary>
    public bool CanHandle(string authenticationMode, string? providerName)
    {
        var config = _authConfig.CurrentValue;
        return authenticationMode == "AuthorizationServer" && 
               config.ExternalIdP.Provider == "AzureAD";
    }
}

/// <summary>
/// Factory for creating OAuth endpoint providers.
/// </summary>
public class OAuthEndpointProviderFactory : IOAuthEndpointProviderFactory
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptionsMonitor<AuthenticationConfiguration> _authConfig;
    private readonly ILogger<OAuthEndpointProviderFactory> _logger;

    public OAuthEndpointProviderFactory(
        IServiceProvider serviceProvider,
        IOptionsMonitor<AuthenticationConfiguration> authConfig,
        ILogger<OAuthEndpointProviderFactory> logger)
    {
        _serviceProvider = serviceProvider;
        _authConfig = authConfig;
        _logger = logger;
    }

    public IOAuthEndpointProvider GetProvider()
    {
        var config = _authConfig.CurrentValue;
        
        // Choose provider based on configuration
        if (config.ExternalIdP.Provider == "AzureAD")
        {
            _logger.LogInformation("Using Azure AD OAuth provider");
            return _serviceProvider.GetRequiredService<SimpleOAuthEndpointProvider>();
        }
        else
        {
            _logger.LogInformation("Using Local OAuth provider for mcp-remote compatibility");
            return _serviceProvider.GetRequiredService<LocalOAuthEndpointProvider>();
        }
    }
}