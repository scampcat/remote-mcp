using Authentication.Interfaces;
using Authentication.Models;
using Authentication.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace Authentication.Services;

/// <summary>
/// Enterprise authentication mode provider implementing adaptive security patterns.
/// Supports multiple authentication modes configurable at runtime.
/// </summary>
public class AuthenticationModeProvider : IAuthenticationModeProvider
{
    private readonly ILogger<AuthenticationModeProvider> _logger;
    private readonly IOptionsMonitor<AuthenticationConfiguration> _authConfig;
    private AuthenticationMode _currentMode;

    public AuthenticationModeProvider(
        ILogger<AuthenticationModeProvider> logger,
        IOptionsMonitor<AuthenticationConfiguration> authConfig)
    {
        _logger = logger;
        _authConfig = authConfig;
        _currentMode = _authConfig.CurrentValue.Mode;
        
        // Monitor configuration changes for runtime mode switching
        _authConfig.OnChange(config =>
        {
            _logger.LogInformation("Authentication mode changing from {OldMode} to {NewMode}", 
                _currentMode, config.Mode);
            _currentMode = config.Mode;
        });
    }

    /// <summary>
    /// Current authentication mode for the enterprise deployment.
    /// </summary>
    public AuthenticationMode CurrentMode => _currentMode;

    /// <summary>
    /// Validates authentication request according to current enterprise mode.
    /// </summary>
    public async Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request)
    {
        try
        {
            _logger.LogDebug("Authenticating request for tool {Tool} in mode {Mode}", 
                request.RequestedTool, _currentMode);

            return _currentMode switch
            {
                AuthenticationMode.Disabled => HandleDisabledMode(request),
                AuthenticationMode.ResourceServer => await HandleResourceServerModeAsync(request),
                AuthenticationMode.AuthorizationServer => await HandleAuthorizationServerModeAsync(request),
                AuthenticationMode.Hybrid => await HandleHybridModeAsync(request),
                AuthenticationMode.ZeroTrust => await HandleZeroTrustModeAsync(request),
                _ => AuthenticationResult.Failure("Unknown authentication mode", "invalid_mode")
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed for request to tool {Tool}", request.RequestedTool);
            return AuthenticationResult.Failure("Authentication error", "internal_error");
        }
    }

    /// <summary>
    /// Determines if authentication feature is supported in current mode.
    /// </summary>
    public async Task<bool> SupportsFeatureAsync(AuthenticationFeature feature)
    {
        return _currentMode switch
        {
            AuthenticationMode.Disabled => false,
            AuthenticationMode.ResourceServer => feature == AuthenticationFeature.ExternalIdPIntegration,
            AuthenticationMode.AuthorizationServer => feature != AuthenticationFeature.ExternalIdPIntegration,
            AuthenticationMode.Hybrid => true, // Hybrid supports all features
            AuthenticationMode.ZeroTrust => true, // Zero trust supports all features
            _ => false
        };
    }

    /// <summary>
    /// Evaluates enterprise security policy for authentication decisions.
    /// </summary>
    public async Task<PolicyResult> EvaluatePolicyAsync(SecurityPolicy policy, AuthenticationContext context)
    {
        // Basic policy evaluation - will be enhanced in later sprints
        if (policy.ToolPermissions.TryGetValue(context.Device?.DeviceType ?? "unknown", out var accessLevel))
        {
            if (accessLevel == ToolAccessLevel.Denied)
            {
                return new PolicyResult
                {
                    IsAllowed = false,
                    Reason = "Tool access denied by enterprise policy"
                };
            }
        }

        return new PolicyResult
        {
            IsAllowed = true,
            Reason = "Policy evaluation passed"
        };
    }

    /// <summary>
    /// Switches authentication mode at runtime without service interruption.
    /// </summary>
    public async Task<bool> SwitchModeAsync(AuthenticationMode newMode)
    {
        try
        {
            _logger.LogInformation("Switching authentication mode from {OldMode} to {NewMode}", 
                _currentMode, newMode);

            // Validate mode switch is safe
            if (!IsModeSwitchSafe(_currentMode, newMode))
            {
                _logger.LogWarning("Unsafe mode switch from {OldMode} to {NewMode} rejected", 
                    _currentMode, newMode);
                return false;
            }

            _currentMode = newMode;
            
            _logger.LogInformation("Authentication mode successfully switched to {NewMode}", newMode);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to switch authentication mode to {NewMode}", newMode);
            return false;
        }
    }

    /// <summary>
    /// Handles disabled authentication mode (development environments).
    /// </summary>
    private AuthenticationResult HandleDisabledMode(AuthenticationRequest request)
    {
        _logger.LogDebug("Authentication disabled - allowing request to {Tool}", request.RequestedTool);
        
        // Create anonymous user for disabled mode
        var identity = new ClaimsIdentity("anonymous");
        identity.AddClaim(new Claim(ClaimTypes.Name, "anonymous"));
        identity.AddClaim(new Claim("tool_access", "all"));
        
        var principal = new ClaimsPrincipal(identity);
        
        return AuthenticationResult.Success(principal, new AuthenticationContext
        {
            AuthenticationMethod = "disabled",
            TenantId = request.TenantId ?? "default"
        });
    }

    /// <summary>
    /// Handles resource server mode (external IdP delegation).
    /// </summary>
    private async Task<AuthenticationResult> HandleResourceServerModeAsync(AuthenticationRequest request)
    {
        if (string.IsNullOrEmpty(request.BearerToken))
        {
            return AuthenticationResult.Failure(
                "Authorization required", 
                "unauthorized",
                "Bearer realm=\"MCP Server\", scope=\"mcp:tools\"");
        }

        // Token validation will be implemented in next sprint
        _logger.LogDebug("Resource server mode token validation for {Tool}", request.RequestedTool);
        
        return AuthenticationResult.Failure("Token validation not yet implemented", "not_implemented");
    }

    /// <summary>
    /// Handles authorization server mode (full enterprise control).
    /// </summary>
    private async Task<AuthenticationResult> HandleAuthorizationServerModeAsync(AuthenticationRequest request)
    {
        if (string.IsNullOrEmpty(request.BearerToken))
        {
            return AuthenticationResult.Failure(
                "Authorization required",
                "unauthorized", 
                "Bearer realm=\"MCP Server\", scope=\"mcp:tools\"");
        }

        // OAuth token validation will be implemented in next sprint
        _logger.LogDebug("Authorization server mode token validation for {Tool}", request.RequestedTool);
        
        return AuthenticationResult.Failure("OAuth validation not yet implemented", "not_implemented");
    }

    /// <summary>
    /// Handles hybrid mode (both resource and authorization server).
    /// </summary>
    private async Task<AuthenticationResult> HandleHybridModeAsync(AuthenticationRequest request)
    {
        // Try authorization server first, fallback to resource server
        var authServerResult = await HandleAuthorizationServerModeAsync(request);
        if (authServerResult.IsAuthenticated)
        {
            return authServerResult;
        }

        return await HandleResourceServerModeAsync(request);
    }

    /// <summary>
    /// Handles zero trust mode (continuous validation and threat detection).
    /// </summary>
    private async Task<AuthenticationResult> HandleZeroTrustModeAsync(AuthenticationRequest request)
    {
        // Zero trust requires token + additional validation
        var authResult = await HandleAuthorizationServerModeAsync(request);
        if (!authResult.IsAuthenticated)
        {
            return authResult;
        }

        // Additional zero trust validations will be implemented in later sprints
        _logger.LogDebug("Zero trust additional validations for {Tool}", request.RequestedTool);
        
        return authResult;
    }

    /// <summary>
    /// Validates if authentication mode switch is safe for enterprise operations.
    /// </summary>
    private bool IsModeSwitchSafe(AuthenticationMode from, AuthenticationMode to)
    {
        // Switching to disabled from any mode is always safe
        if (to == AuthenticationMode.Disabled)
            return true;

        // Switching from disabled to any mode is safe
        if (from == AuthenticationMode.Disabled)
            return true;

        // Other mode switches require careful consideration
        return from == to; // Same mode is always safe
    }
}