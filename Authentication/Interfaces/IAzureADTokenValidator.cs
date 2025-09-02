using Authentication.Configuration;
using Authentication.Models;
using System.Security.Claims;

namespace Authentication.Interfaces;

/// <summary>
/// Interface for secure Azure AD JWT token validation with enterprise requirements.
/// Provides abstraction for testing and dependency injection.
/// </summary>
public interface IAzureADTokenValidator
{
    /// <summary>
    /// Validates Azure AD JWT access token with comprehensive security checks.
    /// </summary>
    /// <param name="token">JWT access token from Azure AD</param>
    /// <param name="config">Azure AD configuration with tenant and audience details</param>
    /// <returns>ClaimsPrincipal if valid, null if invalid</returns>
    Task<ClaimsPrincipal?> ValidateTokenAsync(string token, AzureADConfiguration config);

    /// <summary>
    /// Validates that Azure AD configuration is complete and correct.
    /// </summary>
    /// <param name="config">Azure AD configuration to validate</param>
    /// <returns>True if configuration is valid for production use</returns>
    Task<bool> IsConfigurationValidAsync(AzureADConfiguration config);

    /// <summary>
    /// Checks Azure AD connectivity and JWKS endpoint availability.
    /// </summary>
    /// <param name="config">Azure AD configuration</param>
    /// <returns>True if Azure AD is reachable and responding</returns>
    Task<bool> CheckConnectivityAsync(AzureADConfiguration config);

    /// <summary>
    /// Validates token contains required scopes for MCP tool access.
    /// </summary>
    /// <param name="userPrincipal">Validated user claims from Azure AD token</param>
    /// <param name="requiredScopes">Required OAuth scopes (e.g., "mcp:tools", "mcp:math")</param>
    /// <returns>True if token contains all required scopes</returns>
    Task<bool> ValidateScopesAsync(ClaimsPrincipal userPrincipal, string[] requiredScopes);

    /// <summary>
    /// Extracts scopes from Azure AD token for authorization decisions.
    /// </summary>
    /// <param name="userPrincipal">Validated user claims</param>
    /// <returns>Array of scopes present in the token</returns>
    Task<string[]> ExtractScopesAsync(ClaimsPrincipal userPrincipal);
}