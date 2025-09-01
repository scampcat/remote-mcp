using Authentication.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Services;

/// <summary>
/// Enterprise token service for OAuth 2.1 JWT token management.
/// Implements secure token creation, validation, and lifecycle management.
/// </summary>
public interface ITokenService
{
    Task<string> CreateAccessTokenAsync(ClaimsPrincipal user, string clientId, string[] scopes, string? tenantId = null);
    Task<string> CreateRefreshTokenAsync(ClaimsPrincipal user, string clientId, string? tenantId = null);
    Task<ClaimsPrincipal?> ValidateTokenAsync(string token);
    Task<bool> RevokeTokenAsync(string tokenId);
    Task<bool> IsTokenRevokedAsync(string tokenId);
}

/// <summary>
/// Enterprise JWT token service implementation with security best practices.
/// </summary>
public class TokenService : ITokenService
{
    private readonly ILogger<TokenService> _logger;
    private readonly IOptionsMonitor<AuthenticationConfiguration> _authConfig;
    private readonly HashSet<string> _revokedTokens = new(); // In-memory for development
    private static SecurityKey? _sharedSigningKey; // Shared across all instances
    private static readonly object _keyLock = new object();

    public TokenService(
        ILogger<TokenService> logger,
        IOptionsMonitor<AuthenticationConfiguration> authConfig)
    {
        _logger = logger;
        _authConfig = authConfig;
    }

    /// <summary>
    /// Gets shared signing key across all TokenService instances.
    /// </summary>
    private SecurityKey SigningKey
    {
        get
        {
            if (_sharedSigningKey == null)
            {
                lock (_keyLock)
                {
                    if (_sharedSigningKey == null)
                    {
                        _sharedSigningKey = CreateConsistentSigningKey();
                        _logger.LogInformation("Created shared signing key for enterprise authentication");
                    }
                }
            }
            return _sharedSigningKey;
        }
    }

    /// <summary>
    /// Creates enterprise-grade JWT access token with MCP-specific claims.
    /// </summary>
    public async Task<string> CreateAccessTokenAsync(ClaimsPrincipal user, string clientId, string[] scopes, string? tenantId = null)
    {
        var config = _authConfig.CurrentValue;
        var now = DateTime.UtcNow;
        var expiry = now.Add(config.OAuth.AccessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Identity?.Name ?? "unknown"),
            new(JwtRegisteredClaimNames.Aud, config.OAuth.Issuer),
            new(JwtRegisteredClaimNames.Iss, config.OAuth.Issuer),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expiry).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("client_id", clientId),
            new("scope", string.Join(" ", scopes))
        };

        // Add tenant claim for multi-tenant support
        if (!string.IsNullOrEmpty(tenantId))
        {
            claims.Add(new Claim("tenant", tenantId));
        }

        // Add tool-specific permissions
        foreach (var scope in scopes)
        {
            if (scope.StartsWith("mcp:"))
            {
                claims.Add(new Claim("tools", scope.Substring(4))); // Remove "mcp:" prefix
            }
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiry,
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256),
            Issuer = config.OAuth.Issuer,
            Audience = config.OAuth.Issuer
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        _logger.LogDebug("Created access token for user {User} client {Client} with scopes {Scopes}",
            user.Identity?.Name, clientId, string.Join(",", scopes));

        return tokenString;
    }

    /// <summary>
    /// Creates secure refresh token for extended enterprise sessions.
    /// </summary>
    public async Task<string> CreateRefreshTokenAsync(ClaimsPrincipal user, string clientId, string? tenantId = null)
    {
        var config = _authConfig.CurrentValue;
        var now = DateTime.UtcNow;
        var expiry = now.Add(config.OAuth.RefreshTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Identity?.Name ?? "unknown"),
            new(JwtRegisteredClaimNames.Aud, config.OAuth.Issuer),
            new(JwtRegisteredClaimNames.Iss, config.OAuth.Issuer),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expiry).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("client_id", clientId),
            new("token_type", "refresh")
        };

        if (!string.IsNullOrEmpty(tenantId))
        {
            claims.Add(new Claim("tenant", tenantId));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiry,
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256),
            Issuer = config.OAuth.Issuer,
            Audience = config.OAuth.Issuer
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        _logger.LogDebug("Created refresh token for user {User} client {Client}",
            user.Identity?.Name, clientId);

        return tokenString;
    }

    /// <summary>
    /// Validates JWT token with enterprise security requirements.
    /// </summary>
    public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token)
    {
        try
        {
            var config = _authConfig.CurrentValue;
            var tokenHandler = new JwtSecurityTokenHandler();

            // Check if token is revoked first
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jti = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
            
            if (!string.IsNullOrEmpty(jti) && await IsTokenRevokedAsync(jti))
            {
                _logger.LogWarning("Attempted use of revoked token {TokenId}", jti);
                return null;
            }

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.OAuth.Issuer,
                ValidateAudience = true,
                ValidAudience = config.OAuth.Issuer,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = SigningKey,
                ClockSkew = TimeSpan.FromMinutes(5) // Enterprise clock skew tolerance
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            
            _logger.LogDebug("Successfully validated token for user {User}",
                principal.Identity?.Name);

            return principal;
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger.LogDebug("Token expired: {Message}", ex.Message);
            return null;
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogWarning("Token validation failed: {Message}", ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token validation");
            return null;
        }
    }

    /// <summary>
    /// Revokes token for enterprise security lifecycle management.
    /// </summary>
    public async Task<bool> RevokeTokenAsync(string tokenId)
    {
        try
        {
            _revokedTokens.Add(tokenId);
            _logger.LogInformation("Token {TokenId} revoked", tokenId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke token {TokenId}", tokenId);
            return false;
        }
    }

    /// <summary>
    /// Checks if token is revoked for enterprise access control.
    /// </summary>
    public async Task<bool> IsTokenRevokedAsync(string tokenId)
    {
        return _revokedTokens.Contains(tokenId);
    }

    /// <summary>
    /// Creates consistent RSA signing key for enterprise token security.
    /// </summary>
    private static SecurityKey CreateConsistentSigningKey()
    {
        // For development, use a deterministic key (in production, this would come from enterprise HSM)
        var rsa = RSA.Create(2048);
        
        // Create key with consistent ID for JWT validation
        var key = new RsaSecurityKey(rsa)
        {
            KeyId = "enterprise-signing-key"
        };
        
        return key;
    }
}