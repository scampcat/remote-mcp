using Authentication.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Authentication.Services;

/// <summary>
/// Enterprise signing key service implementing SOLID principles.
/// Single Responsibility: Manages JWT signing keys consistently.
/// Dependency Inversion: Provides abstractions for key management.
/// </summary>
public class SigningKeyService : ISigningKeyService
{
    private static SecurityKey? _sharedSigningKey;
    private static readonly object _keyLock = new object();

    /// <summary>
    /// Gets the current signing key for JWT token creation and validation.
    /// Thread-safe singleton pattern ensures consistent key across all services.
    /// </summary>
    public SecurityKey GetSigningKey()
    {
        if (_sharedSigningKey == null)
        {
            lock (_keyLock)
            {
                if (_sharedSigningKey == null)
                {
                    _sharedSigningKey = CreateConsistentSigningKey();
                }
            }
        }
        return _sharedSigningKey;
    }

    /// <summary>
    /// Gets signing credentials for JWT token creation.
    /// </summary>
    public SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(GetSigningKey(), SecurityAlgorithms.RsaSha256);
    }

    /// <summary>
    /// Gets token validation parameters for JWT Bearer middleware.
    /// Ensures same key is used for creation and validation.
    /// </summary>
    public TokenValidationParameters GetValidationParameters(string issuer, string audience)
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = GetSigningKey(), // Same key used for creation
            ClockSkew = TimeSpan.FromMinutes(5),
            RequireSignedTokens = true,
            RequireExpirationTime = true
        };
    }

    /// <summary>
    /// Creates consistent RSA signing key for enterprise JWT operations.
    /// </summary>
    private SecurityKey CreateConsistentSigningKey()
    {
        using var rsa = RSA.Create(2048); // Enterprise-grade 2048-bit key
        var key = new RsaSecurityKey(rsa.ExportParameters(false)) // Public key only for validation
        {
            KeyId = "enterprise-signing-key"
        };
        
        // Export and import to create a persistent key
        var keyBytes = rsa.ExportRSAPrivateKey();
        var persistentRsa = RSA.Create();
        persistentRsa.ImportRSAPrivateKey(keyBytes, out _);
        
        return new RsaSecurityKey(persistentRsa)
        {
            KeyId = "enterprise-signing-key"
        };
    }
}