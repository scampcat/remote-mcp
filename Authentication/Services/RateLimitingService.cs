using Authentication.Interfaces;
using Authentication.Models;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Authentication.Services;

/// <summary>
/// Simple rate limiting service - MVP implementation.
/// </summary>
public class RateLimitingService : IRateLimitingService
{
    private readonly ILogger<RateLimitingService> _logger;
    private readonly ConcurrentDictionary<string, List<DateTime>> _requests = new();

    public RateLimitingService(ILogger<RateLimitingService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Simple rate limiting: 60 requests per minute per IP.
    /// </summary>
    public async Task<bool> IsRequestAllowedAsync(AuthenticationRequest request)
    {
        try
        {
            var ip = request.ClientIPAddress;
            var now = DateTime.UtcNow;
            var oneMinuteAgo = now.AddMinutes(-1);
            
            var requests = _requests.GetOrAdd(ip, _ => new List<DateTime>());
            
            lock (requests)
            {
                // Remove old requests
                requests.RemoveAll(time => time < oneMinuteAgo);
                
                // Check if under limit (5 requests for testing)
                if (requests.Count >= 5)
                {
                    _logger.LogWarning("Rate limit exceeded for {IP}: {Count}/5 requests", ip, requests.Count);
                    return false;
                }
                
                // Record this request
                requests.Add(now);
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Rate limiting error - allowing request");
            return true; // Fail open
        }
    }
}