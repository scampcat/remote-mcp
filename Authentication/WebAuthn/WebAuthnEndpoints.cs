using Authentication.WebAuthn;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace Authentication.WebAuthn;

/// <summary>
/// WebAuthn endpoint implementations for enterprise passwordless authentication.
/// </summary>
public static class WebAuthnEndpoints
{
    /// <summary>
    /// Maps WebAuthn endpoints for enterprise integration.
    /// </summary>
    public static void MapWebAuthnEndpoints(this WebApplication app)
    {
        // WebAuthn registration endpoints
        app.MapPost("/webauthn/register/begin", BeginRegistration);
        app.MapPost("/webauthn/register/complete", CompleteRegistration);

        // WebAuthn authentication endpoints  
        app.MapPost("/webauthn/authenticate/begin", BeginAuthentication);
        app.MapPost("/webauthn/authenticate/complete", CompleteAuthentication);

        // Enterprise management endpoints
        app.MapGet("/webauthn/statistics/{tenantId}", GetStatistics);
        app.MapDelete("/webauthn/credentials/{credentialId}", RevokeCredential);
    }

    /// <summary>
    /// Begins WebAuthn registration process.
    /// </summary>
    private static async Task<IResult> BeginRegistration(
        HttpContext context,
        IEnterpriseWebAuthnService webAuthnService,
        ILogger<IEnterpriseWebAuthnService> logger)
    {
        try
        {
            var request = await context.Request.ReadFromJsonAsync<RegistrationRequest>();
            if (request == null)
            {
                return Results.BadRequest("Invalid request");
            }

            var options = await webAuthnService.BeginRegistrationAsync(
                request.UserId, request.DisplayName, request.TenantId);

            // Store challenge in session
            context.Session.SetString("webauthn_challenge", Convert.ToBase64String(options.Challenge));
            context.Session.SetString("webauthn_user", request.UserId);
            context.Session.SetString("webauthn_tenant", request.TenantId);

            return Results.Ok(options);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error beginning WebAuthn registration");
            return Results.Problem("Registration error");
        }
    }

    /// <summary>
    /// Completes WebAuthn registration process.
    /// </summary>
    private static async Task<IResult> CompleteRegistration(
        HttpContext context,
        IEnterpriseWebAuthnService webAuthnService,
        ILogger<IEnterpriseWebAuthnService> logger)
    {
        try
        {
            var challenge = context.Session.GetString("webauthn_challenge");
            if (string.IsNullOrEmpty(challenge))
            {
                return Results.BadRequest("No active session");
            }

            var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            var result = await webAuthnService.CompleteRegistrationAsync(requestBody, challenge);

            // Clear session
            context.Session.Remove("webauthn_challenge");
            context.Session.Remove("webauthn_user");
            context.Session.Remove("webauthn_tenant");

            if (result.IsSuccessful)
            {
                return Results.Ok(new { status = "success", credential_id = result.CredentialId });
            }
            else
            {
                return Results.BadRequest(new { error = result.ErrorMessage });
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error completing WebAuthn registration");
            return Results.Problem("Registration completion error");
        }
    }

    /// <summary>
    /// Begins WebAuthn authentication process.
    /// </summary>
    private static async Task<IResult> BeginAuthentication(
        HttpContext context,
        IEnterpriseWebAuthnService webAuthnService,
        ILogger<IEnterpriseWebAuthnService> logger)
    {
        try
        {
            var request = await context.Request.ReadFromJsonAsync<AuthenticationRequest>();
            if (request == null)
            {
                return Results.BadRequest("Invalid request");
            }

            var options = await webAuthnService.BeginAuthenticationAsync(request.UserId, request.TenantId);

            // Store challenge in session
            context.Session.SetString("webauthn_auth_challenge", Convert.ToBase64String(options.Challenge));
            context.Session.SetString("webauthn_auth_user", request.UserId);
            context.Session.SetString("webauthn_auth_tenant", request.TenantId);

            return Results.Ok(options);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error beginning WebAuthn authentication for user {User}", 
                context.Session.GetString("webauthn_auth_user"));
            return Results.Problem("Authentication error");
        }
    }

    /// <summary>
    /// Completes WebAuthn authentication process.
    /// </summary>
    private static async Task<IResult> CompleteAuthentication(
        HttpContext context,
        IEnterpriseWebAuthnService webAuthnService,
        ILogger<IEnterpriseWebAuthnService> logger)
    {
        try
        {
            var challenge = context.Session.GetString("webauthn_auth_challenge");
            var userId = context.Session.GetString("webauthn_auth_user");
            var tenantId = context.Session.GetString("webauthn_auth_tenant");

            if (string.IsNullOrEmpty(challenge) || string.IsNullOrEmpty(userId))
            {
                return Results.BadRequest("No active session");
            }

            var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            var result = await webAuthnService.CompleteAuthenticationAsync(requestBody, challenge);

            // Clear session
            context.Session.Remove("webauthn_auth_challenge");
            context.Session.Remove("webauthn_auth_user");
            context.Session.Remove("webauthn_auth_tenant");

            if (result.IsAuthenticated)
            {
                return Results.Ok(new { 
                    status = "success", 
                    user_id = result.UserId,
                    tenant_id = result.TenantId 
                });
            }
            else
            {
                return Results.Unauthorized();
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error completing WebAuthn authentication");
            return Results.Problem("Authentication completion error");
        }
    }

    /// <summary>
    /// Gets WebAuthn statistics for enterprise monitoring.
    /// </summary>
    private static async Task<IResult> GetStatistics(
        string tenantId,
        IEnterpriseWebAuthnService webAuthnService)
    {
        try
        {
            var stats = await webAuthnService.GetStatisticsAsync(tenantId);
            return Results.Ok(stats);
        }
        catch (Exception ex)
        {
            return Results.Problem("Error retrieving statistics");
        }
    }

    /// <summary>
    /// Revokes WebAuthn credential.
    /// </summary>
    private static async Task<IResult> RevokeCredential(
        string credentialId,
        IEnterpriseWebAuthnService webAuthnService)
    {
        try
        {
            var success = await webAuthnService.RevokeCredentialAsync(credentialId);
            if (success)
            {
                return Results.Ok(new { status = "revoked" });
            }
            else
            {
                return Results.NotFound();
            }
        }
        catch (Exception ex)
        {
            return Results.Problem("Error revoking credential");
        }
    }
}

/// <summary>
/// Request models for WebAuthn endpoints.
/// </summary>

public class RegistrationRequest
{
    public string UserId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string TenantId { get; set; } = "default";
}

public class AuthenticationRequest
{
    public string UserId { get; set; } = string.Empty;
    public string TenantId { get; set; } = "default";
}