using McpGuardrails.Core.Access;
using McpGuardrails.Core.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace McpGuardrails.Cli;

/// <summary>
/// Serves the guardrailed MCP server over Streamable HTTP, stateless.
/// </summary>
/// <remarks>
/// Only the listener lives here. The MCP server itself - handlers and every
/// guardrail filter - is registered once in ServeCommand and is identical for
/// both transports; this class decides where it listens and who may reach it.
/// </remarks>
internal static class HttpHost
{
    /// <summary>The path the MCP endpoint is mapped to.</summary>
    public const string Endpoint = "/mcp";

    /// <summary>Binds Kestrel to exactly one address: the one the options name.</summary>
    /// <remarks>
    /// An explicit Listen overrides ASPNETCORE_URLS, --urls and appsettings, so
    /// nothing in the environment can widen what the operator asked for.
    /// </remarks>
    public static void ConfigureListener(WebApplicationBuilder builder, ServeOptions options)
    {
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(options.BindAddress, options.Port);

            // Tool arguments are small; nothing legitimate needs the 30 MB default.
            kestrel.Limits.MaxRequestBodySize = 4 * 1024 * 1024;

            // No point advertising the server stack to whoever can reach the port.
            kestrel.AddServerHeader = false;
        });
    }

    /// <summary>Maps the endpoint behind the access guard, then runs until shutdown.</summary>
    /// <param name="app">The built host.</param>
    /// <param name="options">The validated transport options.</param>
    /// <param name="oauth">The access-token guard, when the policy configures <c>access.oauth</c>.</param>
    public static async Task RunAsync(WebApplication app, ServeOptions options, OAuthAccessGuard? oauth)
    {
        var guard = new HttpAccessGuard(options.BearerToken);

        // Ahead of the endpoint, so a refused request never reaches the MCP
        // handler - or the audit log, which records tool calls, not HTTP noise.
        app.Use(async (context, next) =>
        {
            var authorization = Header(context.Request.Headers.Authorization);
            var origin = Header(context.Request.Headers.Origin);

            if (oauth is null)
            {
                await Respond(context, next, new HttpAccessResult(guard.Check(authorization, origin), Challenge: "Bearer"));
                return;
            }

            var resource = oauth.Resource(
                context.Request.Scheme,
                context.Request.Host.HasValue ? context.Request.Host.Value : "localhost",
                Endpoint);

            // The metadata is public by definition: it is how a client without
            // a token finds out where to get one.
            if (IsMetadataRequest(context.Request, resource))
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(oauth.MetadataDocument(resource), context.RequestAborted);
                return;
            }

            await Respond(
                context,
                next,
                await oauth.CheckAsync(authorization, origin, resource, context.RequestAborted));
        });

        app.MapMcp(Endpoint);

        await app.StartAsync();

        // After StartAsync the addresses carry the real port, which matters when
        // the operator (or the smoke test) asked for port 0.
        foreach (var url in app.Urls)
        {
            app.Logger.LogInformation(
                "Serving MCP over Streamable HTTP (stateless) at {Url}{Endpoint}; auth: {Auth}",
                url,
                Endpoint,
                options.AuthenticationName);
        }

        await app.WaitForShutdownAsync();
    }

    private static string? Header(Microsoft.Extensions.Primitives.StringValues value) =>
        value.ToString() is { Length: > 0 } text ? text : null;

    /// <summary>Passes an allowed request on, or answers a refused one.</summary>
    /// <remarks>
    /// The validated caller rides on HttpContext.User, which the MCP SDK hands
    /// to the tool-call filters as the message's user. Assigned only here, from
    /// a token this proxy checked, so no other component can supply an identity.
    /// </remarks>
    private static async Task Respond(HttpContext context, RequestDelegate next, HttpAccessResult result)
    {
        switch (result.Verdict)
        {
            case HttpAccessVerdict.Allowed:
                if (result.Caller is { } caller)
                {
                    context.User = caller.ToClaimsPrincipal();
                }

                await next(context);
                break;

            case HttpAccessVerdict.Unauthorized:
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers[HeaderNames.WWWAuthenticate] = result.Challenge;
                break;

            case HttpAccessVerdict.InsufficientScope:
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.Headers[HeaderNames.WWWAuthenticate] = result.Challenge;
                break;

            case HttpAccessVerdict.Unavailable:
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                break;

            default:
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                break;
        }
    }

    /// <remarks>
    /// Both RFC 9728 locations: the path-suffixed one the MCP specification has
    /// clients try first, and the bare well-known path for clients that do not.
    /// </remarks>
    private static bool IsMetadataRequest(HttpRequest request, Uri resource) =>
        (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method)) &&
        (request.Path == OAuthAccessGuard.MetadataPath ||
         request.Path == OAuthAccessGuard.MetadataPath + resource.AbsolutePath.TrimEnd('/'));
}
