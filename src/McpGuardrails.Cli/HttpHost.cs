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
    public static async Task RunAsync(WebApplication app, ServeOptions options)
    {
        var guard = new HttpAccessGuard(options.BearerToken);

        // Ahead of the endpoint, so a refused request never reaches the MCP
        // handler - or the audit log, which records tool calls, not HTTP noise.
        app.Use(async (context, next) =>
        {
            var verdict = guard.Check(
                context.Request.Headers.Authorization.ToString() is { Length: > 0 } auth
                    ? auth
                    : null,
                context.Request.Headers.Origin.ToString() is { Length: > 0 } origin
                    ? origin
                    : null);

            switch (verdict)
            {
                case HttpAccessVerdict.Allowed:
                    await next(context);
                    break;

                case HttpAccessVerdict.Unauthorized:
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.Headers[HeaderNames.WWWAuthenticate] = "Bearer";
                    break;

                default:
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    break;
            }
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
                options.RequiresToken ? "bearer token" : "none (loopback only)");
        }

        await app.WaitForShutdownAsync();
    }
}
