﻿using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using System;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System.Linq;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace OAKProxy.Proxy
{
    public class HeadersAuthenticator : IAuthenticator
    {
        private readonly AuthenticatorOptionsBase _options;
        private readonly HeaderApplicator[] _applicators;
        private readonly ILogger<HeadersAuthenticator> _logger;
        private readonly bool _needsGlobals;

        public HeadersAuthenticator(AuthenticatorOptionsBase options, AuthenticatorBindingOptionsBase _, ILogger<HeadersAuthenticator> logger)
        {
            _options = options;
            _logger = logger;
            _applicators = _options.HeaderDefinitions.Select(d =>
            {
                var applicator = new HeaderApplicator
                {
                    Definition = d,
                    UseBasicClaim = !String.IsNullOrEmpty(d.ClaimName)
                };

                if (!applicator.UseBasicClaim)
                {
                    (var scriptOptions, var scriptText) = ParseExpression(d.Expression);
                    try
                    {
                        var script = CSharpScript.Create<string>(scriptText, scriptOptions, typeof(ExpressionGlobals));
                        applicator.ExpressionRunner = script.CreateDelegate();
                    }
                    catch (Exception ex)
                    {
                        logger.LogCritical($"Failed to compile expresion for header: {applicator.Definition.HeaderName}. {ex.Message}");
                        throw;
                    }
                }

                return applicator;
            }).ToArray();
            _needsGlobals = _applicators.Any(a => !a.UseBasicClaim);
        }

        private static readonly Regex referenceRegex = new Regex(@"^\s*#r\s+""(.+?)""\s*$", RegexOptions.Compiled);

        private static (ScriptOptions, string) ParseExpression(string expression)
        {
            string text;
            var assemblies = new List<string>();
            using (var reader = new StringReader(expression))
            using (var writer = new StringWriter())
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    var match = referenceRegex.Match(line);
                    if (match.Success)
                    {
                        assemblies.Add(match.Groups[1].Value);
                    }
                    else
                    {
                        writer.WriteLine(line);
                    }
                }
                writer.Close();
                text = writer.ToString();
            }
            var options = ScriptOptions.Default;
            if (assemblies.Count > 0)
            {
                options = options.WithReferences(assemblies);
            }
            return (options, text);
        }

        public void Configure(ProxyMessageHandlerBuilder builder)
        {
            builder.AuthenticatorHandlers.Add(new HeadersHandler()
            {
                Authenticator = this
            });
        }

        public async Task Apply(AuthenticatorSendContext context, CancellationToken cancellationToken)
        {
            var user = context.AuthenticatedUser;
            ExpressionGlobals globals = null;
            if (_needsGlobals)
            {
                globals = new ExpressionGlobals();
                globals.c = user.Claims.ToDictionary(c => c.Type, c => c.Value);
            }

            foreach (var applicator in _applicators)
            {
                string value = null;

                if (applicator.UseBasicClaim)
                {
                    value = user.Claims.FirstOrDefault(c => c.Type == applicator.Definition.ClaimName)?.Value;
                    if (String.IsNullOrEmpty(value) && applicator.Definition.Required)
                    {
                        _logger.LogError($"Failed to resolve required claim '{applicator.Definition.ClaimName}' on user '{user.Identity.Name}' for header '{applicator.Definition.HeaderName}'.");
                        throw new AuthenticatorException(Errors.Code.Unknown, "Missing required claims for authentication.");
                    }
                }
                else
                {
                    bool computed = false;
                    try
                    {
                        value = await applicator.ExpressionRunner(globals, cancellationToken);
                        computed = true;
                    }
                    catch (TaskCanceledException)
                    {
                        throw;
                    }
                    catch (Exception e)
                    {
                        _logger.LogError(e, $"Failed to run expression on user '{user.Identity.Name}' for header '{applicator.Definition.HeaderName}'.");
                    }
                    
                    if (String.IsNullOrEmpty(value) && applicator.Definition.Required)
                    {
                        if (computed)
                        {
                            throw new AuthenticatorException(Errors.Code.Unknown, "No value was computed for a required header for authentication.");
                        }
                        else
                        {
                            throw new AuthenticatorException(Errors.Code.Unknown, "Failed to compute required header for authentication.");
                        }
                    }
                }

                if (value == null)
                {
                    if (context.Message.Headers.Contains(applicator.Definition.HeaderName))
                        context.Message.Headers.Remove(applicator.Definition.HeaderName);
                }
                else
                {
                    context.Message.Headers.Add(applicator.Definition.HeaderName, value);
                }
            }
        }

        private class HeadersHandler : AuthenticatorHandler
        {
            public HeadersAuthenticator Authenticator;

            protected override async Task<HttpResponseMessage> SendAsyncAuthenticator(AuthenticatorSendContext context, CancellationToken cancellationToken)
            {
                await Authenticator.Apply(context, cancellationToken);
                return await base.SendAsyncAuthenticator(context, cancellationToken);
            }
        }

        private class HeaderApplicator
        {
            public HeaderDefinition Definition;

            public ScriptRunner<string> ExpressionRunner;

            public bool UseBasicClaim;
        }
    }

    public class ExpressionGlobals
    {
        public Dictionary<string, string> c;
    }
}

