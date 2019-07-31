using Microsoft.Extensions.Logging;
using OAKProxy.ProcessPrivileges;
using System;

namespace OAKProxy.Extensions.Logging
{
    class DeferringLogger : ILogger
    {
        private readonly ILogger _logger;
        private readonly DeferringLoggerContext _context;

        public DeferringLogger(ILogger logger, DeferringLoggerContext context)
        {
            _logger = logger;
            _context = context;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return _logger.BeginScope(state);
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return _logger.IsEnabled(logLevel);
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if (ThreadExtensions.IsImpersonating())
            {
                _context.Push(() => {
                    _logger.Log(logLevel, eventId, state, exception, formatter);
                });
            }
            else
            {
                _context.Flush();
                _logger.Log(logLevel, eventId, state, exception, formatter);
            }
        }
    }
}
