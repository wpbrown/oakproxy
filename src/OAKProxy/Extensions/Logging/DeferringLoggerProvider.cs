using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace OAKProxy.Extensions.Logging
{
    class DeferringLoggerProvider : ILoggerProvider
    {
        private readonly ILoggerProvider _loggerProvider;
        private readonly DeferringLoggerContext _context = new DeferringLoggerContext();
        private readonly CancellationTokenSource _flusherControl = new CancellationTokenSource();
        private readonly Task _flusher;

        public DeferringLoggerProvider(ILoggerProvider loggerProvider)
        {
            _loggerProvider = loggerProvider;

            var token = _flusherControl.Token;
            _flusher = Task.Run(async () => {
                while (!token.IsCancellationRequested)
                {
                    _context.Flush();
                    await Task.Delay(TimeSpan.FromSeconds(5), token);
                }
            });
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new DeferringLogger(_loggerProvider.CreateLogger(categoryName), _context);
        }

        public void Dispose()
        {
            _flusherControl.Cancel();
            _flusher.Wait();
            _loggerProvider.Dispose();
        }
    }

    internal class DeferringLoggerContext
    {
        private ConcurrentQueue<Action> _queue = new ConcurrentQueue<Action>();

        internal void Push(Action action)
        {
            _queue.Enqueue(action);
        }

        internal void Flush()
        {
            while (_queue.TryDequeue(out Action result))
            {
                result();
            }
        }
    }
}
